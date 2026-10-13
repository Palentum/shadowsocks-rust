#![cfg(all(feature = "server", feature = "aead-cipher"))]

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{self, Duration, Instant},
};

use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType},
    run_server,
    shadowsocks::{
        ProxyClientStream,
        config::{ServerConfig, ServerType},
        context::Context,
        relay::socks5::Address,
    },
};

const MAGIC_ADDRESS: &str = "sp.mux.sing-box.arpa";

const METHOD: &str = "aes-256-gcm";
const PASSWORD: &str = "password";

const PROTOCOL_SMUX: u8 = 0;
const PROTOCOL_YAMUX: u8 = 1;

const SMUX_SYN: u8 = 0;
const SMUX_FIN: u8 = 1;
const SMUX_PSH: u8 = 2;

const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;

/// Timeout of every operation, so failures don't hang
const TIMEOUT: Duration = Duration::from_secs(10);

fn random_local_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn tcp_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// Starts a TCP only ssserver with extra `options` and `acl` rules, returns its config for clients
async fn start_server(method: &str, password: &str, options: &str, acl: Option<&str>) -> ServerConfig {
    let server_port = random_local_tcp_port();
    let mut server_config = Config::load_from_str(
        &format!(
            r#"{{
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "{password}",
            "method": "{method}",
            "mode": "tcp_only"
            {options}
        }}"#
        ),
        ConfigType::Server,
    )
    .unwrap();
    if let Some(rules) = acl {
        let path = std::env::temp_dir().join(format!("shadowsocks-sing-mux-{server_port}.acl"));
        std::fs::write(&path, rules).unwrap();
        server_config.acl = Some(AccessControl::load_from_file(&path).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    tokio::spawn(run_server(server_config));

    let server_addr = SocketAddr::from(([127, 0, 0, 1], server_port));
    let deadline = Instant::now() + TIMEOUT;
    while TcpStream::connect(server_addr).await.is_err() {
        assert!(Instant::now() < deadline, "server {server_addr} not ready");
        time::sleep(Duration::from_millis(10)).await;
    }

    ServerConfig::new(server_addr, password, method.parse().unwrap()).unwrap()
}

type ClientStream = ProxyClientStream<shadowsocks_service::shadowsocks::net::TcpStream>;

/// Opens a session to the magic address and sends the session request
async fn open_session(
    svr_cfg: &ServerConfig,
    protocol: u8,
    padding: bool,
) -> (ReadHalf<ClientStream>, WriteHalf<ClientStream>) {
    let context = Context::new_shared(ServerType::Local);
    let addr = Address::DomainNameAddress(MAGIC_ADDRESS.to_owned(), 444);
    let mut stream = time::timeout(TIMEOUT, ProxyClientStream::connect(context, svr_cfg, addr))
        .await
        .expect("connect timeout")
        .expect("connect");

    let mut request = if padding {
        vec![0x01, protocol, 0x01, 0x01, 0x00]
    } else {
        vec![0x00, protocol]
    };
    if padding {
        request.extend_from_slice(&[0xEE; 256]);
    }
    stream.write_all(&request).await.unwrap();

    tokio::io::split(stream)
}

fn stream_request(flags: u16, addr: &Address) -> Vec<u8> {
    let mut buf = flags.to_be_bytes().to_vec();
    addr.write_to_buf(&mut buf);
    buf
}

/// Writes of the client, the first 16 are padded if enabled
struct PaddedWriter<W> {
    writer: W,
    frames: usize,
}

impl<W: AsyncWrite + Unpin> PaddedWriter<W> {
    fn new(writer: W, padding: bool) -> Self {
        Self {
            writer,
            frames: if padding { 0 } else { 16 },
        }
    }

    async fn write(&mut self, data: &[u8]) {
        let data = if self.frames < 16 {
            self.frames += 1;
            let mut frame = (data.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&300u16.to_be_bytes());
            frame.extend_from_slice(data);
            frame.extend_from_slice(&[0u8; 300]);
            frame
        } else {
            data.to_vec()
        };
        time::timeout(TIMEOUT, async {
            self.writer.write_all(&data).await?;
            self.writer.flush().await
        })
        .await
        .expect("write timeout")
        .expect("write");
    }

    async fn smux_frame(&mut self, cmd: u8, stream_id: u32, data: &[u8]) {
        let mut frame = vec![1, cmd];
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(&stream_id.to_le_bytes());
        frame.extend_from_slice(data);
        self.write(&frame).await;
    }
}

/// Reads of the client, the first 16 frames of the server are padded if enabled
struct PaddedReader<R> {
    reader: R,
    frames: usize,
    data_remaining: usize,
    padding_remaining: usize,
}

impl<R: AsyncRead + Unpin> PaddedReader<R> {
    fn new(reader: R, padding: bool) -> Self {
        Self {
            reader,
            frames: if padding { 0 } else { 16 },
            data_remaining: 0,
            padding_remaining: 0,
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) {
        let mut filled = 0;
        while filled < buf.len() {
            if self.data_remaining > 0 {
                let n = self.data_remaining.min(buf.len() - filled);
                self.reader.read_exact(&mut buf[filled..filled + n]).await.unwrap();
                filled += n;
                self.data_remaining -= n;
            } else if self.padding_remaining > 0 {
                let mut padding = vec![0u8; self.padding_remaining];
                self.reader.read_exact(&mut padding).await.unwrap();
                self.padding_remaining = 0;
            } else if self.frames < 16 {
                self.frames += 1;
                self.data_remaining = self.reader.read_u16().await.unwrap() as usize;
                self.padding_remaining = self.reader.read_u16().await.unwrap() as usize;
                assert!((256..768).contains(&self.padding_remaining));
            } else {
                self.reader.read_exact(&mut buf[filled..]).await.unwrap();
                filled = buf.len();
            }
        }
    }

    async fn smux_frame(&mut self) -> (u8, u32, Vec<u8>) {
        let mut header = [0u8; 8];
        self.read_exact(&mut header).await;
        assert_eq!(header[0], 1, "smux version");
        let mut data = vec![0u8; u16::from_le_bytes([header[2], header[3]]) as usize];
        self.read_exact(&mut data).await;
        (
            header[1],
            u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
            data,
        )
    }
}

#[derive(Default)]
struct Received {
    data: HashMap<u32, Vec<u8>>,
    fin: HashSet<u32>,
}

/// Receives smux frames until `done`
async fn receive_until<R, F>(reader: &mut PaddedReader<R>, received: &mut Received, done: F)
where
    R: AsyncRead + Unpin,
    F: Fn(&Received) -> bool,
{
    time::timeout(TIMEOUT, async {
        while !done(received) {
            match reader.smux_frame().await {
                (SMUX_PSH, stream_id, data) => received.data.entry(stream_id).or_default().extend(data),
                (SMUX_FIN, stream_id, _) => {
                    received.fin.insert(stream_id);
                }
                (cmd, ..) => panic!("unexpected smux command {cmd}"),
            }
        }
    })
    .await
    .expect("receive timeout");
}

/// UDP connect, UDP with addresses and 4 MiB of TCP in one smux session
async fn smux_round_trips(svr_cfg: &ServerConfig, padding: bool) {
    let tcp_echo = Address::SocketAddress(tcp_echo_server().await);
    let udp_echo = Address::SocketAddress(udp_echo_server().await);
    let (reader, writer) = open_session(svr_cfg, PROTOCOL_SMUX, padding).await;
    let mut reader = PaddedReader::new(reader, padding);
    let mut writer = PaddedWriter::new(writer, padding);

    let mut data = stream_request(FLAG_UDP, &udp_echo);
    data.extend_from_slice(&[0x00, 0x05]);
    data.extend_from_slice(b"hello");
    writer.smux_frame(SMUX_SYN, 3, &[]).await;
    writer.smux_frame(SMUX_PSH, 3, &data).await;

    let mut data = stream_request(FLAG_UDP | FLAG_ADDR, &udp_echo);
    udp_echo.write_to_buf(&mut data);
    data.extend_from_slice(&[0x00, 0x05]);
    data.extend_from_slice(b"world");
    writer.smux_frame(SMUX_SYN, 5, &[]).await;
    writer.smux_frame(SMUX_PSH, 5, &data).await;

    let payload: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    writer.smux_frame(SMUX_SYN, 7, &[]).await;
    writer.smux_frame(SMUX_PSH, 7, &stream_request(0, &tcp_echo)).await;
    let tcp_payload = payload.clone();
    let writer = tokio::spawn(async move {
        for chunk in tcp_payload.chunks(32 * 1024) {
            writer.smux_frame(SMUX_PSH, 7, chunk).await;
        }
        writer
    });

    let mut received = Received::default();
    let udp_addr_len = udp_echo.serialized_len();
    receive_until(&mut reader, &mut received, |r| {
        r.data.get(&3).map_or(0, Vec::len) == 1 + 2 + 5
            && r.data.get(&5).map_or(0, Vec::len) == 1 + udp_addr_len + 2 + 5
            && r.data.get(&7).map_or(0, Vec::len) == 1 + payload.len()
    })
    .await;

    assert_eq!(received.data[&3], b"\x00\x00\x05hello");
    let mut expected = vec![0x00];
    udp_echo.write_to_buf(&mut expected);
    expected.extend_from_slice(b"\x00\x05world");
    assert_eq!(received.data[&5], expected);
    assert_eq!(received.data[&7][0], 0x00);
    assert!(received.data[&7][1..] == payload[..], "TCP data mismatch");

    // Closed by the client, then by the server
    let mut writer = writer.await.unwrap();
    for stream_id in [3, 5, 7] {
        writer.smux_frame(SMUX_FIN, stream_id, &[]).await;
    }
    receive_until(&mut reader, &mut received, |r| r.fin.len() == 3).await;
}

#[tokio::test]
async fn smux() {
    let _ = env_logger::try_init();

    let svr_cfg = start_server(METHOD, PASSWORD, r#", "multiplex": true"#, None).await;
    smux_round_trips(&svr_cfg, false).await;
}

#[tokio::test]
async fn smux_padding() {
    let _ = env_logger::try_init();

    let svr_cfg = start_server(METHOD, PASSWORD, r#", "multiplex": true"#, None).await;
    smux_round_trips(&svr_cfg, true).await;
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn smux_padding_aead_2022() {
    let _ = env_logger::try_init();

    let svr_cfg = start_server(
        "2022-blake3-aes-256-gcm",
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        r#", "multiplex": true"#,
        None,
    )
    .await;
    smux_round_trips(&svr_cfg, true).await;
}

#[tokio::test]
async fn yamux_ack_immediately() {
    let _ = env_logger::try_init();

    let svr_cfg = start_server(METHOD, PASSWORD, r#", "multiplex": true"#, None).await;
    let (mut reader, mut writer) = open_session(&svr_cfg, PROTOCOL_YAMUX, false).await;

    // Window update with SYN, without any stream request
    let mut frame = vec![0x00, 0x01];
    frame.extend_from_slice(&0x0001u16.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    writer.write_all(&frame).await.unwrap();
    writer.flush().await.unwrap();

    // hashicorp/yamux closes the session if the stream isn't acknowledged in 5 seconds
    let mut header = [0u8; 12];
    time::timeout(Duration::from_secs(1), reader.read_exact(&mut header))
        .await
        .expect("ACK timeout")
        .unwrap();
    assert_eq!(header[1], 0x01, "window update");
    assert_ne!(u16::from_be_bytes([header[2], header[3]]) & 0x0002, 0, "ACK flag");
    assert_eq!(u32::from_be_bytes([header[4], header[5], header[6], header[7]]), 1);
}

#[tokio::test]
async fn blocked_by_acl() {
    let _ = env_logger::try_init();

    let tcp_echo = tcp_echo_server().await;
    let acl = "[outbound_block_list]\n|localhost\n";
    let svr_cfg = start_server(METHOD, PASSWORD, r#", "multiplex": true"#, Some(acl)).await;
    let (reader, writer) = open_session(&svr_cfg, PROTOCOL_SMUX, false).await;
    let mut reader = PaddedReader::new(reader, false);
    let mut writer = PaddedWriter::new(writer, false);

    let target = Address::DomainNameAddress("localhost".to_owned(), tcp_echo.port());
    writer.smux_frame(SMUX_SYN, 3, &[]).await;
    writer.smux_frame(SMUX_PSH, 3, &stream_request(0, &target)).await;

    let mut received = Received::default();
    receive_until(&mut reader, &mut received, |r| r.fin.contains(&3)).await;
    assert_eq!(received.data[&3], b"\x01\x14blocked by ACL rules");
}

#[tokio::test]
async fn brutal_not_enabled() {
    let _ = env_logger::try_init();

    let svr_cfg = start_server(METHOD, PASSWORD, r#", "multiplex": true"#, None).await;
    let (reader, writer) = open_session(&svr_cfg, PROTOCOL_SMUX, false).await;
    let mut reader = PaddedReader::new(reader, false);
    let mut writer = PaddedWriter::new(writer, false);

    let mut data = stream_request(0, &Address::DomainNameAddress("_BrutalBwExchange".to_owned(), 0));
    data.extend_from_slice(&100_000_000u64.to_be_bytes());
    writer.smux_frame(SMUX_SYN, 3, &[]).await;
    writer.smux_frame(SMUX_PSH, 3, &data).await;

    let mut received = Received::default();
    receive_until(&mut reader, &mut received, |r| r.fin.contains(&3)).await;
    assert_eq!(received.data[&3], b"\x00\x00\x23brutal is not enabled by the server");
}

#[tokio::test]
async fn disabled_by_default() {
    let _ = env_logger::try_init();

    let tcp_echo = Address::SocketAddress(tcp_echo_server().await);
    let svr_cfg = start_server(METHOD, PASSWORD, "", None).await;
    let (mut reader, writer) = open_session(&svr_cfg, PROTOCOL_SMUX, false).await;
    let mut writer = PaddedWriter::new(writer, false);

    let mut data = stream_request(0, &tcp_echo);
    data.extend_from_slice(b"hello");
    writer.smux_frame(SMUX_SYN, 3, &[]).await;
    writer.smux_frame(SMUX_PSH, 3, &data).await;

    // The magic address is relayed as a normal TCP target, which can't be connected.
    // Either EOF, error or nothing at all
    let mut buf = [0u8; 64];
    if let Ok(Ok(n)) = time::timeout(Duration::from_secs(2), reader.read(&mut buf)).await {
        assert_eq!(n, 0, "unexpected response {:?}", &buf[..n]);
    }
}
