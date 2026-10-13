#![cfg(all(feature = "server", feature = "aead-cipher"))]

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
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

const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

const METHOD: &str = "aes-256-gcm";
const PASSWORD: &str = "password";

/// Timeout of every operation, so failures don't hang
const TIMEOUT: Duration = Duration::from_secs(5);

fn random_local_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// UDP echo server, counts received packets
async fn spawn_echo_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (addr, received)
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
        let path = std::env::temp_dir().join(format!("shadowsocks-udp-over-tcp-{server_port}.acl"));
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

/// Opens a shadowsocks stream to the UoT magic address `host`
async fn connect(svr_cfg: &ServerConfig, host: &str) -> impl AsyncRead + AsyncWrite + Unpin + use<> {
    let context = Context::new_shared(ServerType::Local);
    let addr = Address::DomainNameAddress(host.to_owned(), 0);
    time::timeout(TIMEOUT, ProxyClientStream::connect(context, svr_cfg, addr))
        .await
        .expect("connect timeout")
        .expect("connect")
}

/// v2 request, `dest` is a SOCKS5 address
fn encode_request(buf: &mut Vec<u8>, is_connect: bool, dest: &Address) {
    buf.push(is_connect as u8);
    dest.write_to_buf(buf);
}

/// Packet with UoT address `addr` in non-connect mode
fn encode_packet(buf: &mut Vec<u8>, addr: Option<&Address>, payload: &[u8]) {
    match addr {
        None => {}
        Some(Address::SocketAddress(SocketAddr::V4(v4))) => {
            buf.push(0x00);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(Address::SocketAddress(SocketAddr::V6(v6))) => {
            buf.push(0x01);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        Some(Address::DomainNameAddress(name, port)) => {
            buf.push(0x02);
            buf.push(name.len() as u8);
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
}

async fn write<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) {
    time::timeout(TIMEOUT, async {
        stream.write_all(data).await?;
        stream.flush().await
    })
    .await
    .expect("write timeout")
    .expect("write");
}

/// Reads a packet, returns its source address in non-connect mode.
/// IPv4 (family `0x00`) is returned as `SocketAddr::V4`, IPv6 (family `0x01`) as `SocketAddr::V6`
async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S, connect: bool) -> (Option<SocketAddr>, Vec<u8>) {
    time::timeout(TIMEOUT, async {
        let addr = if connect {
            None
        } else {
            let ip = match stream.read_u8().await? {
                0x00 => {
                    let mut ip = [0u8; 4];
                    stream.read_exact(&mut ip).await?;
                    IpAddr::from(ip)
                }
                0x01 => {
                    let mut ip = [0u8; 16];
                    stream.read_exact(&mut ip).await?;
                    IpAddr::from(ip)
                }
                family => panic!("unexpected address family {family:#x}"),
            };
            Some(SocketAddr::new(ip, stream.read_u16().await?))
        };
        let len = stream.read_u16().await?;
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await?;
        io::Result::Ok((addr, payload))
    })
    .await
    .expect("read packet timeout")
    .expect("read packet")
}

/// v2 non-connect round trips through `svr_cfg`
async fn v2_non_connect_round_trip(svr_cfg: &ServerConfig) {
    let (echo_addr, received) = spawn_echo_server().await;
    let echo = Address::SocketAddress(echo_addr);
    let mut stream = connect(svr_cfg, MAGIC_ADDRESS).await;

    let mut data = Vec::new();
    encode_request(&mut data, false, &echo);
    encode_packet(&mut data, Some(&echo), b"hello");
    encode_packet(&mut data, Some(&echo), b"");
    encode_packet(&mut data, Some(&echo), b"world");
    write(&mut stream, &data).await;

    // echo_addr is IPv4, so the address family must be 0x00 even if the server sent it from an IPv6 socket
    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"hello".to_vec())
    );
    assert_eq!(read_packet(&mut stream, false).await, (Some(echo_addr), Vec::new()));
    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"world".to_vec())
    );

    // Later packets in a separate write
    let mut data = Vec::new();
    encode_packet(&mut data, Some(&echo), b"again");
    write(&mut stream, &data).await;
    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"again".to_vec())
    );

    assert_eq!(received.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn v2_non_connect() {
    let _ = env_logger::try_init();

    let svr_cfg = start_server(METHOD, PASSWORD, r#", "udp_over_tcp": true"#, None).await;
    v2_non_connect_round_trip(&svr_cfg).await;
}

#[tokio::test]
async fn v2_connect() {
    let _ = env_logger::try_init();

    let (echo_addr, received) = spawn_echo_server().await;
    let svr_cfg = start_server(METHOD, PASSWORD, r#", "udp_over_tcp": true"#, None).await;
    let mut stream = connect(&svr_cfg, MAGIC_ADDRESS).await;

    let mut data = Vec::new();
    encode_request(&mut data, true, &Address::SocketAddress(echo_addr));
    encode_packet(&mut data, None, b"hello");
    encode_packet(&mut data, None, b"");
    write(&mut stream, &data).await;

    assert_eq!(read_packet(&mut stream, true).await, (None, b"hello".to_vec()));
    assert_eq!(read_packet(&mut stream, true).await, (None, Vec::new()));

    let mut data = Vec::new();
    encode_packet(&mut data, None, b"world");
    write(&mut stream, &data).await;
    assert_eq!(read_packet(&mut stream, true).await, (None, b"world".to_vec()));

    assert_eq!(received.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn v1_legacy() {
    let _ = env_logger::try_init();

    let (echo_addr, received) = spawn_echo_server().await;
    let echo = Address::SocketAddress(echo_addr);
    let svr_cfg = start_server(METHOD, PASSWORD, r#", "udp_over_tcp": true"#, None).await;
    let mut stream = connect(&svr_cfg, LEGACY_MAGIC_ADDRESS).await;

    // No request, packets start right away
    let mut data = Vec::new();
    encode_packet(&mut data, Some(&echo), b"hello");
    encode_packet(&mut data, Some(&echo), b"world");
    write(&mut stream, &data).await;

    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"hello".to_vec())
    );
    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"world".to_vec())
    );

    assert_eq!(received.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn v2_domain_name_target() {
    let _ = env_logger::try_init();

    let (echo_addr, _) = spawn_echo_server().await;
    let svr_cfg = start_server(METHOD, PASSWORD, r#", "udp_over_tcp": true"#, None).await;
    let mut stream = connect(&svr_cfg, MAGIC_ADDRESS).await;

    // Resolved by the server, IPv4 is preferred
    let mut data = Vec::new();
    encode_request(&mut data, false, &Address::SocketAddress(echo_addr));
    let target = Address::DomainNameAddress("localhost".to_owned(), echo_addr.port());
    encode_packet(&mut data, Some(&target), b"hello");
    write(&mut stream, &data).await;

    // Response comes with the resolved address
    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"hello".to_vec())
    );
}

#[tokio::test]
async fn v2_large_packet() {
    let _ = env_logger::try_init();

    let (echo_addr, _) = spawn_echo_server().await;
    let echo = Address::SocketAddress(echo_addr);
    let svr_cfg = start_server(METHOD, PASSWORD, r#", "udp_over_tcp": true"#, None).await;
    let mut stream = connect(&svr_cfg, MAGIC_ADDRESS).await;

    // The first write is sent with the shadowsocks header in one AEAD chunk, keep it small
    let mut data = Vec::new();
    encode_request(&mut data, false, &echo);
    encode_packet(&mut data, Some(&echo), b"hello");
    write(&mut stream, &data).await;
    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"hello".to_vec())
    );

    // Larger than an AEAD chunk (0x3FFF) in both directions
    let payload = (0..20000u32).map(|i| i as u8).collect::<Vec<_>>();
    let mut data = Vec::new();
    encode_packet(&mut data, Some(&echo), &payload);
    write(&mut stream, &data).await;
    assert_eq!(read_packet(&mut stream, false).await, (Some(echo_addr), payload));
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn v2_non_connect_aead_2022() {
    let _ = env_logger::try_init();

    let svr_cfg = start_server(
        "2022-blake3-aes-256-gcm",
        "0TSsdgK7IOeJH/5Nkk1cGXYerGWG3xuoG5cHymEIMFc=",
        r#", "udp_over_tcp": true"#,
        None,
    )
    .await;
    v2_non_connect_round_trip(&svr_cfg).await;
}

#[tokio::test]
async fn disabled_by_default() {
    let _ = env_logger::try_init();

    let (echo_addr, received) = spawn_echo_server().await;
    let echo = Address::SocketAddress(echo_addr);
    let svr_cfg = start_server(METHOD, PASSWORD, "", None).await;
    let mut stream = connect(&svr_cfg, MAGIC_ADDRESS).await;

    let mut data = Vec::new();
    encode_request(&mut data, false, &echo);
    encode_packet(&mut data, Some(&echo), b"hello");
    write(&mut stream, &data).await;

    // The magic address is relayed as a normal TCP target, which can't be connected.
    // Either EOF, error or nothing at all
    let mut buf = [0u8; 64];
    if let Ok(Ok(n)) = time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        assert_eq!(n, 0, "unexpected response {:?}", &buf[..n]);
    }

    assert_eq!(received.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn packet_target_blocked_by_acl() {
    let _ = env_logger::try_init();

    let (echo_addr, received) = spawn_echo_server().await;
    let echo = Address::SocketAddress(echo_addr);
    // localhost would reach the echo server if it wasn't blocked, see v2_domain_name_target
    let acl = "[outbound_block_list]\n||blocked.example\n|localhost\n";
    let svr_cfg = start_server(METHOD, PASSWORD, r#", "udp_over_tcp": true"#, Some(acl)).await;
    let mut stream = connect(&svr_cfg, MAGIC_ADDRESS).await;

    let mut data = Vec::new();
    encode_request(&mut data, false, &echo);
    let blocked = Address::DomainNameAddress("www.blocked.example".to_owned(), echo_addr.port());
    encode_packet(&mut data, Some(&blocked), b"blocked");
    let blocked = Address::DomainNameAddress("localhost".to_owned(), echo_addr.port());
    encode_packet(&mut data, Some(&blocked), b"blocked");
    encode_packet(&mut data, Some(&echo), b"allowed");
    write(&mut stream, &data).await;

    // Blocked packets are dropped without closing the stream
    assert_eq!(
        read_packet(&mut stream, false).await,
        (Some(echo_addr), b"allowed".to_vec())
    );
    assert_eq!(received.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn connect_target_blocked_by_acl() {
    let _ = env_logger::try_init();

    let (echo_addr, received) = spawn_echo_server().await;
    let acl = "[outbound_block_list]\n|localhost\n";
    let svr_cfg = start_server(METHOD, PASSWORD, r#", "udp_over_tcp": true"#, Some(acl)).await;
    let mut stream = connect(&svr_cfg, MAGIC_ADDRESS).await;

    let mut data = Vec::new();
    let blocked = Address::DomainNameAddress("localhost".to_owned(), echo_addr.port());
    encode_request(&mut data, true, &blocked);
    encode_packet(&mut data, None, b"blocked");
    write(&mut stream, &data).await;

    // The stream is closed, a connection closed by the server may be reset
    let mut buf = [0u8; 64];
    if let Ok(n) = time::timeout(TIMEOUT, stream.read(&mut buf))
        .await
        .expect("read timeout")
    {
        assert_eq!(n, 0, "unexpected response {:?}", &buf[..n]);
    }

    assert_eq!(received.load(Ordering::SeqCst), 0);
}
