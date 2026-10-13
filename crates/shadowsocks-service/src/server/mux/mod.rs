//! sing-box compatible multiplex (sing-mux) server
//!
//! <https://github.com/SagerNet/sing-mux>
//!
//! A session is a stream to the magic address, which starts with a request `[version u8][protocol u8]`,
//! and `[padding u8]` in version 1, followed by `[padding length u16][padding]` if padding is enabled.
//! Streams of the session are multiplexed by smux, yamux or h2mux, and each starts with a request
//! `[flags u16][SOCKS5 address]`, which is responded with a status `0x00` or `[0x01][message length uvarint][message]`.
//!
//! UDP streams are packets `[length u16][payload]` to the requested address,
//! or `[SOCKS5 address][length u16][payload]` if the address flag is set.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use log::{debug, trace};
use shadowsocks::relay::socks5::Address;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional_with_sizes},
    task::JoinSet,
};

use super::{
    context::ServiceContext,
    tcprelay::{TcpConnect, connect_target, timeout_fut},
    uot::{self, MUX_FORMAT},
};

use self::padding::PaddingStream;

mod frames;
mod h2mux;
mod padding;
mod smux;
mod yamux;

/// Target address of sing-mux sessions
const MAGIC_ADDRESS: &str = "sp.mux.sing-box.arpa";

/// Maximum concurrent streams of a session
const MAX_STREAMS: usize = 1024;
/// Buffer size of TCP relays, same as the maximum frame size of smux
const COPY_BUFFER_SIZE: usize = 32 * 1024;

/// Multiplex protocols in session requests
const PROTOCOL_SMUX: u8 = 0;
const PROTOCOL_YAMUX: u8 = 1;
const PROTOCOL_H2MUX: u8 = 2;

/// Flags of stream requests
const FLAG_UDP: u16 = 0x01;
const FLAG_ADDR: u16 = 0x02;

/// Status of stream responses
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_ERROR: u8 = 0x01;

/// Target of TCP Brutal bandwidth exchange streams
const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";
/// Response of TCP Brutal bandwidth exchanges: status, not OK, and the message
const BRUTAL_NOT_ENABLED: &[u8] = b"\x00\x00\x23brutal is not enabled by the server";

/// Check if `addr` is the sing-mux magic address
pub(super) fn is_mux_address(addr: &Address) -> bool {
    matches!(*addr, Address::DomainNameAddress(ref host, _) if host == MAGIC_ADDRESS)
}

/// Session request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionRequest {
    protocol: u8,
    padding: bool,
}

impl SessionRequest {
    async fn read_from<R>(reader: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let version = reader.read_u8().await?;
        if version > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported sing-mux version {version}"),
            ));
        }

        let protocol = reader.read_u8().await?;
        if !matches!(protocol, PROTOCOL_SMUX | PROTOCOL_YAMUX | PROTOCOL_H2MUX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported sing-mux protocol {protocol}"),
            ));
        }

        let padding = version == 1 && reader.read_u8().await? != 0;
        if padding {
            let len = reader.read_u16().await?;
            let skipped = tokio::io::copy(&mut (&mut *reader).take(len as u64), &mut tokio::io::sink()).await?;
            if skipped != len as u64 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }

        Ok(Self { protocol, padding })
    }
}

/// Serve a sing-mux session until it is closed
pub(super) async fn serve<S>(
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    mut stream: S,
    timeout: Option<Duration>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = match timeout_fut(timeout, SessionRequest::read_from(&mut stream)).await {
        Ok(r) => r,
        Err(err) => {
            debug!(
                "sing-mux client {} read session request failed, error: {}",
                peer_addr, err
            );
            return Ok(());
        }
    };

    debug!("established sing-mux session {}, {:?}", peer_addr, request);

    let stream = PaddingStream::new(stream, request.padding);

    // Stream tasks are aborted when the session is closed
    let mut streams = JoinSet::new();

    // Accept loops must not await anything else, yamux and h2mux streams are responded by polling the session
    macro_rules! accept_streams {
        ($session:expr) => {{
            let mut session = $session;
            loop {
                match session.accept().await {
                    Ok(Some(s)) => spawn_stream(&mut streams, &context, peer_addr, s, timeout),
                    Ok(None) => break Ok(()),
                    Err(err) => break Err(err),
                }
            }
        }};
    }

    let result = match request.protocol {
        PROTOCOL_SMUX => accept_streams!(smux::Session::new(stream)),
        PROTOCOL_YAMUX => accept_streams!(yamux::Session::new(stream)),
        _ => match timeout_fut(timeout, h2mux::Session::handshake(stream)).await {
            Ok(session) => accept_streams!(session),
            Err(err) => Err(err),
        },
    };

    match result {
        Ok(()) => debug!("sing-mux session {} closed", peer_addr),
        Err(err) => debug!("sing-mux session {} closed with error: {}", peer_addr, err),
    }
    Ok(())
}

fn spawn_stream<T>(
    streams: &mut JoinSet<()>,
    context: &Arc<ServiceContext>,
    peer_addr: SocketAddr,
    stream: T,
    timeout: Option<Duration>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Reap finished streams
    while streams.try_join_next().is_some() {}

    streams.spawn(serve_stream(context.clone(), peer_addr, stream, timeout));
}

/// Stream request
#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamRequest {
    udp: bool,
    /// Packets of UDP streams have addresses
    packet_addr: bool,
    destination: Address,
}

impl StreamRequest {
    async fn read_from<R>(reader: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let flags = reader.read_u16().await?;
        let destination = Address::read_from(reader).await?;
        let udp = flags & FLAG_UDP != 0;

        Ok(Self {
            udp,
            packet_addr: udp && flags & FLAG_ADDR != 0,
            destination,
        })
    }
}

/// Error response, the message length is an uvarint
fn encode_error(message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 10 + message.len());
    buf.push(STATUS_ERROR);
    let mut len = message.len() as u64;
    while len >= 0x80 {
        buf.push(len as u8 | 0x80);
        len >>= 7;
    }
    buf.push(len as u8);
    buf.extend_from_slice(message.as_bytes());
    buf
}

async fn write_response<S>(stream: &mut S, response: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(response).await?;
    stream.flush().await
}

async fn serve_stream<T>(context: Arc<ServiceContext>, peer_addr: SocketAddr, mut stream: T, timeout: Option<Duration>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The request is sent with the first payload
    let request = match timeout_fut(timeout, StreamRequest::read_from(&mut stream)).await {
        Ok(r) => r,
        Err(err) => {
            debug!(
                "sing-mux client {} read stream request failed, error: {}",
                peer_addr, err
            );
            return;
        }
    };

    trace!("sing-mux client {} stream request {:?}", peer_addr, request);

    let result = if request.udp {
        serve_udp_stream(&context, peer_addr, &mut stream, &request).await
    } else if matches!(request.destination, Address::DomainNameAddress(ref host, _) if host == BRUTAL_EXCHANGE_DOMAIN) {
        serve_brutal_exchange(peer_addr, &mut stream, timeout).await
    } else {
        serve_tcp_stream(&context, peer_addr, &mut stream, request.destination, timeout).await
    };

    match result {
        // FIN or END_STREAM
        Ok(()) => {
            let _ = stream.shutdown().await;
        }
        // Dropped without shutdown, the stream is reset
        Err(err) => trace!("sing-mux client {} stream closed with error: {}", peer_addr, err),
    }
}

async fn serve_tcp_stream<T>(
    context: &ServiceContext,
    peer_addr: SocketAddr,
    stream: &mut T,
    mut target_addr: Address,
    timeout: Option<Duration>,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut remote_stream = match connect_target(context, peer_addr, stream, &mut target_addr, timeout).await {
        Ok(TcpConnect::Connected(s)) => s,
        Ok(TcpConnect::Blocked) => return write_response(stream, &encode_error("blocked by ACL rules")).await,
        Ok(TcpConnect::Closed) => return Ok(()),
        Err(err) => return write_response(stream, &encode_error(&err.to_string())).await,
    };

    write_response(stream, &[STATUS_SUCCESS]).await?;

    debug!("established sing-mux tcp tunnel {} <-> {}", peer_addr, target_addr);

    let (rn, wn) =
        copy_bidirectional_with_sizes(stream, &mut remote_stream, COPY_BUFFER_SIZE, COPY_BUFFER_SIZE).await?;
    trace!(
        "sing-mux tcp tunnel {} <-> {} closed, L2R {} bytes, R2L {} bytes",
        peer_addr, target_addr, rn, wn
    );
    Ok(())
}

async fn serve_udp_stream<T>(
    context: &ServiceContext,
    peer_addr: SocketAddr,
    stream: &mut T,
    request: &StreamRequest,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Targets of packets are checked by ACL one by one
    let connect_addr = if request.packet_addr {
        None
    } else {
        match uot::resolve_connect_target(context, peer_addr, &request.destination, MUX_FORMAT).await {
            Ok(Some(sa)) => Some(sa),
            Ok(None) => return write_response(stream, &encode_error("blocked by ACL rules")).await,
            Err(err) => return write_response(stream, &encode_error(&err.to_string())).await,
        }
    };

    write_response(stream, &[STATUS_SUCCESS]).await?;

    debug!(
        "established sing-mux udp tunnel {}, connect: {:?}",
        peer_addr, connect_addr
    );

    uot::relay(context, peer_addr, stream, connect_addr, MUX_FORMAT).await
}

/// TCP Brutal is not supported, clients enabling it close the session
async fn serve_brutal_exchange<T>(peer_addr: SocketAddr, stream: &mut T, timeout: Option<Duration>) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Receiving bandwidth of the client
    timeout_fut(timeout, stream.read_u64()).await?;

    debug!(
        "sing-mux client {} requested TCP Brutal, which is not enabled",
        peer_addr
    );
    write_response(stream, BRUTAL_NOT_ENABLED).await
}

#[cfg(test)]
mod test {
    use futures::StreamExt;
    use http::{Method, Request, StatusCode};
    use tokio::{
        io::DuplexStream,
        net::{TcpListener, UdpSocket},
        time,
    };

    use crate::acl::AccessControl;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

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

    fn context_with_acl(rules: &str) -> ServiceContext {
        let path = std::env::temp_dir().join(format!(
            "shadowsocks-sing-mux-{}-{:?}.acl",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, rules).unwrap();
        let acl = AccessControl::load_from_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let mut context = ServiceContext::new();
        context.set_acl(Arc::new(acl));
        context
    }

    /// Starts serving a session, whose request `header` has been sent
    async fn start_session(context: ServiceContext, header: &[u8]) -> DuplexStream {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        client.write_all(header).await.unwrap();
        let peer_addr = "127.0.0.1:1".parse().unwrap();
        tokio::spawn(serve(Arc::new(context), peer_addr, server, None));
        client
    }

    fn stream_request(flags: u16, addr: &Address) -> Vec<u8> {
        let mut buf = flags.to_be_bytes().to_vec();
        addr.write_to_buf(&mut buf);
        buf
    }

    async fn read_status<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(), String> {
        time::timeout(TIMEOUT, async {
            if stream.read_u8().await.unwrap() == STATUS_SUCCESS {
                return Ok(());
            }
            let len = stream.read_u8().await.unwrap();
            assert!(len < 0x80);
            let mut message = vec![0u8; len as usize];
            stream.read_exact(&mut message).await.unwrap();
            Err(String::from_utf8(message).unwrap())
        })
        .await
        .expect("read status timeout")
    }

    async fn tcp_round_trip<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, target: Address) -> Result<(), String> {
        // The request is sent with the first payload
        let mut data = stream_request(0, &target);
        data.extend_from_slice(b"hello");
        stream.write_all(&data).await.unwrap();
        stream.flush().await.unwrap();

        read_status(stream).await?;
        let mut buf = [0u8; 5];
        time::timeout(TIMEOUT, stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    async fn udp_round_trip<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: Address,
        packet_addr: bool,
    ) -> Result<(), String> {
        let flags = if packet_addr { FLAG_UDP | FLAG_ADDR } else { FLAG_UDP };
        let mut data = stream_request(flags, &target);
        for payload in [&b"hello"[..], b"world"] {
            if packet_addr {
                target.write_to_buf(&mut data);
            }
            data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            data.extend_from_slice(payload);
        }
        stream.write_all(&data).await.unwrap();
        stream.flush().await.unwrap();

        read_status(stream).await?;
        for payload in [&b"hello"[..], b"world"] {
            time::timeout(TIMEOUT, async {
                if packet_addr {
                    assert_eq!(Address::read_from(stream).await.unwrap(), target);
                }
                let len = stream.read_u16().await.unwrap();
                let mut buf = vec![0u8; len as usize];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, payload);
            })
            .await
            .expect("read packet timeout");
        }
        Ok(())
    }

    async fn yamux_client<S>(io: S) -> tokio_yamux::Control
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut session = tokio_yamux::Session::new_client(io, tokio_yamux::Config::default());
        let control = session.control();
        tokio::spawn(async move { while let Some(Ok(..)) = session.next().await {} });
        control
    }

    fn smux_frame(cmd: u8, stream_id: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = vec![1, cmd];
        buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&stream_id.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Reads data of a smux stream until FIN
    async fn smux_read_to_fin(client: &mut DuplexStream, stream_id: u32) -> Vec<u8> {
        let mut received = Vec::new();
        time::timeout(TIMEOUT, async {
            loop {
                let mut header = [0u8; 8];
                client.read_exact(&mut header).await.unwrap();
                let len = u16::from_le_bytes([header[2], header[3]]) as usize;
                let mut data = vec![0u8; len];
                client.read_exact(&mut data).await.unwrap();
                assert_eq!(
                    u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
                    stream_id
                );
                match header[1] {
                    2 => received.extend(data),
                    1 => break,
                    cmd => panic!("unexpected smux command {cmd}"),
                }
            }
        })
        .await
        .expect("read smux stream timeout");
        received
    }

    #[tokio::test]
    async fn requests() {
        let mut buf = &[0x00, 0x02][..];
        let request = SessionRequest::read_from(&mut buf).await.unwrap();
        assert_eq!(
            request,
            SessionRequest {
                protocol: PROTOCOL_H2MUX,
                padding: false
            }
        );

        let mut buf = &[0x01, 0x00, 0x00, 0xFF][..];
        let request = SessionRequest::read_from(&mut buf).await.unwrap();
        assert_eq!(
            request,
            SessionRequest {
                protocol: PROTOCOL_SMUX,
                padding: false
            }
        );
        // Not read
        assert_eq!(buf, &[0xFF]);

        let mut data = vec![0x01, 0x01, 0x01, 0x01, 0x00];
        data.extend_from_slice(&[0xEE; 256]);
        data.push(0xFF);
        let mut buf = &data[..];
        let request = SessionRequest::read_from(&mut buf).await.unwrap();
        assert_eq!(
            request,
            SessionRequest {
                protocol: PROTOCOL_YAMUX,
                padding: true
            }
        );
        assert_eq!(buf, &[0xFF]);

        for invalid in [&[0x02, 0x00][..], &[0x00, 0x03], &[0x01, 0x00, 0x01, 0x01, 0x00, 0xEE]] {
            let mut buf = invalid;
            assert!(SessionRequest::read_from(&mut buf).await.is_err(), "{invalid:?}");
        }

        let addr = Address::DomainNameAddress("example.com".to_owned(), 443);
        let data = stream_request(FLAG_UDP | FLAG_ADDR, &addr);
        let request = StreamRequest::read_from(&mut &data[..]).await.unwrap();
        assert_eq!(
            request,
            StreamRequest {
                udp: true,
                packet_addr: true,
                destination: addr.clone()
            }
        );
        // The address flag only works with UDP
        let data = stream_request(FLAG_ADDR, &addr);
        let request = StreamRequest::read_from(&mut &data[..]).await.unwrap();
        assert_eq!(
            request,
            StreamRequest {
                udp: false,
                packet_addr: false,
                destination: addr
            }
        );
    }

    #[test]
    fn responses() {
        assert_eq!(encode_error("error"), b"\x01\x05error");
        // Multi-byte uvarint
        let message = "e".repeat(300);
        let encoded = encode_error(&message);
        assert_eq!(&encoded[..3], &[0x01, 0xAC, 0x02]);
        assert_eq!(&encoded[3..], message.as_bytes());

        assert_eq!(BRUTAL_NOT_ENABLED.len(), 38);
        assert_eq!(&BRUTAL_NOT_ENABLED[..2], &[STATUS_SUCCESS, 0x00]);
        assert_eq!(
            &BRUTAL_NOT_ENABLED[2..],
            &encode_error("brutal is not enabled by the server")[1..]
        );
    }

    #[tokio::test]
    async fn smux_streams() {
        let tcp_echo = tcp_echo_server().await;
        let mut client = start_session(ServiceContext::new(), &[0x00, PROTOCOL_SMUX]).await;

        let mut data = stream_request(0, &Address::SocketAddress(tcp_echo));
        data.extend_from_slice(b"hello");
        let mut frames = smux_frame(0, 3, &[]);
        frames.extend(smux_frame(2, 3, &data));
        client.write_all(&frames).await.unwrap();

        let mut buf = Vec::new();
        while buf.len() < 6 {
            let mut header = [0u8; 8];
            time::timeout(TIMEOUT, client.read_exact(&mut header))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(header[1], 2);
            let mut data = vec![0u8; u16::from_le_bytes([header[2], header[3]]) as usize];
            client.read_exact(&mut data).await.unwrap();
            buf.extend(data);
        }
        assert_eq!(buf, b"\x00hello");

        // Closed by the client
        client.write_all(&smux_frame(1, 3, &[])).await.unwrap();
        assert!(smux_read_to_fin(&mut client, 3).await.is_empty());
    }

    #[tokio::test]
    async fn smux_blocked_by_acl() {
        let tcp_echo = tcp_echo_server().await;
        let udp_echo = udp_echo_server().await;
        let context = context_with_acl("[outbound_block_list]\n|localhost\n");
        let mut client = start_session(context, &[0x00, PROTOCOL_SMUX]).await;

        let mut frames = smux_frame(0, 3, &[]);
        let target = Address::DomainNameAddress("localhost".to_owned(), tcp_echo.port());
        frames.extend(smux_frame(2, 3, &stream_request(0, &target)));
        client.write_all(&frames).await.unwrap();
        assert_eq!(
            smux_read_to_fin(&mut client, 3).await,
            encode_error("blocked by ACL rules")
        );

        let mut frames = smux_frame(0, 5, &[]);
        let target = Address::DomainNameAddress("localhost".to_owned(), udp_echo.port());
        frames.extend(smux_frame(2, 5, &stream_request(FLAG_UDP, &target)));
        client.write_all(&frames).await.unwrap();
        assert_eq!(
            smux_read_to_fin(&mut client, 5).await,
            encode_error("blocked by ACL rules")
        );
    }

    #[tokio::test]
    async fn yamux_streams() {
        let tcp_echo = tcp_echo_server().await;
        let udp_echo = udp_echo_server().await;
        let client = start_session(ServiceContext::new(), &[0x00, PROTOCOL_YAMUX]).await;
        let mut control = yamux_client(client).await;

        let mut stream = control.open_stream().await.unwrap();
        tcp_round_trip(&mut stream, Address::SocketAddress(tcp_echo))
            .await
            .unwrap();

        let mut stream = control.open_stream().await.unwrap();
        udp_round_trip(&mut stream, Address::SocketAddress(udp_echo), false)
            .await
            .unwrap();

        let mut stream = control.open_stream().await.unwrap();
        udp_round_trip(&mut stream, Address::SocketAddress(udp_echo), true)
            .await
            .unwrap();

        // Connection failure
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let mut stream = control.open_stream().await.unwrap();
        assert!(
            tcp_round_trip(&mut stream, Address::SocketAddress(closed))
                .await
                .is_err()
        );

        // TCP Brutal
        let mut stream = control.open_stream().await.unwrap();
        let mut data = stream_request(0, &Address::DomainNameAddress(BRUTAL_EXCHANGE_DOMAIN.to_owned(), 0));
        data.extend_from_slice(&100_000_000u64.to_be_bytes());
        stream.write_all(&data).await.unwrap();
        let mut response = Vec::new();
        time::timeout(TIMEOUT, stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, BRUTAL_NOT_ENABLED);
    }

    #[tokio::test]
    async fn reset_on_error() {
        let udp_echo = udp_echo_server().await;
        let client = start_session(ServiceContext::new(), &[0x00, PROTOCOL_YAMUX]).await;
        let mut control = yamux_client(client).await;

        // Invalid address type of a packet fails the relay
        let mut stream = control.open_stream().await.unwrap();
        let mut data = stream_request(FLAG_UDP | FLAG_ADDR, &Address::SocketAddress(udp_echo));
        data.extend_from_slice(&[0x7F, 0x00, 0x00]);
        stream.write_all(&data).await.unwrap();
        read_status(&mut stream).await.unwrap();

        // Reset instead of FIN, which would look like a normal close
        let mut buf = Vec::new();
        let err = time::timeout(TIMEOUT, stream.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn h2mux_streams() {
        let tcp_echo = tcp_echo_server().await;
        let udp_echo = udp_echo_server().await;
        let client = start_session(ServiceContext::new(), &[0x00, PROTOCOL_H2MUX]).await;

        let (send_request, connection) = h2::client::handshake(client).await.unwrap();
        tokio::spawn(connection);
        let open = || {
            let mut send_request = send_request.clone();
            async move {
                let request = Request::builder()
                    .method(Method::CONNECT)
                    .uri("localhost:443")
                    .body(())
                    .unwrap();
                let (response, send) = send_request.send_request(request, false).unwrap();
                let response = time::timeout(TIMEOUT, response).await.unwrap().unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                h2mux::H2Stream::new(send, response.into_body())
            }
        };

        tcp_round_trip(&mut open().await, Address::SocketAddress(tcp_echo))
            .await
            .unwrap();
        udp_round_trip(&mut open().await, Address::SocketAddress(udp_echo), false)
            .await
            .unwrap();
        udp_round_trip(&mut open().await, Address::SocketAddress(udp_echo), true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn padding_session() {
        let tcp_echo = tcp_echo_server().await;
        let udp_echo = udp_echo_server().await;

        let mut header = vec![0x01, PROTOCOL_YAMUX, 0x01, 0x01, 0x2C];
        header.extend_from_slice(&[0u8; 300]);
        let client = start_session(ServiceContext::new(), &header).await;
        let mut control = yamux_client(PaddingStream::new(client, true)).await;

        // More than 16 frames in both directions
        for _ in 0..10 {
            let mut stream = control.open_stream().await.unwrap();
            tcp_round_trip(&mut stream, Address::SocketAddress(tcp_echo))
                .await
                .unwrap();
            let mut stream = control.open_stream().await.unwrap();
            udp_round_trip(&mut stream, Address::SocketAddress(udp_echo), true)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_session() {
        let mut client = start_session(ServiceContext::new(), &[0x00, 0x03, 0x00, 0x00]).await;
        let mut buf = Vec::new();
        time::timeout(TIMEOUT, client.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn magic_address() {
        assert!(is_mux_address(&Address::DomainNameAddress(
            MAGIC_ADDRESS.to_owned(),
            444
        )));
        assert!(!is_mux_address(&Address::DomainNameAddress(
            "example.com".to_owned(),
            444
        )));
        assert!(!is_mux_address(&Address::SocketAddress(
            "127.0.0.1:444".parse().unwrap()
        )));
    }
}
