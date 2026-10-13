//! sing-box compatible UDP over TCP (UoT) server
//!
//! <https://github.com/SagerNet/sing/tree/main/common/uot>
//!
//! v2 stream starts with a request `[is_connect u8][SOCKS5 address]`, v1 has no request.
//! Packets in both directions are:
//!
//! - non-connect mode: `[UoT address][length u16][payload]`
//! - connect mode: `[length u16][payload]`, target is the address in the request

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
    pin::{Pin, pin},
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, BufMut, BytesMut};
use log::{debug, error, trace, warn};
use shadowsocks::{lookup_then, relay::socks5::Address};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{self, Instant, Sleep},
};

use crate::net::utils::to_ipv4_mapped;

use super::{
    context::ServiceContext,
    udprelay::{receive_from_outbound_opt, send_outbound_packet},
};

/// Target address of UoT v2 streams
const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
/// Target address of legacy UoT v1 streams
const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

// Address types of packets, which are different from SOCKS5
const ADDR_TYPE_IPV4: u8 = 0x00;
const ADDR_TYPE_IPV6: u8 = 0x01;
const ADDR_TYPE_DOMAIN_NAME: u8 = 0x02;

/// Spare capacity reserved before each read, otherwise `BytesMut` grows by 64 bytes
const READ_RESERVE_SIZE: usize = 16 * 1024;

/// UoT protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotVersion {
    V1,
    V2,
}

/// Get the UoT version if `addr` is a UoT magic address
pub fn uot_version(addr: &Address) -> Option<UotVersion> {
    match *addr {
        Address::DomainNameAddress(ref host, _) if host == MAGIC_ADDRESS => Some(UotVersion::V2),
        Address::DomainNameAddress(ref host, _) if host == LEGACY_MAGIC_ADDRESS => Some(UotVersion::V1),
        _ => None,
    }
}

/// Decode a UoT address, returns `None` if `buf` is incomplete
fn decode_address(buf: &mut &[u8]) -> io::Result<Option<Address>> {
    let addr_len = match buf.first() {
        None => return Ok(None),
        Some(&ADDR_TYPE_IPV4) => 4,
        Some(&ADDR_TYPE_IPV6) => 16,
        Some(&ADDR_TYPE_DOMAIN_NAME) => match buf.get(1) {
            None => return Ok(None),
            Some(&n) => 1 + n as usize,
        },
        Some(&addr_type) => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid udp-over-tcp address type {addr_type:#x}"),
            ));
        }
    };

    // Type + Address + Port
    if buf.len() < 1 + addr_len + 2 {
        return Ok(None);
    }

    let addr = match buf.get_u8() {
        ADDR_TYPE_IPV4 => {
            let ip = Ipv4Addr::from(buf.get_u32());
            Address::SocketAddress(SocketAddr::new(ip.into(), buf.get_u16()))
        }
        ADDR_TYPE_IPV6 => {
            let ip = Ipv6Addr::from(buf.get_u128());
            Address::SocketAddress(SocketAddr::new(ip.into(), buf.get_u16()))
        }
        _ => {
            let len = buf.get_u8() as usize;
            let name = str::from_utf8(&buf[..len])
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid udp-over-tcp domain name"))?
                .to_owned();
            buf.advance(len);
            Address::DomainNameAddress(name, buf.get_u16())
        }
    };

    Ok(Some(addr))
}

/// Decode a packet, returns the target address (non-connect mode) and the payload range in `buf`,
/// or `None` if `buf` is incomplete
fn decode_packet(buf: &[u8], connect: bool) -> io::Result<Option<(Option<Address>, Range<usize>)>> {
    let mut rest = buf;

    let addr = if connect {
        None
    } else {
        match decode_address(&mut rest)? {
            None => return Ok(None),
            Some(addr) => Some(addr),
        }
    };

    if rest.len() < 2 {
        return Ok(None);
    }
    let len = rest.get_u16() as usize;
    if rest.len() < len {
        return Ok(None);
    }

    let start = buf.len() - rest.len();
    Ok(Some((addr, start..start + len)))
}

/// Convert IPv4-mapped-IPv6 address to IPv4
fn unmap_ipv4(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(ref v6) => match to_ipv4_mapped(v6.ip()) {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        SocketAddr::V4(..) => addr,
    }
}

/// Encode a packet, with source address `addr` in non-connect mode
fn encode_packet(buf: &mut BytesMut, addr: Option<SocketAddr>, payload: &[u8]) {
    if let Some(addr) = addr {
        // IPv4-mapped-IPv6 is sent back as IPv4
        let addr = unmap_ipv4(addr);

        match addr {
            SocketAddr::V4(ref v4) => {
                buf.put_u8(ADDR_TYPE_IPV4);
                buf.put_slice(&v4.ip().octets());
            }
            SocketAddr::V6(ref v6) => {
                buf.put_u8(ADDR_TYPE_IPV6);
                buf.put_slice(&v6.ip().octets());
            }
        }
        buf.put_u16(addr.port());
    }

    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
}

/// Serve a UoT stream until EOF, error or idle for `udp_expiry_duration`
pub async fn serve<S>(
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    mut stream: S,
    version: UotVersion,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let udp_expiry = context.udp_expiry_duration();

    // v2 request may be sent with the first packet
    let connect_addr = match version {
        UotVersion::V1 => None,
        UotVersion::V2 => {
            let request = time::timeout(udp_expiry, async {
                let is_connect = stream.read_u8().await?;
                let addr = Address::read_from(&mut stream).await?;
                io::Result::Ok((is_connect != 0, addr))
            })
            .await;

            match request {
                Ok(Ok((is_connect, addr))) => is_connect.then_some(addr),
                Ok(Err(err)) => {
                    debug!("udp-over-tcp client {} read request failed, error: {}", peer_addr, err);
                    return Ok(());
                }
                Err(..) => {
                    debug!("udp-over-tcp client {} read request timeout", peer_addr);
                    return Ok(());
                }
            }
        }
    };

    if let Some(ref addr) = connect_addr
        && context.check_outbound_blocked(addr).await
    {
        error!(
            "udp-over-tcp client {} outbound {} blocked by ACL rules",
            peer_addr, addr
        );
        return Ok(());
    }

    // Resolve the target of connect mode only once, it can't be changed by DNS after the ACL check
    let connect_addr = match connect_addr {
        None => None,
        Some(Address::SocketAddress(sa)) => Some(unmap_ipv4(sa)),
        Some(Address::DomainNameAddress(ref dname, port)) => {
            match async { lookup_then!(context.context_ref(), dname, port, |sa| { io::Result::Ok(()) }) }.await {
                Ok((sa, ..)) => Some(unmap_ipv4(sa)),
                Err(err) => {
                    error!(
                        "udp-over-tcp client {} resolve {}:{} failed, error: {}",
                        peer_addr, dname, port, err
                    );
                    return Ok(());
                }
            }
        }
    };
    let connect_target = connect_addr.map(Address::SocketAddress);

    debug!(
        "established udp-over-tcp {:?} tunnel {}, connect: {:?}",
        version, peer_addr, connect_addr
    );

    let connect = connect_addr.is_some();

    let mut read_buffer = BytesMut::new();
    let mut write_buffer = BytesMut::new();
    let mut outbound_ipv4_socket = None;
    let mut outbound_ipv6_socket = None;
    let mut outbound_ipv4_buffer = Vec::new();
    let mut outbound_ipv6_buffer = Vec::new();
    let mut idle_timer = pin!(time::sleep(udp_expiry));

    loop {
        // `read_buf` is cancel safe, but writes are not. Writes must only happen in branch handlers.
        read_buffer.reserve(READ_RESERVE_SIZE);

        tokio::select! {
            read_result = stream.read_buf(&mut read_buffer) => {
                if read_result? == 0 {
                    if !read_buffer.is_empty() {
                        debug!(
                            "udp-over-tcp client {} closed with {} bytes of incomplete packet",
                            peer_addr,
                            read_buffer.len()
                        );
                    }
                    break;
                }
                reset_timer(idle_timer.as_mut(), udp_expiry);

                let mut offset = 0;
                while let Some((addr, payload)) = decode_packet(&read_buffer[offset..], connect)? {
                    let data = &read_buffer[offset + payload.start..offset + payload.end];
                    offset += payload.end;

                    let target_addr = match (&addr, &connect_target) {
                        (Some(addr), _) => {
                            if context.check_outbound_blocked(addr).await {
                                warn!("udp-over-tcp client {} outbound {} blocked by ACL rules", peer_addr, addr);
                                continue;
                            }
                            addr
                        }
                        (None, Some(addr)) => addr,
                        (None, None) => unreachable!("udp-over-tcp packet without target address"),
                    };

                    trace!("udp-over-tcp relay {} -> {} with {} bytes", peer_addr, target_addr, data.len());

                    if let Err(err) = send_outbound_packet(
                        &context,
                        peer_addr,
                        &mut outbound_ipv4_socket,
                        &mut outbound_ipv6_socket,
                        target_addr,
                        data,
                    )
                    .await
                    {
                        error!(
                            "udp-over-tcp relay {} -> {} with {} bytes, error: {}",
                            peer_addr,
                            target_addr,
                            data.len(),
                            err
                        );
                    }
                }
                read_buffer.advance(offset);
            }

            received_opt = receive_from_outbound_opt(&outbound_ipv4_socket, &mut outbound_ipv4_buffer), if outbound_ipv4_socket.is_some() => {
                let (n, addr) = match received_opt {
                    Ok(r) => r,
                    Err(err) => {
                        error!("udp-over-tcp relay {} <- ... failed, error: {}", peer_addr, err);
                        // Socket failure. Reset for recreation.
                        outbound_ipv4_socket = None;
                        continue;
                    }
                };

                if !is_expected_source(connect_addr, addr) {
                    trace!("udp-over-tcp relay {} <- {} dropped, expecting {:?}", peer_addr, addr, connect_addr);
                    continue;
                }

                let data = &outbound_ipv4_buffer[..n];
                send_back_packet(&mut stream, &mut write_buffer, peer_addr, (!connect).then_some(addr), data, udp_expiry).await?;
                reset_timer(idle_timer.as_mut(), udp_expiry);
            }

            received_opt = receive_from_outbound_opt(&outbound_ipv6_socket, &mut outbound_ipv6_buffer), if outbound_ipv6_socket.is_some() => {
                let (n, addr) = match received_opt {
                    Ok(r) => r,
                    Err(err) => {
                        error!("udp-over-tcp relay {} <- ... failed, error: {}", peer_addr, err);
                        // Socket failure. Reset for recreation.
                        outbound_ipv6_socket = None;
                        continue;
                    }
                };

                if !is_expected_source(connect_addr, addr) {
                    trace!("udp-over-tcp relay {} <- {} dropped, expecting {:?}", peer_addr, addr, connect_addr);
                    continue;
                }

                let data = &outbound_ipv6_buffer[..n];
                send_back_packet(&mut stream, &mut write_buffer, peer_addr, (!connect).then_some(addr), data, udp_expiry).await?;
                reset_timer(idle_timer.as_mut(), udp_expiry);
            }

            _ = &mut idle_timer => {
                debug!("udp-over-tcp tunnel {} idle timeout", peer_addr);
                break;
            }
        }
    }

    // Notify the client (JLS close_notify), which may block if the client doesn't read
    let _ = time::timeout(udp_expiry, stream.shutdown()).await;

    debug!("udp-over-tcp tunnel {} closed", peer_addr);
    Ok(())
}

/// `udp_timeout` may be too large to be added to `Instant`, then the timer never fires
fn reset_timer(timer: Pin<&mut Sleep>, timeout: Duration) {
    if let Some(deadline) = Instant::now().checked_add(timeout) {
        timer.reset(deadline);
    }
}

/// Connect mode responds without address, so only packets from the target are accepted, like connected UDP sockets
fn is_expected_source(connect_addr: Option<SocketAddr>, addr: SocketAddr) -> bool {
    match connect_addr {
        None => true,
        Some(target) => {
            let addr = unmap_ipv4(addr);
            addr.ip() == target.ip() && addr.port() == target.port()
        }
    }
}

async fn send_back_packet<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    peer_addr: SocketAddr,
    addr: Option<SocketAddr>,
    data: &[u8],
    timeout: Duration,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if data.len() > u16::MAX as usize {
        warn!(
            "udp-over-tcp failed to send back {} bytes to client {}, packet too large",
            data.len(),
            peer_addr
        );
        return Ok(());
    }

    buffer.clear();
    encode_packet(buffer, addr, data);

    // Flush is required, JLS keeps data in TLS buffer until flushed
    match time::timeout(timeout, async {
        stream.write_all(buffer).await?;
        stream.flush().await
    })
    .await
    {
        Ok(r) => r,
        Err(..) => Err(ErrorKind::TimedOut.into()),
    }
}

#[cfg(test)]
mod test {
    use std::net::SocketAddrV6;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UdpSocket,
    };

    use super::*;

    #[test]
    fn magic_address() {
        assert_eq!(
            uot_version(&Address::DomainNameAddress(MAGIC_ADDRESS.to_owned(), 0)),
            Some(UotVersion::V2)
        );
        assert_eq!(
            uot_version(&Address::DomainNameAddress(LEGACY_MAGIC_ADDRESS.to_owned(), 443)),
            Some(UotVersion::V1)
        );
        assert_eq!(
            uot_version(&Address::DomainNameAddress("example.com".to_owned(), 0)),
            None
        );
        assert_eq!(
            uot_version(&Address::SocketAddress("127.0.0.1:0".parse().unwrap())),
            None
        );
    }

    #[test]
    fn decode_packets() {
        // 8.8.8.8:53, AA BB CC
        let buf = [0x00, 8, 8, 8, 8, 0x00, 0x35, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xFF];
        let (addr, payload) = decode_packet(&buf, false).unwrap().unwrap();
        assert_eq!(addr, Some(Address::SocketAddress("8.8.8.8:53".parse().unwrap())));
        assert_eq!(&buf[payload], &[0xAA, 0xBB, 0xCC]);

        // [2001:db8::1]:443, empty payload
        let mut buf = vec![0x01];
        buf.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        buf.extend_from_slice(&[0x01, 0xBB, 0x00, 0x00]);
        let (addr, payload) = decode_packet(&buf, false).unwrap().unwrap();
        assert_eq!(addr, Some(Address::SocketAddress("[2001:db8::1]:443".parse().unwrap())));
        assert!(payload.is_empty());
        assert_eq!(payload.end, buf.len());

        // example.com:80
        let mut buf = vec![0x02, 11];
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&[0x00, 0x50, 0x00, 0x01, 0x42]);
        let (addr, payload) = decode_packet(&buf, false).unwrap().unwrap();
        assert_eq!(addr, Some(Address::DomainNameAddress("example.com".to_owned(), 80)));
        assert_eq!(&buf[payload], &[0x42]);

        // connect mode
        let buf = [0x00, 0x02, 0x11, 0x22];
        let (addr, payload) = decode_packet(&buf, true).unwrap().unwrap();
        assert_eq!(addr, None);
        assert_eq!(&buf[payload], &[0x11, 0x22]);
    }

    #[test]
    fn decode_incomplete_packets() {
        let mut domain = vec![0x02, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&[0x00, 0x50, 0x00, 0x01, 0x42]);

        let packets: [(&[u8], bool); 3] = [
            (&[0x00, 8, 8, 8, 8, 0x00, 0x35, 0x00, 0x03, 0xAA, 0xBB, 0xCC], false),
            (&domain, false),
            (&[0x00, 0x02, 0x11, 0x22], true),
        ];

        for (packet, connect) in packets {
            for n in 0..packet.len() {
                assert!(decode_packet(&packet[..n], connect).unwrap().is_none());
            }
            assert!(decode_packet(packet, connect).unwrap().is_some());
        }
    }

    #[test]
    fn decode_invalid_packets() {
        // SOCKS5 IPv6 address type
        assert!(decode_packet(&[0x04, 0, 0, 0, 0], false).is_err());
        // Invalid UTF-8
        assert!(decode_packet(&[0x02, 0x01, 0xFF, 0x00, 0x50, 0x00, 0x00], false).is_err());
    }

    #[test]
    fn encode_packets() {
        let mut buf = BytesMut::new();
        encode_packet(&mut buf, Some("8.8.8.8:53".parse().unwrap()), &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(
            &buf[..],
            &[0x00, 8, 8, 8, 8, 0x00, 0x35, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44]
        );

        // IPv4-mapped-IPv6 is sent back as IPv4
        buf.clear();
        let mapped = SocketAddrV6::new(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped(), 53, 0, 0);
        encode_packet(&mut buf, Some(mapped.into()), &[]);
        assert_eq!(&buf[..], &[0x00, 1, 2, 3, 4, 0x00, 0x35, 0x00, 0x00]);

        buf.clear();
        encode_packet(&mut buf, Some("[2001:db8::1]:443".parse().unwrap()), &[0x42]);
        let (addr, payload) = decode_packet(&buf, false).unwrap().unwrap();
        assert_eq!(addr, Some(Address::SocketAddress("[2001:db8::1]:443".parse().unwrap())));
        assert_eq!(&buf[payload], &[0x42]);

        // connect mode
        buf.clear();
        encode_packet(&mut buf, None, &[0x11, 0x22]);
        assert_eq!(&buf[..], &[0x00, 0x02, 0x11, 0x22]);
    }

    /// UDP echo server, returns its address
    async fn udp_echo_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                socket.send_to(&buf[..n], peer).await.unwrap();
            }
        });
        addr
    }

    fn encode_socks5_addr(addr: SocketAddr) -> Vec<u8> {
        let mut buf = BytesMut::new();
        Address::SocketAddress(addr).write_to_buf(&mut buf);
        buf.to_vec()
    }

    /// Write `data` one byte at a time, to test partial packets and lazy request
    async fn write_bytewise<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) {
        for b in data {
            stream.write_all(&[*b]).await.unwrap();
            tokio::task::yield_now().await;
        }
    }

    async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S, connect: bool) -> (Option<SocketAddr>, Vec<u8>) {
        let addr = if connect {
            None
        } else {
            let mut ipv4 = [0u8; 7];
            stream.read_exact(&mut ipv4).await.unwrap();
            assert_eq!(ipv4[0], ADDR_TYPE_IPV4);
            let ip = Ipv4Addr::new(ipv4[1], ipv4[2], ipv4[3], ipv4[4]);
            Some(SocketAddr::new(ip.into(), u16::from_be_bytes([ipv4[5], ipv4[6]])))
        };
        let len = stream.read_u16().await.unwrap();
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).await.unwrap();
        (addr, payload)
    }

    fn start_server(version: UotVersion) -> tokio::io::DuplexStream {
        start_server_with_context(ServiceContext::new(), version)
    }

    fn start_server_with_context(context: ServiceContext, version: UotVersion) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let peer_addr = "127.0.0.1:1".parse().unwrap();
        tokio::spawn(serve(Arc::new(context), peer_addr, server, version));
        client
    }

    #[tokio::test]
    async fn serve_v2() {
        let echo_addr = udp_echo_server().await;
        let mut client = start_server(UotVersion::V2);

        // Request is sent lazily with the first packet
        let mut data = vec![0x00];
        data.extend(encode_socks5_addr(echo_addr));
        let mut packets = BytesMut::new();
        encode_packet(&mut packets, Some(echo_addr), b"hello");
        encode_packet(&mut packets, Some(echo_addr), b"");
        data.extend_from_slice(&packets);
        write_bytewise(&mut client, &data).await;

        assert_eq!(
            read_packet(&mut client, false).await,
            (Some(echo_addr), b"hello".to_vec())
        );
        assert_eq!(read_packet(&mut client, false).await, (Some(echo_addr), Vec::new()));

        // Large packet, written at once
        let payload = vec![0x5A; 20000];
        packets.clear();
        encode_packet(&mut packets, Some(echo_addr), &payload);
        client.write_all(&packets).await.unwrap();
        assert_eq!(read_packet(&mut client, false).await, (Some(echo_addr), payload));
    }

    #[tokio::test]
    async fn serve_v2_connect() {
        let echo_addr = udp_echo_server().await;
        let mut client = start_server(UotVersion::V2);

        let mut data = vec![0x01];
        data.extend(encode_socks5_addr(echo_addr));
        let mut packets = BytesMut::new();
        encode_packet(&mut packets, None, b"hello");
        data.extend_from_slice(&packets);
        write_bytewise(&mut client, &data).await;

        assert_eq!(read_packet(&mut client, true).await, (None, b"hello".to_vec()));
    }

    #[tokio::test]
    async fn serve_v2_connect_domain_name() {
        let echo_addr = udp_echo_server().await;
        let mut client = start_server(UotVersion::V2);

        let mut data = vec![0x01];
        let mut addr = BytesMut::new();
        Address::DomainNameAddress("localhost".to_owned(), echo_addr.port()).write_to_buf(&mut addr);
        data.extend_from_slice(&addr);
        let mut packets = BytesMut::new();
        encode_packet(&mut packets, None, b"hello");
        data.extend_from_slice(&packets);
        client.write_all(&data).await.unwrap();

        assert_eq!(read_packet(&mut client, true).await, (None, b"hello".to_vec()));
    }

    #[tokio::test]
    async fn serve_v2_connect_drops_other_sources() {
        // Echo server, which sends a packet from another socket before each echo
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                other.send_to(b"spoofed", peer).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                socket.send_to(&buf[..n], peer).await.unwrap();
            }
        });

        let mut client = start_server(UotVersion::V2);

        let mut data = vec![0x01];
        data.extend(encode_socks5_addr(echo_addr));
        let mut packets = BytesMut::new();
        encode_packet(&mut packets, None, b"hello");
        data.extend_from_slice(&packets);
        client.write_all(&data).await.unwrap();

        assert_eq!(read_packet(&mut client, true).await, (None, b"hello".to_vec()));
    }

    #[tokio::test]
    async fn serve_huge_udp_timeout() {
        let echo_addr = udp_echo_server().await;
        let mut context = ServiceContext::new();
        context.set_udp_expiry_duration(Duration::MAX);
        let mut client = start_server_with_context(context, UotVersion::V1);

        let mut packets = BytesMut::new();
        encode_packet(&mut packets, Some(echo_addr), b"hello");
        client.write_all(&packets).await.unwrap();

        assert_eq!(
            read_packet(&mut client, false).await,
            (Some(echo_addr), b"hello".to_vec())
        );
    }

    #[tokio::test]
    async fn serve_v1() {
        let echo_addr = udp_echo_server().await;
        let mut client = start_server(UotVersion::V1);

        let mut packets = BytesMut::new();
        encode_packet(&mut packets, Some(echo_addr), b"hello");
        encode_packet(&mut packets, Some(echo_addr), b"world");
        client.write_all(&packets).await.unwrap();

        assert_eq!(
            read_packet(&mut client, false).await,
            (Some(echo_addr), b"hello".to_vec())
        );
        assert_eq!(
            read_packet(&mut client, false).await,
            (Some(echo_addr), b"world".to_vec())
        );
    }

    #[tokio::test]
    async fn serve_invalid_address_type() {
        let mut client = start_server(UotVersion::V1);

        client.write_all(&[0x03, 0x00, 0x00]).await.unwrap();

        // Server closes the stream
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn serve_eof() {
        let echo_addr = udp_echo_server().await;
        let mut client = start_server(UotVersion::V1);

        let mut packets = BytesMut::new();
        encode_packet(&mut packets, Some(echo_addr), b"hello");
        client.write_all(&packets).await.unwrap();
        assert_eq!(
            read_packet(&mut client, false).await,
            (Some(echo_addr), b"hello".to_vec())
        );

        client.shutdown().await.unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        assert!(buf.is_empty());
    }
}
