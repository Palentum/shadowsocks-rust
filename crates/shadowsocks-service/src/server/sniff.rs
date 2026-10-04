//! Sniffing the domain name from the first bytes of a TCP stream
//!
//! Clients resolving domain names by themselves request IP addresses, while the domain name is still in the
//! SNI of TLS ClientHello, or in the `Host` header of HTTP/1.x requests.

use std::{io, net::IpAddr, str, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{self, Instant},
};

use crate::config::DomainSniffConfig;

/// Time waiting for the client to send enough bytes
const SNIFF_TIMEOUT: Duration = Duration::from_millis(250);
/// Maximum bytes read ahead, far more than a TLS ClientHello takes
const SNIFF_BUFFER_SIZE: usize = 16 * 1024;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: usize = 0x01;
const TLS_EXTENSION_SERVER_NAME: usize = 0x0000;
const TLS_NAME_TYPE_HOST_NAME: usize = 0x00;

/// HTTP/1.x request methods, each followed by an origin-form request target.
/// The `Host` of requests to proxies (CONNECT, absolute-form) is not the server connected to
const HTTP_METHODS: [&[u8]; 8] = [
    b"GET /",
    b"POST /",
    b"PUT /",
    b"DELETE /",
    b"HEAD /",
    b"OPTIONS /",
    b"PATCH /",
    b"TRACE /",
];

/// Reads the first bytes of `stream` and sniffs the domain name in them
///
/// Returns the bytes read, which have to be sent to the target before relaying, and the domain name.
/// Stops reading at EOF, or after `SNIFF_TIMEOUT` if the client sends nothing or not enough.
pub async fn sniff_domain<S>(stream: &mut S, config: DomainSniffConfig) -> io::Result<(Vec<u8>, Option<String>)>
where
    S: AsyncRead + Unpin,
{
    let deadline = Instant::now() + SNIFF_TIMEOUT;
    let mut buffer = vec![0u8; SNIFF_BUFFER_SIZE];
    let mut len = 0;

    let domain = loop {
        let n = match time::timeout_at(deadline, stream.read(&mut buffer[len..])).await {
            Ok(result) => result?,
            Err(..) => break None,
        };
        if n == 0 {
            break None;
        }
        len += n;

        match sniff(&buffer[..len], config) {
            Sniffed::Domain(domain) => break Some(domain),
            Sniffed::Incomplete if len < buffer.len() => {}
            Sniffed::Incomplete | Sniffed::NotFound => break None,
        }
    };

    buffer.truncate(len);
    Ok((buffer, domain))
}

#[derive(Debug, PartialEq, Eq)]
enum Sniffed {
    Domain(String),
    /// More bytes may contain the domain name
    Incomplete,
    NotFound,
}

fn sniff(data: &[u8], config: DomainSniffConfig) -> Sniffed {
    match data.first() {
        Some(&TLS_CONTENT_TYPE_HANDSHAKE) if config.tls => sniff_tls(data),
        Some(..) if config.http => sniff_http(data),
        _ => Sniffed::NotFound,
    }
}

/// Sniffs the SNI of a TLS ClientHello, which may be fragmented into several handshake records
fn sniff_tls(data: &[u8]) -> Sniffed {
    let mut handshake = Vec::new();
    let mut records = data;
    while let [TLS_CONTENT_TYPE_HANDSHAKE, 0x03, _, len_hi, len_lo, rest @ ..] = records {
        let len = usize::from(u16::from_be_bytes([*len_hi, *len_lo]));
        let fragment = &rest[..len.min(rest.len())];
        handshake.extend_from_slice(fragment);
        records = &rest[fragment.len()..];
    }

    let mut message = Reader(&handshake);
    match (message.uint(1), message.vector(3)) {
        (Some(TLS_HANDSHAKE_CLIENT_HELLO), Some(body)) => server_name(body).map_or(Sniffed::NotFound, domain_name),
        // Truncated, more bytes won't help if a non-handshake record follows
        (Some(TLS_HANDSHAKE_CLIENT_HELLO) | None, None) if records.len() < TLS_RECORD_HEADER_LEN => Sniffed::Incomplete,
        _ => Sniffed::NotFound,
    }
}

/// Gets the `host_name` of the `server_name` extension in a ClientHello `body`
fn server_name(body: &[u8]) -> Option<&[u8]> {
    let mut body = Reader(body);
    body.take(2 + 32)?; // legacy_version, random
    body.vector(1)?; // legacy_session_id
    body.vector(2)?; // cipher_suites
    body.vector(1)?; // legacy_compression_methods

    let mut extensions = Reader(body.vector(2)?);
    while !extensions.0.is_empty() {
        let extension_type = extensions.uint(2)?;
        let extension_data = extensions.vector(2)?;
        if extension_type == TLS_EXTENSION_SERVER_NAME {
            // host_name is the only name type, and appears once at most
            let mut names = Reader(Reader(extension_data).vector(2)?);
            if names.uint(1)? != TLS_NAME_TYPE_HOST_NAME {
                return None;
            }
            return names.vector(2);
        }
    }
    None
}

/// Reads TLS big-endian integers and vectors, `None` if running out of bytes
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (bytes, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(bytes)
    }

    fn uint(&mut self, size: usize) -> Option<usize> {
        let bytes = self.take(size)?;
        Some(bytes.iter().fold(0, |n, &b| (n << 8) | usize::from(b)))
    }

    /// Reads a vector with a `len_size` bytes length prefix
    fn vector(&mut self, len_size: usize) -> Option<&'a [u8]> {
        let len = self.uint(len_size)?;
        self.take(len)
    }
}

/// Sniffs the `Host` header of an HTTP/1.x request
fn sniff_http(data: &[u8]) -> Sniffed {
    if !HTTP_METHODS.iter().any(|method| data.starts_with(method)) {
        return Sniffed::NotFound;
    }

    // Skips the request line
    let Some((_, mut headers)) = split_line(data) else {
        return Sniffed::Incomplete;
    };
    while let Some((line, rest)) = split_line(headers) {
        if line.is_empty() {
            // End of headers
            return Sniffed::NotFound;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':')
            && line[..colon].eq_ignore_ascii_case(b"host")
        {
            // Removes the port, domain names have no `:`
            let value = line[colon + 1..].trim_ascii();
            return domain_name(value.split(|&b| b == b':').next().unwrap_or(value));
        }
        headers = rest;
    }
    Sniffed::Incomplete
}

/// Splits the first CRLF terminated line off `data`
fn split_line(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = data.windows(2).position(|w| w == b"\r\n")?;
    Some((&data[..end], &data[end + 2..]))
}

/// Accepts `name` if it looks like a domain name. IP addresses are not domain names
fn domain_name(name: &[u8]) -> Sniffed {
    let is_domain_name = !name.is_empty()
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    match str::from_utf8(name) {
        Ok(name) if is_domain_name && name.parse::<IpAddr>().is_err() => Sniffed::Domain(name.to_owned()),
        _ => Sniffed::NotFound,
    }
}

#[cfg(test)]
mod test {
    use tokio::io::AsyncWriteExt;

    use super::*;

    const TLS_AND_HTTP: DomainSniffConfig = DomainSniffConfig {
        tls: true,
        http: true,
        redirect: false,
    };

    fn domain(name: &str) -> Sniffed {
        Sniffed::Domain(name.to_owned())
    }

    /// ClientHello handshake message, with a `server_name` extension if `sni` is set
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        // supported_versions, an unrelated extension before server_name
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        if let Some(sni) = sni {
            let len = sni.len() as u16;
            extensions.extend_from_slice(&[0x00, 0x00]);
            extensions.extend_from_slice(&(len + 5).to_be_bytes()); // extension_data
            extensions.extend_from_slice(&(len + 3).to_be_bytes()); // server_name_list
            extensions.push(0x00); // host_name
            extensions.extend_from_slice(&len.to_be_bytes());
            extensions.extend_from_slice(sni.as_bytes());
        }

        let mut body = vec![0x03, 0x03]; // legacy_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(32); // legacy_session_id
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut message = vec![0x01];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    /// Fragments a handshake `message` into records carrying at most `size` bytes
    fn records(message: &[u8], size: usize) -> Vec<u8> {
        let mut records = Vec::new();
        for fragment in message.chunks(size) {
            records.extend_from_slice(&[0x16, 0x03, 0x01]);
            records.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            records.extend_from_slice(fragment);
        }
        records
    }

    #[test]
    fn tls_sni() {
        let message = client_hello(Some("www.Example.com"));
        assert_eq!(
            sniff(&records(&message, 16384), TLS_AND_HTTP),
            domain("www.Example.com")
        );
        assert_eq!(sniff(&records(&message, 16), TLS_AND_HTTP), domain("www.Example.com"));

        // A ChangeCipherSpec record may follow in TLS 1.3 middlebox compatibility mode
        let mut data = records(&message, 16384);
        data.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        assert_eq!(sniff(&data, TLS_AND_HTTP), domain("www.Example.com"));
    }

    #[test]
    fn tls_truncated() {
        let message = client_hello(Some("www.example.com"));
        for data in [records(&message, 16384), records(&message, 16)] {
            for len in 1..data.len() {
                assert_eq!(
                    sniff(&data[..len], TLS_AND_HTTP),
                    Sniffed::Incomplete,
                    "truncated at {len}"
                );
            }
        }

        // Followed by another record, the ClientHello will never be complete
        let mut data = records(&message[..64], 64);
        data.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]);
        assert_eq!(sniff(&data, TLS_AND_HTTP), Sniffed::NotFound);
    }

    #[test]
    fn tls_without_sni() {
        let message = client_hello(None);
        assert_eq!(sniff(&records(&message, 16384), TLS_AND_HTTP), Sniffed::NotFound);

        // Not a ClientHello
        let mut message = client_hello(Some("www.example.com"));
        message[0] = 0x02;
        assert_eq!(sniff(&records(&message, 16384), TLS_AND_HTTP), Sniffed::NotFound);
    }

    #[test]
    fn http_host() {
        let request = b"GET /index.html HTTP/1.1\r\nUser-Agent: curl\r\nhost:  www.Example.com:8080 \r\n\r\n";
        assert_eq!(sniff(request, TLS_AND_HTTP), domain("www.Example.com"));

        let request = b"POST / HTTP/1.0\r\nHost: www.example.com\r\n";
        assert_eq!(sniff(request, TLS_AND_HTTP), domain("www.example.com"));
    }

    #[test]
    fn http_incomplete() {
        assert_eq!(sniff(b"GET / HTTP/1.1", TLS_AND_HTTP), Sniffed::Incomplete);
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nAccept: */*\r\nHo", TLS_AND_HTTP),
            Sniffed::Incomplete
        );
    }

    #[test]
    fn http_proxy_request() {
        // The Host of requests to proxies is not the server connected to
        let request = b"CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n";
        assert_eq!(sniff(request, TLS_AND_HTTP), Sniffed::NotFound);
        let request = b"GET http://www.example.com/ HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        assert_eq!(sniff(request, TLS_AND_HTTP), Sniffed::NotFound);
    }

    #[test]
    fn http_without_host() {
        let request = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\nHost: www.example.com\r\n\r\n";
        assert_eq!(sniff(request, TLS_AND_HTTP), Sniffed::NotFound);
    }

    #[test]
    fn not_domain_name() {
        for host in ["127.0.0.1", "127.0.0.1:80", "[::1]:80", "::1", "a b", "a/b", ""] {
            let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert_eq!(
                sniff(request.as_bytes(), TLS_AND_HTTP),
                Sniffed::NotFound,
                "Host: {host}"
            );
        }

        let message = client_hello(Some("10.0.0.1"));
        assert_eq!(sniff(&records(&message, 16384), TLS_AND_HTTP), Sniffed::NotFound);
        let message = client_hello(Some("www.example.com\r\nX"));
        assert_eq!(sniff(&records(&message, 16384), TLS_AND_HTTP), Sniffed::NotFound);
    }

    #[test]
    fn disabled_protocols() {
        let tls = records(&client_hello(Some("www.example.com")), 16384);
        let http = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";

        let tls_only = DomainSniffConfig {
            http: false,
            ..TLS_AND_HTTP
        };
        assert_eq!(sniff(&tls, tls_only), domain("www.example.com"));
        assert_eq!(sniff(http, tls_only), Sniffed::NotFound);

        let http_only = DomainSniffConfig {
            tls: false,
            ..TLS_AND_HTTP
        };
        assert_eq!(sniff(&tls, http_only), Sniffed::NotFound);
        assert_eq!(sniff(http, http_only), domain("www.example.com"));
    }

    #[test]
    fn other_protocols() {
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.6\r\n", TLS_AND_HTTP), Sniffed::NotFound);
        assert_eq!(
            sniff(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", TLS_AND_HTTP),
            Sniffed::NotFound
        );
        assert_eq!(sniff(&[0x16, 0x01, 0x00, 0x00, 0x00], TLS_AND_HTTP), Sniffed::NotFound);
        assert_eq!(sniff(&[], TLS_AND_HTTP), Sniffed::NotFound);
    }

    #[tokio::test]
    async fn sniff_domain_across_reads() {
        let data = records(&client_hello(Some("www.example.com")), 16384);
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        let (first, second) = data.split_at(data.len() / 2);
        client.write_all(first).await.unwrap();
        let writer = tokio::spawn({
            let second = second.to_vec();
            async move {
                time::sleep(Duration::from_millis(20)).await;
                client.write_all(&second).await.unwrap();
                client
            }
        });

        let (read, domain) = sniff_domain(&mut server, TLS_AND_HTTP).await.unwrap();
        assert_eq!(domain.as_deref(), Some("www.example.com"));
        assert_eq!(read, data);
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn sniff_domain_gives_up() {
        // Nothing sent before the timeout
        let (_client, mut server) = tokio::io::duplex(64 * 1024);
        let started = Instant::now();
        let (read, domain) = sniff_domain(&mut server, TLS_AND_HTTP).await.unwrap();
        assert!(read.is_empty() && domain.is_none());
        assert!(started.elapsed() >= SNIFF_TIMEOUT);

        // EOF before the headers complete
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        drop(client);
        let (read, domain) = sniff_domain(&mut server, TLS_AND_HTTP).await.unwrap();
        assert_eq!(read, b"GET / HTTP/1.1\r\n");
        assert!(domain.is_none());

        // Not sniffable, returns without waiting for more
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        client.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
        let (read, domain) = sniff_domain(&mut server, TLS_AND_HTTP).await.unwrap();
        assert_eq!(read, b"SSH-2.0-OpenSSH_9.6\r\n");
        assert!(domain.is_none());
        drop(client);
    }
}
