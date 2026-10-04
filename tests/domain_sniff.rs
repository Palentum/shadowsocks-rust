#![cfg(all(feature = "local-tunnel", feature = "server"))]

use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{self, Duration},
};

use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType},
    run_local,
    run_server,
};

/// TEST-NET-1, connections to it never complete
const BLACKHOLE_IP: &str = "192.0.2.1";

fn random_local_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// TCP echo server, reports every accepted connection
async fn spawn_echo_server() -> (SocketAddr, mpsc::UnboundedReceiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = tx.send(());
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, rx)
}

/// Starts ssserver with extra `server_options` and `acl` rules, and a sslocal tunnel to `forward_ip:forward_port`.
/// Returns the tunnel port
async fn start(server_options: &str, acl: Option<&str>, forward_ip: &str, forward_port: u16) -> u16 {
    let server_port = random_local_tcp_port();
    let mut server_config = Config::load_from_str(
        &format!(
            r#"{{
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "password",
            "method": "aes-256-gcm",
            {server_options}
        }}"#
        ),
        ConfigType::Server,
    )
    .unwrap();
    if let Some(rules) = acl {
        let path = std::env::temp_dir().join(format!("shadowsocks-domain-sniff-{server_port}.acl"));
        std::fs::write(&path, rules).unwrap();
        server_config.acl = Some(AccessControl::load_from_file(&path).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    let local_port = random_local_tcp_port();
    let local_config = Config::load_from_str(
        &format!(
            r#"{{
            "locals": [
                {{
                    "local_port": {local_port},
                    "local_address": "127.0.0.1",
                    "protocol": "tunnel",
                    "forward_address": "{forward_ip}",
                    "forward_port": {forward_port}
                }}
            ],
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "password",
            "method": "aes-256-gcm"
        }}"#
        ),
        ConfigType::Local,
    )
    .unwrap();

    tokio::spawn(run_server(server_config));
    tokio::spawn(run_local(local_config));
    time::sleep(Duration::from_secs(1)).await;
    local_port
}

/// Sends `data` through the tunnel, returns what comes back until `data.len()` bytes or EOF
async fn round_trip(local_port: u16, data: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
    stream.write_all(data).await.unwrap();

    let mut received = Vec::new();
    let mut reader = stream.take(data.len() as u64);
    // A connection closed by the server may be reset
    let _ = time::timeout(Duration::from_secs(5), reader.read_to_end(&mut received))
        .await
        .expect("round trip timeout");
    received
}

#[tokio::test]
async fn sniff_redirect_to_http_host() {
    let _ = env_logger::try_init();

    let (upstream, _) = spawn_echo_server().await;
    // The requested IP is a black hole, only the sniffed domain name reaches the upstream
    let local_port = start(
        r#""domain_sniff": ["http"], "sniff_redirect": true"#,
        None,
        BLACKHOLE_IP,
        upstream.port(),
    )
    .await;

    let request = format!("GET / HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", upstream.port());
    assert_eq!(round_trip(local_port, request.as_bytes()).await, request.as_bytes());
}

#[tokio::test]
async fn sniffed_domain_blocked_by_acl() {
    let _ = env_logger::try_init();

    let (upstream, mut accepted) = spawn_echo_server().await;
    let acl = "[outbound_block_list]\n||blocked.example\n";
    let local_port = start(r#""domain_sniff": ["http"]"#, Some(acl), "127.0.0.1", upstream.port()).await;

    let blocked = b"GET / HTTP/1.1\r\nHost: www.blocked.example\r\n\r\n";
    assert!(round_trip(local_port, blocked).await.is_empty());

    let allowed = b"GET / HTTP/1.1\r\nHost: www.allowed.example\r\n\r\n";
    assert_eq!(round_trip(local_port, allowed).await, allowed);

    // Only the allowed connection reached the upstream
    assert!(accepted.try_recv().is_ok());
    assert!(accepted.try_recv().is_err());
}

#[tokio::test]
async fn sniff_redirect_target_checked_by_acl() {
    let _ = env_logger::try_init();

    let (upstream, _) = spawn_echo_server().await;
    let acl = "[outbound_block_list]\n|localhost\n";
    let local_port = start(
        r#""domain_sniff": ["tls", "http"], "sniff_redirect": true"#,
        Some(acl),
        "127.0.0.1",
        upstream.port(),
    )
    .await;

    // The requested IP is allowed, but the connection would go to the sniffed domain name
    let request = format!("GET / HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", upstream.port());
    assert!(round_trip(local_port, request.as_bytes()).await.is_empty());

    // Not a domain name, connects to the requested IP
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", upstream.port());
    assert_eq!(round_trip(local_port, request.as_bytes()).await, request.as_bytes());
}
