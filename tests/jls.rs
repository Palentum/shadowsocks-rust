#![cfg(all(feature = "jls", feature = "local-tunnel", feature = "server"))]

use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{self, Duration},
};

use shadowsocks_service::{
    config::{Config, ConfigType},
    run_local,
    run_server,
};

const JLS_SERVER_OPTS: &str = "username=jls-user;password=jls-password;sni=www.example.com";
const JLS_CLIENT_OPTS: &str = "host=www.example.com;username=jls-user;password=jls-password";
const UPSTREAM_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nUPSTREAM";

fn random_local_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// TCP echo server, keeps echoing until the client shuts down its write half
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

/// Fake camouflage website, reports the first bytes it received and responds with `UPSTREAM_RESPONSE`
async fn spawn_fake_upstream() -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec());
                let _ = stream.write_all(UPSTREAM_RESPONSE).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, rx)
}

/// Starts a JLS ssserver, returns its port
async fn start_server(method: &str, password: &str, upstream: SocketAddr) -> u16 {
    let server_port = random_local_tcp_port();
    let server_config = Config::load_from_str(
        &format!(
            r#"{{
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "{password}",
            "method": "{method}",
            "plugin": "jls",
            "plugin_opts": "{JLS_SERVER_OPTS};dest={upstream}"
        }}"#
        ),
        ConfigType::Server,
    )
    .unwrap();
    tokio::spawn(run_server(server_config));
    server_port
}

/// Starts a sslocal tunnel to `forward` through the JLS ssserver at `server_port`, returns the tunnel port
async fn start_local(method: &str, password: &str, server_port: u16, jls_opts: &str, forward: SocketAddr) -> u16 {
    let local_port = random_local_tcp_port();
    let local_config = Config::load_from_str(
        &format!(
            r#"{{
            "locals": [
                {{
                    "local_port": {local_port},
                    "local_address": "127.0.0.1",
                    "protocol": "tunnel",
                    "forward_address": "{}",
                    "forward_port": {}
                }}
            ],
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "{password}",
            "method": "{method}",
            "plugin": "jls",
            "plugin_opts": "{jls_opts}"
        }}"#,
            forward.ip(),
            forward.port()
        ),
        ConfigType::Local,
    )
    .unwrap();
    tokio::spawn(run_local(local_config));
    local_port
}

/// Sends `len` bytes through the tunnel and expects them echoed back before closing,
/// like an interactive protocol, so nothing can rely on the flush at EOF
async fn echo_round_trip(local_port: u16, len: usize) {
    let stream = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
    let (mut r, mut w) = stream.into_split();

    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&data).await.unwrap();
        w
    });

    let mut received = vec![0u8; len];
    time::timeout(Duration::from_secs(30), r.read_exact(&mut received))
        .await
        .expect("echo timeout")
        .unwrap();
    assert!(received == expected, "echoed data mismatched");

    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();
    let mut rest = Vec::new();
    r.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

async fn jls_tunnel(method: &str, password: &str) {
    let _ = env_logger::try_init();

    let echo = spawn_echo_server().await;
    let (upstream, mut upstream_rx) = spawn_fake_upstream().await;
    let server_port = start_server(method, password, upstream).await;
    let local_port = start_local(method, password, server_port, JLS_CLIENT_OPTS, echo).await;
    time::sleep(Duration::from_secs(1)).await;

    // Large enough to fill the socket buffers, which leaves TLS records buffered in rustls
    echo_round_trip(local_port, 8 * 1024 * 1024).await;
    // A second connection on the same server
    echo_round_trip(local_port, 1024).await;

    assert!(
        upstream_rx.try_recv().is_err(),
        "authenticated clients must not be forwarded"
    );
}

#[tokio::test]
async fn jls_tunnel_aead() {
    jls_tunnel("aes-256-gcm", "password").await;
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn jls_tunnel_aead2022() {
    jls_tunnel(
        "2022-blake3-aes-256-gcm",
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    )
    .await;
}

#[tokio::test]
async fn jls_probe_fallback() {
    let _ = env_logger::try_init();

    let (upstream, mut upstream_rx) = spawn_fake_upstream().await;
    let server_port = start_server("aes-256-gcm", "password", upstream).await;
    time::sleep(Duration::from_secs(1)).await;

    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";

    let mut stream = TcpStream::connect(("127.0.0.1", server_port)).await.unwrap();
    stream.write_all(REQUEST).await.unwrap();

    let mut response = Vec::new();
    time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("probe timeout")
        .unwrap();

    assert_eq!(response, UPSTREAM_RESPONSE);
    assert_eq!(upstream_rx.recv().await.unwrap(), REQUEST);
}

#[tokio::test]
async fn jls_wrong_password_fallback() {
    let _ = env_logger::try_init();

    let echo = spawn_echo_server().await;
    let (upstream, mut upstream_rx) = spawn_fake_upstream().await;
    let server_port = start_server("aes-256-gcm", "password", upstream).await;
    let local_port = start_local(
        "aes-256-gcm",
        "password",
        server_port,
        "host=www.example.com;username=jls-user;password=wrong-password",
        echo,
    )
    .await;
    time::sleep(Duration::from_secs(1)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
    stream.write_all(b"hello").await.unwrap();

    // The tunnel can't be established
    let mut buf = Vec::new();
    let _ = time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .expect("tunnel should be closed");
    assert!(buf.is_empty());

    // The ClientHello was forwarded to the camouflage website
    let received = time::timeout(Duration::from_secs(10), upstream_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.first(), Some(&0x16));
}
