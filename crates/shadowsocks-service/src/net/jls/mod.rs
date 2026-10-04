//! JLS transport, a TLS 1.3 camouflage without certificates, underneath shadowsocks' TCP stream
//!
//! It is configured with the SIP003 plugin fields as `plugin = "jls"`, but runs in-process.
//! UDP is not affected.
//!
//! Specification: <https://github.com/JimmyHuang454/JLS>

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::{
    io::{self, ErrorKind, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(feature = "jls")]
use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use shadowsocks::{
    ServerConfig,
    context::Context as SsContext,
    net::{ConnectOpts, TcpStream},
    plugin::PluginConfig,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time,
};

#[cfg(feature = "jls")]
pub use self::{
    options::{JlsClientOptions, JlsServerOptions},
    server::{JlsAccepted, JlsAcceptor},
    stream::JlsStream,
};

#[cfg(feature = "jls")]
mod client;
#[cfg(feature = "jls")]
mod options;
#[cfg(feature = "jls")]
mod server;
#[cfg(feature = "jls")]
mod stream;

/// Plugin name that selects the JLS transport
pub const JLS_PLUGIN_NAME: &str = "jls";

/// Client's JLS handshake timeout if the server doesn't have a `timeout` configured
#[cfg(feature = "jls")]
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(feature = "jls")]
static CRYPTO_PROVIDER: LazyLock<Arc<rustls_jls::crypto::CryptoProvider>> =
    LazyLock::new(|| Arc::new(rustls_jls::crypto::aws_lc_rs::default_provider()));

/// Check if `plugin` is the built-in JLS transport instead of a SIP003 plugin process.
///
/// Always `false` without the `jls` feature, then `jls` would be started as an ordinary SIP003 plugin.
pub fn is_jls_plugin(plugin: &PluginConfig) -> bool {
    cfg!(feature = "jls") && plugin.plugin == JLS_PLUGIN_NAME
}

/// Stream to a shadowsocks server, plain or wrapped in JLS
pub enum MaybeJlsStream<S> {
    Plain(S),
    #[cfg(feature = "jls")]
    Jls(Box<JlsStream<S>>),
}

impl<S> MaybeJlsStream<S> {
    /// Get a reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        match self {
            Self::Plain(s) => s,
            #[cfg(feature = "jls")]
            Self::Jls(s) => s.get_ref(),
        }
    }
}

#[cfg(unix)]
impl<S: AsRawFd> AsRawFd for MaybeJlsStream<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().as_raw_fd()
    }
}

#[cfg(windows)]
impl<S: AsRawSocket> AsRawSocket for MaybeJlsStream<S> {
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().as_raw_socket()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeJlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "jls")]
            Self::Jls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeJlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "jls")]
            Self::Jls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "jls")]
            Self::Jls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "jls")]
            Self::Jls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(feature = "jls")]
            Self::Jls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            #[cfg(feature = "jls")]
            Self::Jls(s) => s.is_write_vectored(),
        }
    }
}

/// Wrap `stream` connected to `svr_cfg` in JLS if the server is configured with `plugin = "jls"`
pub async fn connect<S>(svr_cfg: &ServerConfig, stream: S) -> io::Result<MaybeJlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[cfg(feature = "jls")]
    if let Some(plugin) = svr_cfg.plugin()
        && is_jls_plugin(plugin)
    {
        let opts = JlsClientOptions::parse(plugin.plugin_opts.as_deref().unwrap_or_default())?;
        let timeout = svr_cfg.timeout().unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT);
        return match time::timeout(timeout, client::connect(&opts, stream)).await {
            Ok(r) => r.map(|s| MaybeJlsStream::Jls(Box::new(s))),
            Err(..) => Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("jls handshake with {} timeout", svr_cfg.addr()),
            )),
        };
    }

    #[cfg(not(feature = "jls"))]
    let _ = svr_cfg;

    Ok(MaybeJlsStream::Plain(stream))
}

/// Connect to `svr_cfg`'s TCP endpoint directly, the same as `ProxyClientStream::connect_with_opts`,
/// and wrap the stream in JLS if configured
pub async fn connect_server_with_opts(
    context: &SsContext,
    svr_cfg: &ServerConfig,
    opts: &ConnectOpts,
) -> io::Result<MaybeJlsStream<TcpStream>> {
    let dial = TcpStream::connect_server_with_opts(context, svr_cfg.tcp_external_addr(), opts);
    let stream = match svr_cfg.timeout() {
        Some(d) => match time::timeout(d, dial).await {
            Ok(r) => r?,
            Err(..) => {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    format!("connect {} timeout", svr_cfg.addr()),
                ));
            }
        },
        None => dial.await?,
    };
    connect(svr_cfg, stream).await
}

#[cfg(all(test, feature = "jls"))]
mod test {
    use std::time::Duration;

    use shadowsocks::relay::socks5::Address;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    const SERVER_OPTS: &str = "username=jls-user;password=jls-password;dest=127.0.0.1:1;sni=www.example.com";

    fn acceptor() -> JlsAcceptor {
        JlsAcceptor::new(&PluginConfig {
            plugin: JLS_PLUGIN_NAME.to_owned(),
            plugin_opts: Some(SERVER_OPTS.to_owned()),
            plugin_args: Vec::new(),
            plugin_mode: shadowsocks::config::Mode::TcpOnly,
        })
        .unwrap()
    }

    /// Run a client handshake against `acceptor()`, the server side stream is closed on fallback
    async fn client_and_accept(
        client_opts: &str,
    ) -> (
        io::Result<JlsStream<DuplexStream>>,
        io::Result<JlsAccepted<DuplexStream>>,
    ) {
        let opts = JlsClientOptions::parse(client_opts).unwrap();
        let (client, server) = duplex(64 * 1024);
        let acceptor = acceptor();
        let server = async move {
            let r = acceptor.accept(server, Some(Duration::from_secs(5))).await;
            // Unblock a client waiting for the ServerHello
            match r {
                Ok(JlsAccepted::Fallback(s, received)) => {
                    drop(s);
                    Ok(JlsAccepted::Fallback(duplex(1).0, received))
                }
                r => r,
            }
        };
        tokio::join!(client::connect(&opts, client), server)
    }

    #[test]
    fn plain_is_not_jls() {
        let plugin = PluginConfig {
            plugin: "v2ray-plugin".to_owned(),
            plugin_opts: None,
            plugin_args: Vec::new(),
            plugin_mode: shadowsocks::config::Mode::TcpOnly,
        };
        assert!(!is_jls_plugin(&plugin));
        assert_eq!(
            acceptor().dest(),
            &Address::SocketAddress("127.0.0.1:1".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn authed_round_trip() {
        let (client, server) = client_and_accept("host=www.example.com;username=jls-user;password=jls-password").await;
        let mut client = client.unwrap();
        let JlsAccepted::Authed(mut server) = server.unwrap() else {
            panic!("expecting authenticated");
        };
        assert!(client.is_jls_authed());
        assert!(server.is_jls_authed());

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.unwrap();
        server.shutdown().await.unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"pong");
    }

    #[tokio::test]
    async fn wrong_password_falls_back() {
        let (client, server) = client_and_accept("host=www.example.com;username=jls-user;password=wrong").await;
        assert!(client.is_err());
        let JlsAccepted::Fallback(_, received) = server.unwrap() else {
            panic!("expecting fallback");
        };
        // TLS handshake record carrying the ClientHello
        assert_eq!(received[0], 0x16);
        assert_eq!(received[5], 0x01);
        assert_eq!(
            received.len(),
            5 + u16::from_be_bytes([received[3], received[4]]) as usize
        );
    }

    #[tokio::test]
    async fn wrong_sni_falls_back() {
        let (client, server) = client_and_accept("host=www.example.org;username=jls-user;password=jls-password").await;
        assert!(client.is_err());
        assert!(matches!(server.unwrap(), JlsAccepted::Fallback(..)));
    }

    #[tokio::test]
    async fn sni_is_case_sensitive() {
        let (client, server) = client_and_accept("host=WWW.Example.com;username=jls-user;password=jls-password").await;
        assert!(client.is_err());
        assert!(matches!(server.unwrap(), JlsAccepted::Fallback(..)));
    }

    #[tokio::test]
    async fn non_tls_falls_back() {
        const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";

        let (mut client, server) = duplex(1024);
        client.write_all(REQUEST).await.unwrap();
        let JlsAccepted::Fallback(_server, received) = acceptor().accept(server, None).await.unwrap() else {
            panic!("expecting fallback");
        };
        assert_eq!(received, REQUEST);

        // Nothing should be written to the client
        let mut buf = [0u8; 1];
        assert!(
            time::timeout(Duration::from_millis(100), client.read(&mut buf))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn timeout_falls_back() {
        let (mut client, server) = duplex(1024);
        client.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        let accepted = acceptor()
            .accept(server, Some(Duration::from_millis(100)))
            .await
            .unwrap();
        let JlsAccepted::Fallback(_, received) = accepted else {
            panic!("expecting fallback");
        };
        assert_eq!(received, [0x16, 0x03, 0x01]);
    }
}
