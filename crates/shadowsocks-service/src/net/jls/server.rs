//! JLS server handshake and fallback forwarding

use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use log::trace;
use rustls_jls::{
    Connection,
    ServerConfig,
    ServerConnection,
    jls::{JlsServerConfig, JlsState},
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    version::TLS13,
};
use shadowsocks::{
    context::Context,
    net::{ConnectOpts, TcpStream as OutboundTcpStream},
    plugin::PluginConfig,
    relay::socks5::Address,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    time::{self, Instant},
};

use super::{CRYPTO_PROVIDER, options::JlsServerOptions, stream::JlsStream};

/// Maximum bytes buffered before the JLS authentication decision.
/// A ClientHello larger than this is not from our clients.
const MAX_CLIENT_HELLO_SIZE: usize = 64 * 1024;

/// Result of [`JlsAcceptor::accept`]
pub enum JlsAccepted<S> {
    /// Client passed JLS authentication, handshake completed
    Authed(Box<JlsStream<S>>),
    /// Client failed JLS authentication, nothing has been written to the stream.
    /// Holds all the bytes received from the client, which should be forwarded with [`JlsAcceptor::forward`].
    Fallback(S, Vec<u8>),
}

/// JLS server side acceptor
pub struct JlsAcceptor {
    config: Arc<ServerConfig>,
    dest: Address,
}

impl JlsAcceptor {
    /// Create an acceptor from `plugin = "jls"` configuration
    pub fn new(plugin: &PluginConfig) -> io::Result<Self> {
        let opts = JlsServerOptions::parse(plugin.plugin_opts.as_deref().unwrap_or_default())?;
        Self::with_options(opts)
    }

    pub(super) fn with_options(opts: JlsServerOptions) -> io::Result<Self> {
        // Certificate is only visible to authenticated clients, which don't verify it.
        let cert_name = match (&opts.sni, &opts.dest) {
            (Some(sni), _) => sni.clone(),
            (None, Address::DomainNameAddress(host, _)) => host.clone(),
            (None, Address::SocketAddress(addr)) => addr.ip().to_string(),
        };
        let certified = rcgen::generate_simple_self_signed(vec![cert_name]).map_err(io::Error::other)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));

        let mut config = ServerConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
            .with_protocol_versions(&[&TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .map_err(io::Error::other)?;
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        config.jls_config = Arc::new(JlsServerConfig::new(
            opts.password,
            opts.username,
            Some(opts.dest.to_string()),
            opts.sni,
        ));

        Ok(Self {
            config: Arc::new(config),
            dest: opts.dest,
        })
    }

    /// Camouflage website that unauthenticated connections are forwarded to
    pub fn dest(&self) -> &Address {
        &self.dest
    }

    /// Accept a JLS connection on `stream`
    ///
    /// Anything that fails authentication before the server's first flight, including a `timeout`,
    /// becomes [`JlsAccepted::Fallback`]. Errors after authentication are returned as `Err`.
    pub async fn accept<S>(&self, mut stream: S, timeout: Option<Duration>) -> io::Result<JlsAccepted<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut conn = ServerConnection::new(self.config.clone()).map_err(io::Error::other)?;
        let mut received = Vec::new();

        loop {
            let start = received.len();
            received.reserve(4096);

            let n = match deadline {
                Some(deadline) => match time::timeout_at(deadline, stream.read_buf(&mut received)).await {
                    Ok(r) => r?,
                    Err(..) => {
                        trace!("jls fallback, timeout before authentication");
                        return Ok(JlsAccepted::Fallback(stream, received));
                    }
                },
                None => stream.read_buf(&mut received).await?,
            };

            if n == 0 {
                trace!("jls fallback, eof before authentication");
                return Ok(JlsAccepted::Fallback(stream, received));
            }
            if received.len() > MAX_CLIENT_HELLO_SIZE || !feed(&mut conn, &received[start..]) {
                trace!("jls fallback, not an acceptable tls client hello");
                return Ok(JlsAccepted::Fallback(stream, received));
            }

            match conn.jls_state() {
                JlsState::AuthSuccess(..) => break,
                JlsState::NotAuthed => continue,
                state => {
                    trace!("jls fallback, {state:?}");
                    return Ok(JlsAccepted::Fallback(stream, received));
                }
            }
        }

        // ServerHello will be sent from now on, no way to fall back
        let mut stream = JlsStream::new(stream, Connection::Server(conn));
        match deadline {
            Some(deadline) => match time::timeout_at(deadline, stream.handshake()).await {
                Ok(r) => r?,
                Err(..) => return Err(io::Error::new(ErrorKind::TimedOut, "jls handshake timeout")),
            },
            None => stream.handshake().await?,
        }

        Ok(JlsAccepted::Authed(Box::new(stream)))
    }

    /// Forward a connection failed authentication to `dest`, starting with the bytes already `received`
    pub async fn forward<S>(
        &self,
        context: &Context,
        opts: &ConnectOpts,
        mut stream: S,
        received: &[u8],
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut upstream = OutboundTcpStream::connect_remote_with_opts(context, &self.dest, opts).await?;
        upstream.write_all(received).await?;
        copy_bidirectional(&mut stream, &mut upstream).await?;
        Ok(())
    }
}

/// Feed `data` to `conn`, returns `false` if it is not an acceptable TLS stream.
///
/// Never send anything back on failures, errors' alerts would reveal the server.
fn feed(conn: &mut ServerConnection, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        match conn.read_tls(&mut data) {
            Ok(0) | Err(..) => return false,
            Ok(..) => {}
        }
        if conn.process_new_packets().is_err() {
            return false;
        }
    }
    true
}
