//! Shadowsocks TCP server

use std::{
    future::Future,
    io::{self, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use log::{debug, error, info, trace, warn};
use shadowsocks::{
    ProxyListener, ServerConfig,
    crypto::CipherKind,
    net::{AcceptOpts, TcpStream as OutboundTcpStream},
    relay::{socks5::Address, tcprelay::{ProxyServerStream, utils::copy_encrypted_bidirectional}},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream as TokioTcpStream,
    time,
};

#[cfg(feature = "jls")]
use crate::net::jls::{JlsAccepted, JlsAcceptor, is_jls_plugin};
use crate::net::{MonProxyStream, OutboundProxyStream, TcpDialer, jls::MaybeJlsStream, utils::ignore_until_end};

use super::{context::ServiceContext, sniff::sniff_domain};

/// `TcpDialer` adapter that uses the server's connect-options.
struct ServerTcpDialer<'a> {
    context: &'a ServiceContext,
}

impl<'a> TcpDialer for ServerTcpDialer<'a> {
    async fn dial(&self, addr: &Address) -> io::Result<OutboundTcpStream> {
        OutboundTcpStream::connect_remote_with_opts(self.context.context_ref(), addr, self.context.connect_opts_ref())
            .await
    }
}

/// Unified outbound stream: either direct or through the outbound proxy chain.
enum RemoteStream {
    Direct(OutboundTcpStream),
    Proxied(OutboundProxyStream),
}

impl AsyncRead for RemoteStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_read(cx, buf),
            Self::Proxied(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RemoteStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_write(cx, buf),
            Self::Proxied(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_flush(cx),
            Self::Proxied(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_shutdown(cx),
            Self::Proxied(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for RemoteStream {}

/// TCP server instance
pub struct TcpServer {
    context: Arc<ServiceContext>,
    svr_cfg: ServerConfig,
    listener: ProxyListener,
    #[cfg(feature = "jls")]
    jls: Option<Arc<JlsAcceptor>>,
}

impl TcpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        svr_cfg: ServerConfig,
        accept_opts: AcceptOpts,
    ) -> io::Result<Self> {
        #[cfg(feature = "jls")]
        let jls = match svr_cfg.plugin() {
            Some(plugin) if is_jls_plugin(plugin) => Some(Arc::new(JlsAcceptor::new(plugin)?)),
            _ => None,
        };

        let listener = ProxyListener::bind_with_opts(context.context(), &svr_cfg, accept_opts).await?;
        Ok(Self {
            context,
            svr_cfg,
            listener,
            #[cfg(feature = "jls")]
            jls,
        })
    }

    /// Server's configuration
    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    /// Server's listen address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start server's accept loop
    pub async fn run(self) -> io::Result<()> {
        info!(
            "shadowsocks tcp server listening on {}, inbound address {}",
            self.listener.local_addr().expect("listener.local_addr"),
            self.svr_cfg.addr()
        );

        loop {
            #[cfg(feature = "jls")]
            if let Some(ref acceptor) = self.jls {
                // JLS handshake has to be completed before creating the ProxyServerStream
                let (stream, peer_addr) = match self.listener.get_ref().accept().await {
                    Ok(s) => s,
                    Err(err) => {
                        error!("tcp server accept failed with error: {}", err);
                        time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                if self.context.check_client_blocked(&peer_addr) {
                    warn!("access denied from {} by ACL rules", peer_addr);
                    continue;
                }

                tokio::spawn(serve_jls(
                    self.context.clone(),
                    acceptor.clone(),
                    self.svr_cfg.clone(),
                    stream,
                    peer_addr,
                ));
                continue;
            }

            let flow_stat = self.context.flow_stat();

            let (local_stream, peer_addr) = match self
                .listener
                .accept_map(|s| MonProxyStream::from_stream(MaybeJlsStream::Plain(s), flow_stat))
                .await
            {
                Ok(s) => s,
                Err(err) => {
                    error!("tcp server accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if self.context.check_client_blocked(&peer_addr) {
                warn!("access denied from {} by ACL rules", peer_addr);
                continue;
            }

            let client = TcpServerClient {
                context: self.context.clone(),
                method: self.svr_cfg.method(),
                peer_addr,
                stream: local_stream,
                timeout: self.svr_cfg.timeout(),
            };

            tokio::spawn(async move {
                if let Err(err) = client.serve().await {
                    debug!("tcp server stream aborted with error: {}", err);
                }
            });
        }
    }
}

/// Serve a connection of a JLS server, forwarding unauthenticated clients to the camouflage website
#[cfg(feature = "jls")]
async fn serve_jls(
    context: Arc<ServiceContext>,
    acceptor: Arc<JlsAcceptor>,
    svr_cfg: ServerConfig,
    stream: TokioTcpStream,
    peer_addr: SocketAddr,
) {
    match acceptor.accept(stream, svr_cfg.timeout()).await {
        Ok(JlsAccepted::Authed(stream)) => {
            let stream = ProxyServerStream::from_stream_with_user_manager(
                context.context(),
                MonProxyStream::from_stream(MaybeJlsStream::Jls(stream), context.flow_stat()),
                svr_cfg.method(),
                svr_cfg.key(),
                svr_cfg.clone_user_manager(),
            );

            let client = TcpServerClient {
                context,
                method: svr_cfg.method(),
                peer_addr,
                stream,
                timeout: svr_cfg.timeout(),
            };

            if let Err(err) = client.serve().await {
                debug!("tcp server stream aborted with error: {}", err);
            }
        }
        Ok(JlsAccepted::Fallback(stream, received)) => {
            debug!(
                "jls authentication failed, peer: {}, forwarding to {}",
                peer_addr,
                acceptor.dest()
            );

            if let Err(err) = acceptor
                .forward(context.context_ref(), context.connect_opts_ref(), stream, &received)
                .await
            {
                debug!(
                    "jls forwarding {} -> {} aborted with error: {}",
                    peer_addr,
                    acceptor.dest(),
                    err
                );
            }
        }
        Err(err) => debug!("jls handshake failed, peer: {}, {}", peer_addr, err),
    }
}

#[inline]
async fn timeout_fut<F, R>(duration: Option<Duration>, f: F) -> io::Result<R>
where
    F: Future<Output = io::Result<R>>,
{
    match duration {
        None => f.await,
        Some(d) => match time::timeout(d, f).await {
            Ok(o) => o,
            Err(..) => Err(ErrorKind::TimedOut.into()),
        },
    }
}

struct TcpServerClient {
    context: Arc<ServiceContext>,
    method: CipherKind,
    peer_addr: SocketAddr,
    stream: ProxyServerStream<MonProxyStream<MaybeJlsStream<TokioTcpStream>>>,
    timeout: Option<Duration>,
}

impl TcpServerClient {
    async fn serve(mut self) -> io::Result<()> {
        // let target_addr = match Address::read_from(&mut self.stream).await {
        let mut target_addr = match timeout_fut(self.timeout, self.stream.handshake()).await {
            Ok(a) => a,
            // Err(Socks5Error::IoError(ref err)) if err.kind() == ErrorKind::UnexpectedEof => {
            //     debug!(
            //         "handshake failed, received EOF before a complete target Address, peer: {}",
            //         self.peer_addr
            //     );
            //     return Ok(());
            // }
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                debug!(
                    "tcp handshake failed, received EOF before a complete target Address, peer: {}",
                    self.peer_addr
                );
                return Ok(());
            }
            Err(err) if err.kind() == ErrorKind::TimedOut => {
                debug!(
                    "tcp handshake failed, timeout before a complete target Address, peer: {}",
                    self.peer_addr
                );
                return Ok(());
            }
            Err(err) => {
                // https://github.com/shadowsocks/shadowsocks-rust/issues/292
                //
                // Keep connection open. Except AEAD-2022
                warn!("tcp handshake failed. peer: {}, {}", self.peer_addr, err);

                #[cfg(feature = "aead-cipher-2022")]
                if self.method.is_aead_2022() {
                    // Set SO_LINGER(0) for misbehave clients, which will eventually receive RST. (ECONNRESET)
                    // This will also prevent the socket entering TIME_WAIT state.

                    let stream = self.stream.into_inner().into_inner();

                    // tokio's TcpStream.set_linger was marked as deprecated.
                    // But we set linger(0), which won't block the thread when close() the socket.
                    let _ = socket2::SockRef::from(stream.get_ref()).set_linger(Some(Duration::ZERO));

                    return Ok(());
                }

                debug!("tcp silent-drop peer: {}", self.peer_addr);

                // Unwrap and get the plain stream.
                // Otherwise it will keep reporting decryption error before reaching EOF.
                //
                // Note: This will drop all data in the decryption buffer, which is no going back.
                let mut stream = self.stream.into_inner();

                let res = ignore_until_end(&mut stream).await;

                trace!(
                    "tcp silent-drop peer: {} is now closing with result {:?}",
                    self.peer_addr, res
                );

                return Ok(());
            }
        };

        trace!(
            "accepted tcp client connection {}, establishing tunnel to {}",
            self.peer_addr, target_addr
        );

        // Bytes read ahead by sniffing, sent to the target first
        let mut first_packet = None;
        let domain_sniff = self.context.domain_sniff();
        if domain_sniff.is_enabled() && matches!(target_addr, Address::SocketAddress(..)) {
            let (packet, domain) = sniff_domain(&mut self.stream, domain_sniff).await?;
            if let Some(domain) = domain {
                if domain_sniff.redirect {
                    debug!(
                        "tcp client {} sniffed {} for {}, redirecting",
                        self.peer_addr, domain, target_addr
                    );
                    target_addr = Address::DomainNameAddress(domain, target_addr.port());
                } else if self.context.check_outbound_host_blocked(&domain) {
                    // The sniffed domain name is not what we connect to, it can only block
                    error!(
                        "tcp client {} outbound {} (sniffed {}) blocked by ACL rules",
                        self.peer_addr, target_addr, domain
                    );
                    return Ok(());
                }
            }
            first_packet = Some(packet);
        }

        if self.context.check_outbound_blocked(&target_addr).await {
            error!(
                "tcp client {} outbound {} blocked by ACL rules",
                self.peer_addr, target_addr
            );
            return Ok(());
        }

        let mut remote_stream = match timeout_fut(self.timeout, async {
            match self.context.outbound_client() {
                None => OutboundTcpStream::connect_remote_with_opts(
                    self.context.context_ref(),
                    &target_addr,
                    self.context.connect_opts_ref(),
                )
                .await
                .map(RemoteStream::Direct),
                Some(client) => {
                    let dialer = ServerTcpDialer {
                        context: self.context.as_ref(),
                    };
                    client
                        .connect_tcp(&dialer, &target_addr)
                        .await
                        .map(RemoteStream::Proxied)
                }
            }
        })
        .await
        {
            Ok(s) => s,
            Err(err) => {
                error!(
                    "tcp tunnel {} -> {} connect failed, error: {}",
                    self.peer_addr, target_addr, err
                );
                return Err(err);
            }
        };

        // https://github.com/shadowsocks/shadowsocks-rust/issues/232
        //
        // Protocols like FTP, clients will wait for servers to send Welcome Message without sending anything.
        //
        // Wait at most 500ms, and then sends handshake packet to remote servers.
        if let Some(packet) = first_packet {
            // Sniffing has already waited for the first packet
            if !packet.is_empty() {
                timeout_fut(self.timeout, remote_stream.write_all(&packet)).await?;
            } else if self.context.connect_opts_ref().tcp.fastopen {
                timeout_fut(self.timeout, remote_stream.write(&[])).await?;
            }
        } else if self.context.connect_opts_ref().tcp.fastopen {
            let mut buffer = [0u8; 8192];
            match time::timeout(Duration::from_millis(500), self.stream.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    // EOF. Just terminate right here.
                    return Ok(());
                }
                Ok(Ok(n)) => {
                    // Send the first packet.
                    timeout_fut(self.timeout, remote_stream.write_all(&buffer[..n])).await?;
                }
                Ok(Err(err)) => return Err(err),
                Err(..) => {
                    // Timeout. Send handshake to server.
                    timeout_fut(self.timeout, remote_stream.write(&[])).await?;

                    trace!(
                        "tcp tunnel {} -> {} sent TFO connect without data",
                        self.peer_addr, target_addr
                    );
                }
            }
        }

        debug!(
            "established tcp tunnel {} <-> {} with {:?}",
            self.peer_addr,
            target_addr,
            self.context.connect_opts_ref()
        );

        match copy_encrypted_bidirectional(self.method, &mut self.stream, &mut remote_stream).await {
            Ok((rn, wn)) => {
                trace!(
                    "tcp tunnel {} <-> {} closed, L2R {} bytes, R2L {} bytes",
                    self.peer_addr, target_addr, rn, wn
                );
            }
            Err(err) => {
                trace!(
                    "tcp tunnel {} <-> {} closed with error: {}",
                    self.peer_addr, target_addr, err
                );
            }
        }

        Ok(())
    }
}
