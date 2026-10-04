//! JLS client handshake

use std::{
    io::{self, ErrorKind},
    sync::Arc,
};

use rustls_jls::{
    ClientConfig,
    ClientConnection,
    Connection,
    RootCertStore,
    client::Resumption,
    jls::JlsClientConfig,
    pki_types::ServerName,
    version::TLS13,
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{CRYPTO_PROVIDER, options::JlsClientOptions, stream::JlsStream};

/// Perform a JLS handshake on `stream`, fails if the server doesn't pass JLS authentication
pub async fn connect<S>(opts: &JlsClientOptions, stream: S) -> io::Result<JlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Authenticated servers skip certificate verification,
    // an empty root store makes everything else fail verification.
    let mut config = ClientConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
        .with_protocol_versions(&[&TLS13])
        .map_err(io::Error::other)?
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.jls_config = JlsClientConfig::new(&opts.password, &opts.username);
    config.alpn_protocols = opts.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    config.resumption = Resumption::disabled();

    let server_name = ServerName::try_from(opts.host.clone())
        .map_err(|err| io::Error::new(ErrorKind::InvalidInput, format!("invalid jls host: {err}")))?;
    let conn = ClientConnection::new(Arc::new(config), server_name).map_err(io::Error::other)?;

    let mut stream = JlsStream::new(stream, Connection::Client(conn));
    stream.handshake().await?;

    if !stream.is_jls_authed() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "jls server authentication failed",
        ));
    }
    Ok(stream)
}
