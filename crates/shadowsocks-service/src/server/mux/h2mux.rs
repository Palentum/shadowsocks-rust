//! h2mux session of sing-mux, streams are HTTP/2 CONNECT requests

use std::{
    cmp, io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use h2::{
    Reason, RecvStream, SendStream,
    server::{self, Connection},
};
use http::Response;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::MAX_STREAMS;

/// Receive windows, the defaults (64 KiB) are too small for uploading
const STREAM_WINDOW_SIZE: u32 = 1024 * 1024;
const CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024;

fn h2_to_io_error(err: h2::Error) -> io::Error {
    if err.is_io() {
        err.into_io().expect("io error")
    } else {
        io::Error::other(err)
    }
}

/// Server side h2mux session
pub(super) struct Session<T> {
    connection: Connection<T, Bytes>,
}

impl<T> Session<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// HTTP/2 handshake
    pub(super) async fn handshake(io: T) -> io::Result<Self> {
        let connection = server::Builder::new()
            .initial_window_size(STREAM_WINDOW_SIZE)
            .initial_connection_window_size(CONNECTION_WINDOW_SIZE)
            .max_concurrent_streams(MAX_STREAMS as u32)
            .handshake(io)
            .await
            .map_err(h2_to_io_error)?;
        Ok(Self { connection })
    }

    /// Accepts a stream, which has been responded with 200. `None` if the session is closed.
    ///
    /// The whole session is driven by this, so it must be polled continuously. Not cancel safe.
    pub(super) async fn accept(&mut self) -> io::Result<Option<H2Stream>> {
        loop {
            let (request, mut respond) = match self.connection.accept().await {
                Some(r) => r.map_err(h2_to_io_error)?,
                None => return Ok(None),
            };

            // Respond immediately, sing-mux clients cancel streams not responded in 5 seconds.
            // Methods are not checked, the same as sing-mux.
            match respond.send_response(Response::new(()), false) {
                Ok(send) => return Ok(Some(H2Stream::new(send, request.into_body()))),
                Err(err) => debug!("h2mux respond failed, error: {}", err),
            }
        }
    }
}

/// Stream of a h2mux session, request body is read and response body is written
pub(super) struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    buffer: Bytes,
    shutdown: bool,
}

impl H2Stream {
    pub(super) fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            buffer: Bytes::new(),
            shutdown: false,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.buffer.is_empty() {
                let n = cmp::min(this.buffer.len(), buf.remaining());
                buf.put_slice(&this.buffer[..n]);
                this.buffer.advance(n);
                return Poll::Ready(Ok(()));
            }

            match ready!(this.recv.poll_data(cx)) {
                None => return Poll::Ready(Ok(())),
                Some(Ok(data)) => {
                    // Empty data is not EOF, read again
                    let _ = this.recv.flow_control().release_capacity(data.len());
                    this.buffer = data;
                }
                Some(Err(err)) => {
                    return Poll::Ready(match err.reason() {
                        Some(Reason::NO_ERROR) => Ok(()),
                        // Clients cancel streams when they are closed, relays must be aborted instead of half closed
                        Some(..) => Err(io::Error::new(io::ErrorKind::ConnectionReset, err)),
                        None => Err(h2_to_io_error(err)),
                    });
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        this.send.reserve_capacity(buf.len());
        loop {
            match ready!(this.send.poll_capacity(cx)) {
                // Polling again waits for more capacity
                Some(Ok(0)) => {}
                Some(Ok(n)) => {
                    let n = cmp::min(n, buf.len());
                    if this.send.send_data(Bytes::copy_from_slice(&buf[..n]), false).is_err() {
                        break;
                    }
                    return Poll::Ready(Ok(n));
                }
                // Reset or closed
                Some(Err(..)) | None => break,
            }
        }
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Data is flushed by the session
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shutdown {
            this.shutdown = true;
            if this.send.send_data(Bytes::new(), true).is_err() {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use std::{future::poll_fn, time::Duration};

    use h2::client::{self, SendRequest};
    use http::{Method, Request, StatusCode};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
        time,
    };

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// Starts a session, whose streams are served by `handler`
    async fn start<F, Fut>(handler: F) -> SendRequest<Bytes>
    where
        F: Fn(H2Stream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let mut session = Session::handshake(server_io).await.unwrap();
            while let Ok(Some(stream)) = session.accept().await {
                tokio::spawn(handler(stream));
            }
        });

        let (send_request, connection) = client::handshake(client_io).await.unwrap();
        tokio::spawn(connection);
        send_request
    }

    async fn echo(stream: H2Stream) {
        let (mut reader, mut writer) = tokio::io::split(stream);
        if tokio::io::copy(&mut reader, &mut writer).await.is_ok() {
            let _ = writer.shutdown().await;
        }
    }

    /// Opens a stream like sing-mux, a CONNECT request with only `:authority`
    async fn open(send_request: &mut SendRequest<Bytes>) -> (SendStream<Bytes>, RecvStream) {
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("localhost:443")
            .body(())
            .unwrap();
        let (response, send) = send_request.send_request(request, false).unwrap();
        let response = time::timeout(TIMEOUT, response)
            .await
            .expect("response timeout")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        (send, response.into_body())
    }

    async fn send_all(send: &mut SendStream<Bytes>, mut data: Bytes) {
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            let n = poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
            let chunk = data.split_to(cmp::min(n, data.len()));
            send.send_data(chunk, false).unwrap();
        }
    }

    async fn receive_all(recv: &mut RecvStream) -> Vec<u8> {
        let mut received = Vec::new();
        time::timeout(TIMEOUT, async {
            while let Some(data) = recv.data().await {
                let data = data.unwrap();
                let _ = recv.flow_control().release_capacity(data.len());
                received.extend_from_slice(&data);
            }
        })
        .await
        .expect("receive timeout");
        received
    }

    #[tokio::test]
    async fn respond_immediately() {
        let (tx, rx) = oneshot::channel();
        let tx = std::sync::Mutex::new(Some(tx));
        let mut send_request = start(move |stream| {
            // The stream is not touched
            let _ = tx.lock().unwrap().take().unwrap().send(stream);
            async {}
        })
        .await;

        let (_send, _recv) = open(&mut send_request).await;
        let _stream = rx.await.unwrap();
    }

    #[tokio::test]
    async fn transfer() {
        let mut send_request = start(echo).await;
        let (mut send, mut recv) = open(&mut send_request).await;

        // Larger than windows
        let payload: Bytes = (0..5 * 1024 * 1024u32)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>()
            .into();
        let expected = payload.clone();
        let receiver = tokio::spawn(async move { receive_all(&mut recv).await });

        send_all(&mut send, payload).await;
        send.send_data(Bytes::new(), true).unwrap();

        let received = time::timeout(TIMEOUT, receiver).await.unwrap().unwrap();
        assert_eq!(received.len(), expected.len());
        assert!(received == expected);
    }

    #[tokio::test]
    async fn half_close() {
        let mut send_request = start(|mut stream: H2Stream| async move {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"hello");
            // Still writable after EOF
            stream.write_all(b"world").await.unwrap();
            stream.shutdown().await.unwrap();
        })
        .await;

        let (mut send, mut recv) = open(&mut send_request).await;
        send.send_data(Bytes::from_static(b"hello"), true).unwrap();
        assert_eq!(receive_all(&mut recv).await, b"world");
    }

    #[tokio::test]
    async fn reset_is_error() {
        let (tx, rx) = oneshot::channel();
        let tx = std::sync::Mutex::new(Some(tx));
        let mut send_request = start(move |mut stream: H2Stream| {
            let tx = tx.lock().unwrap().take().unwrap();
            async move {
                let mut buf = Vec::new();
                let _ = tx.send(stream.read_to_end(&mut buf).await.map_err(|e| e.kind()));
            }
        })
        .await;

        let (mut send, _recv) = open(&mut send_request).await;
        send.send_data(Bytes::from_static(b"hello"), false).unwrap();
        send.send_reset(Reason::CANCEL);

        let result = time::timeout(TIMEOUT, rx).await.unwrap().unwrap();
        assert_eq!(result, Err(io::ErrorKind::ConnectionReset));
    }

    #[tokio::test]
    async fn concurrent_streams() {
        let send_request = start(echo).await;

        let mut tasks = Vec::new();
        for i in 0..32u8 {
            let mut send_request = send_request.clone();
            tasks.push(tokio::spawn(async move {
                let (mut send, mut recv) = open(&mut send_request).await;
                let payload = Bytes::from(vec![i; 100_000]);
                send_all(&mut send, payload.clone()).await;
                send.send_data(Bytes::new(), true).unwrap();
                assert!(receive_all(&mut recv).await == payload);
            }));
        }
        for task in tasks {
            time::timeout(TIMEOUT, task).await.unwrap().unwrap();
        }
    }
}
