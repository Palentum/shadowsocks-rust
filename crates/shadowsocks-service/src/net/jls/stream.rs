//! Asynchronous I/O adapter for a `rustls_jls` connection
//!
//! Ported from tokio-rustls 0.26 (`src/common/mod.rs`, `src/common/handshake.rs`, MIT / Apache-2.0),
//! trimmed down to what JLS needs: no early data, no vectored writes.

use std::{
    future::poll_fn,
    io::{self, BufRead, ErrorKind, Read, Write},
    pin::Pin,
    task::{Context, Poll, ready},
};

use rustls_jls::{Connection, jls::JlsState};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TLS stream over `IO`, driven by a JLS-enabled client or server connection
pub struct JlsStream<IO> {
    io: IO,
    conn: Connection,
    /// `io` reached EOF
    eof: bool,
    /// The TLS session has been closed for reading
    read_closed: bool,
    /// `close_notify` has been queued
    write_closed: bool,
    /// Handshake data has been written to `io` without a flush
    need_flush: bool,
}

impl<IO> JlsStream<IO> {
    pub(super) fn new(io: IO, conn: Connection) -> Self {
        Self {
            io,
            conn,
            eof: false,
            read_closed: false,
            write_closed: false,
            need_flush: false,
        }
    }

    /// Get a reference to the underlying I/O object
    pub fn get_ref(&self) -> &IO {
        &self.io
    }

    /// Check if the peer has passed JLS authentication
    pub fn is_jls_authed(&self) -> bool {
        matches!(self.conn.jls_authed, JlsState::AuthSuccess(..))
    }
}

impl<IO> JlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Drive the TLS handshake to completion
    pub async fn handshake(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_handshake(cx)).await
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.is_handshaking() {
            ready!(self.handshake_step(cx))?;
        }
        // Flush the last flight, otherwise protocols that wait for the peer to speak first would deadlock
        self.poll_flush_tls(cx)
    }

    fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter { io: &mut self.io, cx };

        let n = match self.conn.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };

        if let Err(err) = self.conn.process_new_packets() {
            // Last-gasp attempt to send the alert describing this error
            let _ = self.write_io(cx);
            return Poll::Ready(Err(io::Error::new(ErrorKind::InvalidData, err)));
        }

        Poll::Ready(Ok(n))
    }

    fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter { io: &mut self.io, cx };

        match self.conn.write_tls(&mut writer) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    /// Makes progress on the handshake, returns `Ready` if any bytes have been transferred
    fn handshake_step(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut progress = false;

        loop {
            let mut would_block = false;

            while self.conn.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(..)) => {
                        progress = true;
                        self.need_flush = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        would_block = true;
                        break;
                    }
                }
            }

            if self.need_flush {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => self.need_flush = false,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => would_block = true,
                }
            }

            while !self.eof && self.conn.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(..)) => progress = true,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        would_block = true;
                        break;
                    }
                }
            }

            return match (self.eof, self.conn.is_handshaking()) {
                (true, true) => Poll::Ready(Err(io::Error::new(ErrorKind::UnexpectedEof, "tls handshake eof"))),
                (_, false) => Poll::Ready(Ok(())),
                (_, true) if would_block => {
                    if progress {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }
                (..) => continue,
            };
        }
    }

    fn poll_flush_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.conn.writer().flush()?;
        while self.conn.wants_write() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(ErrorKind::WriteZero.into()));
            }
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }
}

impl<IO> AsyncRead for JlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.read_closed || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut io_pending = false;
        while !this.eof && this.conn.wants_read() {
            match this.read_io(cx) {
                Poll::Ready(Ok(0)) => {
                    this.eof = true;
                    break;
                }
                Poll::Ready(Ok(..)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
            }
        }

        let n = match this.conn.reader().into_first_chunk() {
            Ok(data) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                n
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if !io_pending {
                    // rustls wants more data but `io` didn't register a wakeup, try again
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            // Peer closed the TCP connection without `close_notify`.
            // Treat it as EOF like a plain TCP stream, integrity is guarded by the shadowsocks AEAD layer.
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => 0,
            Err(err) => return Poll::Ready(Err(err)),
        };

        if n == 0 {
            this.read_closed = true;
        } else {
            this.conn.reader().consume(n);
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncWrite for JlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut pos = 0;

        while pos != buf.len() {
            let mut would_block = false;

            pos += this.conn.writer().write(&buf[pos..])?;

            while this.conn.wants_write() {
                match this.write_io(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(..)) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            // Data accepted by rustls but not yet sent to `io` will be sent by the following writes or `poll_flush`
            if would_block {
                return if pos == 0 { Poll::Pending } else { Poll::Ready(Ok(pos)) };
            }
        }

        Poll::Ready(Ok(pos))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_tls(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.write_closed {
            this.conn.send_close_notify();
            this.write_closed = true;
        }

        while this.conn.wants_write() {
            if ready!(this.write_io(cx))? == 0 {
                return Poll::Ready(Err(ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(match ready!(Pin::new(&mut this.io).poll_shutdown(cx)) {
            // Not being connected is fine when shutting down
            Err(err) if err.kind() == ErrorKind::NotConnected => Ok(()),
            result => result,
        })
    }
}

/// [`Read`] adapter for an [`AsyncRead`], turns `Poll::Pending` into `WouldBlock`
struct SyncReadAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}

/// [`Write`] adapter for an [`AsyncWrite`], turns `Poll::Pending` into `WouldBlock`
struct SyncWriteAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}
