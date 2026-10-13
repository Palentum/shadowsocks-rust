//! sing-mux padding
//!
//! The first 16 frames of both directions are `[length u16][padding length u16][data][padding]`,
//! then data is sent without framing.

use std::{
    cmp, io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Number of padded frames in each direction
const PADDED_FRAMES: usize = 16;
/// Maximum data length of a padded frame
const MAX_DATA_SIZE: usize = u16::MAX as usize;

enum ReadState {
    Header { header: [u8; 4], filled: usize },
    Data { remaining: usize, padding: usize },
    Padding { remaining: usize },
    Raw,
}

/// Stream of a sing-mux session with padding
pub(super) struct PaddingStream<S> {
    inner: S,
    read_state: ReadState,
    read_frames: usize,
    write_frames: usize,
    // Padded frame which is not completely written.
    // Writes of the inner stream are sticky, so it must be written from where it stopped.
    write_buffer: BytesMut,
}

impl<S> PaddingStream<S> {
    /// Wraps `inner`, which is passed through if `enabled` is `false`
    pub(super) fn new(inner: S, enabled: bool) -> Self {
        let (read_state, frames) = if enabled {
            (
                ReadState::Header {
                    header: [0; 4],
                    filled: 0,
                },
                0,
            )
        } else {
            (ReadState::Raw, PADDED_FRAMES)
        };

        Self {
            inner,
            read_state,
            read_frames: frames,
            write_frames: frames,
            write_buffer: BytesMut::new(),
        }
    }
}

impl<S> PaddingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write_buffer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buffer.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write_buffer))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_buffer.advance(n);
        }

        if self.write_frames >= PADDED_FRAMES && self.write_buffer.capacity() > 0 {
            self.write_buffer = BytesMut::new();
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for PaddingStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            match this.read_state {
                ReadState::Raw => return Pin::new(&mut this.inner).poll_read(cx, buf),
                ReadState::Header {
                    ref mut header,
                    ref mut filled,
                } => {
                    let mut header_buf = ReadBuf::new(&mut header[*filled..]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut header_buf))?;
                    let n = header_buf.filled().len();
                    if n == 0 {
                        // EOF is only allowed between frames
                        return if *filled == 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                        };
                    }

                    *filled += n;
                    if *filled == header.len() {
                        this.read_frames += 1;
                        this.read_state = ReadState::Data {
                            remaining: u16::from_be_bytes([header[0], header[1]]) as usize,
                            padding: u16::from_be_bytes([header[2], header[3]]) as usize,
                        };
                    }
                }
                ReadState::Data { remaining: 0, padding } => {
                    this.read_state = ReadState::Padding { remaining: padding };
                }
                ReadState::Data { ref mut remaining, .. } => {
                    let dst = buf.initialize_unfilled_to(cmp::min(*remaining, buf.remaining()));
                    let mut data_buf = ReadBuf::new(dst);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut data_buf))?;
                    let n = data_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }

                    buf.advance(n);
                    *remaining -= n;
                    return Poll::Ready(Ok(()));
                }
                ReadState::Padding { remaining: 0 } => {
                    this.read_state = if this.read_frames >= PADDED_FRAMES {
                        ReadState::Raw
                    } else {
                        ReadState::Header {
                            header: [0; 4],
                            filled: 0,
                        }
                    };
                }
                ReadState::Padding { ref mut remaining } => {
                    let mut scratch = [0u8; 1024];
                    let len = cmp::min(*remaining, scratch.len());
                    let mut padding_buf = ReadBuf::new(&mut scratch[..len]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut padding_buf))?;
                    let n = padding_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *remaining -= n;
                }
            }
        }
    }
}

impl<S> AsyncWrite for PaddingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_write_buffer(cx))?;

        // Empty writes are not framed
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_frames >= PADDED_FRAMES {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let data = &buf[..cmp::min(buf.len(), MAX_DATA_SIZE)];
        let padding = rand::random_range(256..768);
        this.write_buffer.reserve(4 + data.len() + padding);
        this.write_buffer.put_u16(data.len() as u16);
        this.write_buffer.put_u16(padding as u16);
        this.write_buffer.put_slice(data);
        this.write_buffer.put_bytes(0, padding);
        this.write_frames += 1;

        // The frame has been accepted, the rest is written by the next call
        if let Poll::Ready(Err(err)) = this.poll_write_buffer(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_buffer(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_buffer(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod test {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn encode_frame(buf: &mut Vec<u8>, data: &[u8], padding: u16) {
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&padding.to_be_bytes());
        buf.extend_from_slice(data);
        buf.extend(std::iter::repeat_n(0xEE, padding as usize));
    }

    /// Parses padded frames, returns their data and the raw rest
    fn decode_frames(mut buf: &[u8], frames: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut data = Vec::new();
        for _ in 0..frames {
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            let padding = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            assert!((256..768).contains(&padding), "padding length {padding}");
            data.push(buf[4..4 + len].to_vec());
            buf = &buf[4 + len + padding..];
        }
        (data, buf.to_vec())
    }

    /// Returns at most 1 byte per read
    struct BytewiseReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for BytewiseReader {
        fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if self.pos < self.data.len() {
                buf.put_slice(&[self.data[self.pos]]);
                self.pos += 1;
            }
            Poll::Ready(Ok(()))
        }
    }

    /// Commits part of the data on the first call and returns pending, then completes the committed part
    /// regardless of the buffer, like the AEAD writer
    #[derive(Default)]
    struct StickyWriter {
        output: Vec<u8>,
        committed: Option<Vec<u8>>,
    }

    impl AsyncWrite for StickyWriter {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            match self.committed.take() {
                Some(chunk) => {
                    self.output.extend_from_slice(&chunk);
                    Poll::Ready(Ok(chunk.len()))
                }
                None => {
                    let n = cmp::min(buf.len(), 1000);
                    self.committed = Some(buf[..n].to_vec());
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            assert!(self.committed.is_none(), "flushed with a partial write");
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn write_frames() {
        let mut stream = PaddingStream::new(Vec::new(), true);

        // Empty writes are not counted
        assert_eq!(stream.write(&[]).await.unwrap(), 0);

        let chunks: Vec<Vec<u8>> = (0..20).map(|i| format!("chunk {i}").into_bytes()).collect();
        for chunk in &chunks {
            stream.write_all(chunk).await.unwrap();
        }
        stream.flush().await.unwrap();

        let (data, raw) = decode_frames(&stream.inner, PADDED_FRAMES);
        assert_eq!(data, &chunks[..PADDED_FRAMES]);
        assert_eq!(raw, chunks[PADDED_FRAMES..].concat());
    }

    #[tokio::test]
    async fn write_large_frame() {
        let mut stream = PaddingStream::new(Vec::new(), true);

        let payload = vec![0x5A; 70000];
        assert_eq!(stream.write(&payload).await.unwrap(), MAX_DATA_SIZE);
        stream.write_all(&payload[MAX_DATA_SIZE..]).await.unwrap();
        stream.flush().await.unwrap();

        let (data, raw) = decode_frames(&stream.inner, 2);
        assert_eq!(data[0].len(), MAX_DATA_SIZE);
        assert_eq!(data.concat(), payload);
        assert!(raw.is_empty());
    }

    #[tokio::test]
    async fn read_frames() {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for i in 0..PADDED_FRAMES {
            // Empty frames are counted, but they are not EOF
            let data = if i == 3 { Vec::new() } else { vec![i as u8; i + 1] };
            encode_frame(&mut input, &data, 300 + i as u16);
            expected.extend_from_slice(&data);
        }
        // Padding of the 16th frame is skipped, then raw data
        input.extend_from_slice(b"raw data");
        expected.extend_from_slice(b"raw data");

        let mut stream = PaddingStream::new(BytewiseReader { data: input, pos: 0 }, true);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn read_eof() {
        let mut frame = Vec::new();
        encode_frame(&mut frame, b"hello", 300);

        // EOF between frames
        let mut stream = PaddingStream::new(&frame[..], true);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hello");

        // EOF in header, data and padding
        for len in [2, 6, frame.len() - 1] {
            let mut stream = PaddingStream::new(&frame[..len], true);
            let mut output = Vec::new();
            let err = stream.read_to_end(&mut output).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "length {len}");
        }
    }

    #[tokio::test]
    async fn sticky_round_trip() {
        let mut writer = PaddingStream::new(StickyWriter::default(), true);
        let mut expected = Vec::new();
        for i in 0..40usize {
            let chunk = vec![i as u8; (i * 997) % 3000 + 1];
            writer.write_all(&chunk).await.unwrap();
            expected.extend_from_slice(&chunk);
        }
        writer.shutdown().await.unwrap();

        let mut reader = PaddingStream::new(&writer.inner.output[..], true);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn disabled() {
        let mut stream = PaddingStream::new(Vec::new(), false);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(stream.inner, b"hello");

        let mut stream = PaddingStream::new(&b"world"[..], false);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"world");
    }
}
