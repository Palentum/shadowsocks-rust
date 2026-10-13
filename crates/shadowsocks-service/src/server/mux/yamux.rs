//! yamux session of sing-mux, compatible with hashicorp/yamux
//!
//! Frames are `[version u8][type u8][flags u16][stream id u32][length u32]`, followed by data of data frames.
//! Every stream has its own receive window, so reading frames never stops for streams which are not read.

use std::{
    cmp,
    collections::{HashMap, VecDeque},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use log::debug;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, ReadBuf, ReadHalf},
    sync::{Semaphore, mpsc},
};
use tokio_util::sync::PollSemaphore;

use crate::utils::ServerHandle;

use super::{
    MAX_STREAMS,
    frames::{Frame, write_frames},
};

const VERSION: u8 = 0;

const TYPE_DATA: u8 = 0;
const TYPE_WINDOW_UPDATE: u8 = 1;
const TYPE_PING: u8 = 2;
const TYPE_GO_AWAY: u8 = 3;

const FLAG_SYN: u16 = 0x01;
const FLAG_ACK: u16 = 0x02;
const FLAG_FIN: u16 = 0x04;
const FLAG_RST: u16 = 0x08;

const HEADER_SIZE: usize = 12;
/// Receive window of streams, which is the initial window and never increased, same as hashicorp/yamux
const WINDOW_SIZE: u32 = 256 * 1024;
/// Maximum data length of frames sent
const MAX_FRAME_SIZE: usize = 32 * 1024;
/// Data written by streams but not sent
const MAX_SEND_BUFFER: usize = 1024 * 1024;

fn encode_header(ty: u8, flags: u16, stream_id: u32, length: u32) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[0] = VERSION;
    header[1] = ty;
    header[2..4].copy_from_slice(&flags.to_be_bytes());
    header[4..8].copy_from_slice(&stream_id.to_be_bytes());
    header[8..12].copy_from_slice(&length.to_be_bytes());
    header
}

fn protocol_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct StreamState {
    buffer: VecDeque<Bytes>,
    /// Data which the client is allowed to send
    recv_window: u32,
    /// Data read since the last window update
    consumed: u32,
    send_window: u32,
    fin_received: bool,
    /// Reset by the client, or the session is closed
    reset: bool,
    /// Dropped after FIN is sent, data of the client is refused
    dropped: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl StreamState {
    fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            recv_window: WINDOW_SIZE,
            consumed: 0,
            send_window: WINDOW_SIZE,
            fin_received: false,
            reset: false,
            dropped: false,
            read_waker: None,
            write_waker: None,
        }
    }

    fn wake_reader(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }
}

type SharedStreamState = Arc<Mutex<StreamState>>;

struct Shared {
    streams: Mutex<HashMap<u32, SharedStreamState>>,
    // Streams not dropped
    alive: AtomicUsize,
    send_budget: Arc<Semaphore>,
    sender: mpsc::UnboundedSender<Frame>,
}

impl Shared {
    /// Sends a frame without data, for frames of streams
    fn send_frame(&self, ty: u8, flags: u16, stream_id: u32, length: u32) {
        let header = encode_header(ty, flags, stream_id, length);
        let _ = self.sender.send(Frame::new(&header, Bytes::new(), None));
    }

    /// Sends a frame without data in reply to the client, which takes the send budget,
    /// so reading frames stops if the client doesn't read
    async fn reply_frame(&self, ty: u8, flags: u16, stream_id: u32, length: u32) -> io::Result<()> {
        let permit = self
            .send_budget
            .clone()
            .acquire_many_owned(HEADER_SIZE as u32)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let header = encode_header(ty, flags, stream_id, length);
        let _ = self.sender.send(Frame::new(&header, Bytes::new(), Some(permit)));
        Ok(())
    }

    /// Removes the stream if it is still `state`
    fn remove_stream(&self, stream_id: u32, state: &SharedStreamState) {
        let mut streams = self.streams.lock().unwrap();
        if streams.get(&stream_id).is_some_and(|s| Arc::ptr_eq(s, state)) {
            streams.remove(&stream_id);
        }
    }
}

/// Server side yamux session
pub(super) struct Session<T> {
    reader: BufReader<ReadHalf<T>>,
    writer: Option<ServerHandle>,
    shared: Arc<Shared>,
    closed: bool,
}

impl<T> Session<T>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    pub(super) fn new(io: T) -> Self {
        let (reader, writer) = tokio::io::split(io);
        let (sender, receiver) = mpsc::unbounded_channel();

        Self {
            reader: BufReader::new(reader),
            writer: Some(ServerHandle(tokio::spawn(write_frames(writer, receiver)))),
            shared: Arc::new(Shared {
                streams: Mutex::new(HashMap::new()),
                alive: AtomicUsize::new(0),
                send_budget: Arc::new(Semaphore::new(MAX_SEND_BUFFER)),
                sender,
            }),
            closed: false,
        }
    }

    /// Accepts a stream, `None` if the session is closed.
    ///
    /// Not cancel safe.
    pub(super) async fn accept(&mut self) -> io::Result<Option<YamuxStream>> {
        let writer = match self.writer {
            Some(ref mut w) if !self.closed => w,
            _ => return Ok(None),
        };

        let result = tokio::select! {
            r = read_frames(&mut self.reader, &self.shared) => Ok(r),
            r = writer => Err(r),
        };

        let result = match result {
            Ok(r) => r,
            Err(r) => {
                // The writer can't be polled again
                self.writer = None;
                Err(r.err().unwrap_or_else(|| io::ErrorKind::BrokenPipe.into()))
            }
        };

        if !matches!(result, Ok(Some(..))) {
            self.close();
        }
        result
    }
}

impl<T> Session<T> {
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;

        let streams = std::mem::take(&mut *self.shared.streams.lock().unwrap());
        for state in streams.values() {
            let mut state = state.lock().unwrap();
            state.reset = true;
            state.wake_reader();
            state.wake_writer();
        }

        // Wakes writers waiting for the budget
        self.shared.send_budget.close();
    }
}

impl<T> Drop for Session<T> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Reads frames until a new stream is opened
async fn read_frames<R>(reader: &mut R, shared: &Arc<Shared>) -> io::Result<Option<YamuxStream>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_SIZE];
    loop {
        // EOF is only allowed between frames
        if reader.read(&mut header[..1]).await? == 0 {
            return Ok(None);
        }
        reader.read_exact(&mut header[1..]).await?;

        let version = header[0];
        let ty = header[1];
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let stream_id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);

        if version != VERSION {
            return Err(protocol_error(format!("unsupported yamux version {version}")));
        }

        match ty {
            TYPE_DATA | TYPE_WINDOW_UPDATE => {
                let data = if ty == TYPE_DATA && length > 0 {
                    if length > WINDOW_SIZE {
                        return Err(protocol_error(format!("yamux data frame with {length} bytes")));
                    }
                    let mut data = BytesMut::zeroed(length as usize);
                    reader.read_exact(&mut data).await?;
                    Some(data.freeze())
                } else {
                    None
                };

                if let Some(stream) = handle_stream_frame(shared, ty, flags, stream_id, length, data).await? {
                    return Ok(Some(stream));
                }
            }
            TYPE_PING => {
                if flags & FLAG_SYN != 0 {
                    shared.reply_frame(TYPE_PING, FLAG_ACK, 0, length).await?;
                }
            }
            TYPE_GO_AWAY => {
                // No more streams, the client closes the connection after its streams
                debug!("yamux client sent go away, code {}", length);
            }
            _ => return Err(protocol_error(format!("unsupported yamux type {ty}"))),
        }
    }
}

/// Handles a data or window update frame, returns the new stream if it is opened
async fn handle_stream_frame(
    shared: &Arc<Shared>,
    ty: u8,
    flags: u16,
    stream_id: u32,
    length: u32,
    data: Option<Bytes>,
) -> io::Result<Option<YamuxStream>> {
    let mut new_stream = None;
    if flags & FLAG_SYN != 0 {
        let state = {
            let mut streams = shared.streams.lock().unwrap();
            if streams.contains_key(&stream_id) {
                return Err(protocol_error(format!("duplicate yamux stream {stream_id}")));
            }
            if shared.alive.load(Ordering::Relaxed) >= MAX_STREAMS {
                None
            } else {
                let state = Arc::new(Mutex::new(StreamState::new()));
                streams.insert(stream_id, state.clone());
                shared.alive.fetch_add(1, Ordering::Relaxed);
                Some(state)
            }
        };

        let Some(state) = state else {
            shared
                .reply_frame(TYPE_WINDOW_UPDATE, FLAG_ACK | FLAG_RST, stream_id, 0)
                .await?;
            return Ok(None);
        };

        // Acknowledged immediately, hashicorp/yamux closes the session if a stream isn't acknowledged in 5 seconds
        shared.reply_frame(TYPE_WINDOW_UPDATE, FLAG_ACK, stream_id, 0).await?;
        new_stream = Some(YamuxStream {
            stream_id,
            state,
            shared: shared.clone(),
            send_budget: PollSemaphore::new(shared.send_budget.clone()),
            fin_sent: false,
        });
    }

    // Frames of unknown streams are ignored
    let Some(state) = shared.streams.lock().unwrap().get(&stream_id).cloned() else {
        return Ok(new_stream);
    };

    let refused = {
        let mut s = state.lock().unwrap();
        if s.dropped {
            // Waiting for the client's FIN, the stream is closed by FIN, RST or data which won't be read
            data.is_some() || flags & (FLAG_FIN | FLAG_RST) != 0
        } else {
            if ty == TYPE_WINDOW_UPDATE && length > 0 {
                s.send_window = s.send_window.saturating_add(length);
                s.wake_writer();
            }
            if let Some(data) = data {
                if length > s.recv_window {
                    return Err(protocol_error(format!(
                        "yamux stream {stream_id} received {length} bytes, exceeding window {}",
                        s.recv_window
                    )));
                }
                s.recv_window -= length;
                s.buffer.push_back(data);
                s.wake_reader();
            }
            if flags & FLAG_FIN != 0 {
                s.fin_received = true;
                s.wake_reader();
            }
            if flags & FLAG_RST != 0 {
                s.reset = true;
                s.wake_reader();
                s.wake_writer();
            }
            false
        }
    };

    if refused {
        shared.remove_stream(stream_id, &state);
        if flags & (FLAG_FIN | FLAG_RST) == 0 {
            shared.reply_frame(TYPE_WINDOW_UPDATE, FLAG_RST, stream_id, 0).await?;
        }
    } else if flags & FLAG_RST != 0 {
        shared.remove_stream(stream_id, &state);
    }

    Ok(new_stream)
}

/// Stream of a yamux session
pub(super) struct YamuxStream {
    stream_id: u32,
    state: SharedStreamState,
    shared: Arc<Shared>,
    send_budget: PollSemaphore,
    fin_sent: bool,
}

impl AsyncRead for YamuxStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.state.lock().unwrap();

        let mut n = 0;
        while buf.remaining() > 0 {
            let Some(data) = state.buffer.front_mut() else {
                break;
            };
            let len = cmp::min(data.len(), buf.remaining());
            buf.put_slice(&data[..len]);
            data.advance(len);
            if data.is_empty() {
                state.buffer.pop_front();
            }
            n += len;
        }

        if n > 0 {
            // Window update after half of the window is read, same as hashicorp/yamux
            state.consumed += n as u32;
            let mut delta = 0;
            if state.consumed >= WINDOW_SIZE / 2 && !state.fin_received && !state.reset {
                delta = state.consumed;
                state.consumed = 0;
                state.recv_window += delta;
            }
            drop(state);

            if delta > 0 {
                this.shared.send_frame(TYPE_WINDOW_UPDATE, 0, this.stream_id, delta);
            }
            return Poll::Ready(Ok(()));
        }

        if state.fin_received {
            return Poll::Ready(Ok(()));
        }
        if state.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }

        match state.read_waker {
            Some(ref waker) if waker.will_wake(cx.waker()) => {}
            _ => state.read_waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl AsyncWrite for YamuxStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fin_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let len = {
            let mut state = this.state.lock().unwrap();
            if state.reset {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if state.send_window == 0 {
                match state.write_waker {
                    Some(ref waker) if waker.will_wake(cx.waker()) => {}
                    _ => state.write_waker = Some(cx.waker().clone()),
                }
                return Poll::Pending;
            }
            cmp::min(cmp::min(buf.len(), MAX_FRAME_SIZE), state.send_window as usize)
        };

        let Some(permit) = ready!(this.send_budget.poll_acquire_many(cx, len as u32)) else {
            // Session closed
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };

        {
            // Only increased by others, so it's still enough
            let mut state = this.state.lock().unwrap();
            if state.reset {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            state.send_window -= len as u32;
        }

        let header = encode_header(TYPE_DATA, 0, this.stream_id, len as u32);
        let frame = Frame::new(&header, Bytes::copy_from_slice(&buf[..len]), Some(permit));
        if this.shared.sender.send(frame).is_err() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Frames are flushed by the session
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.fin_sent {
            this.fin_sent = true;
            this.shared.send_frame(TYPE_WINDOW_UPDATE, FLAG_FIN, this.stream_id, 0);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for YamuxStream {
    fn drop(&mut self) {
        self.shared.alive.fetch_sub(1, Ordering::Relaxed);

        let (remove, reset) = {
            let mut state = self.state.lock().unwrap();
            state.buffer.clear();
            if state.reset {
                (true, false)
            } else if !self.fin_sent {
                // Not closed gracefully
                (true, true)
            } else if state.fin_received {
                (true, false)
            } else {
                // The client may still read data and FIN, it's reset if it keeps sending
                state.dropped = true;
                (false, false)
            }
        };

        if remove {
            self.shared.remove_stream(self.stream_id, &self.state);
        }
        if reset {
            self.shared.send_frame(TYPE_WINDOW_UPDATE, FLAG_RST, self.stream_id, 0);
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        time,
    };

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn frame(ty: u8, flags: u16, stream_id: u32, length: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = encode_header(ty, flags, stream_id, length).to_vec();
        buf.extend_from_slice(data);
        buf
    }

    fn data_frame(flags: u16, stream_id: u32, data: &[u8]) -> Vec<u8> {
        frame(TYPE_DATA, flags, stream_id, data.len() as u32, data)
    }

    /// Reads a frame, returns its type, flags, stream ID, length and data
    async fn read_frame(client: &mut DuplexStream) -> (u8, u16, u32, u32, Vec<u8>) {
        time::timeout(TIMEOUT, async {
            let mut header = [0u8; HEADER_SIZE];
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], VERSION);
            let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
            let mut data = Vec::new();
            if header[1] == TYPE_DATA {
                data.resize(length as usize, 0);
                client.read_exact(&mut data).await.unwrap();
            }
            (
                header[1],
                u16::from_be_bytes([header[2], header[3]]),
                u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                length,
                data,
            )
        })
        .await
        .expect("read frame timeout")
    }

    async fn accept<T>(session: &mut Session<T>) -> YamuxStream
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        time::timeout(TIMEOUT, session.accept())
            .await
            .expect("accept timeout")
            .unwrap()
            .expect("stream")
    }

    /// Keeps reading frames of the session, accepted streams are kept open
    fn drive<T>(mut session: Session<T>) -> tokio::task::JoinHandle<Vec<YamuxStream>>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        tokio::spawn(async move {
            let mut streams = Vec::new();
            while let Ok(Some(stream)) = session.accept().await {
                streams.push(stream);
            }
            streams
        })
    }

    fn assert_send<T: Send + Unpin + 'static>(_: &T) {}

    #[tokio::test]
    async fn ack_immediately() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        // hashicorp/yamux opens a stream with a window update with SYN
        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, FLAG_SYN, 1, 0, &[]))
            .await
            .unwrap();
        let stream = accept(&mut session).await;
        assert_send(&stream);

        // Not touched by the stream
        assert_eq!(
            read_frame(&mut client).await,
            (TYPE_WINDOW_UPDATE, FLAG_ACK, 1, 0, Vec::new())
        );
    }

    #[tokio::test]
    async fn round_trip_and_half_close() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        let mut data = data_frame(FLAG_SYN, 1, b"hello");
        data.extend(data_frame(0, 1, b""));
        data.extend(frame(TYPE_WINDOW_UPDATE, FLAG_FIN, 1, 0, &[]));
        client.write_all(&data).await.unwrap();

        let mut stream = accept(&mut session).await;
        let _driver = drive(session);
        assert_eq!(read_frame(&mut client).await.1, FLAG_ACK);

        // FIN of the client is EOF
        let mut buf = Vec::new();
        time::timeout(TIMEOUT, stream.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, b"hello");

        // Still writable after the client's FIN
        stream.write_all(b"world").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(read_frame(&mut client).await, (TYPE_DATA, 0, 1, 5, b"world".to_vec()));
        assert_eq!(
            read_frame(&mut client).await,
            (TYPE_WINDOW_UPDATE, FLAG_FIN, 1, 0, Vec::new())
        );

        // Closed by both, no RST
        drop(stream);
        client.write_all(&frame(TYPE_PING, FLAG_SYN, 0, 7, &[])).await.unwrap();
        assert_eq!(read_frame(&mut client).await, (TYPE_PING, FLAG_ACK, 0, 7, Vec::new()));
    }

    #[tokio::test]
    async fn no_head_of_line_blocking() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let mut session = Session::new(server);

        // Stream 1 is never read, like a relay blocked by a slow remote
        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, FLAG_SYN, 1, 0, &[]))
            .await
            .unwrap();
        let _stalled = accept(&mut session).await;
        let _driver = drive(session);
        assert_eq!(read_frame(&mut client).await.1, FLAG_ACK);

        // The whole window, in small frames
        for _ in 0..64 {
            client.write_all(&data_frame(0, 1, &[0u8; 4096])).await.unwrap();
        }

        // Other streams and pings are still served
        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, FLAG_SYN, 3, 0, &[]))
            .await
            .unwrap();
        client.write_all(&frame(TYPE_PING, FLAG_SYN, 0, 42, &[])).await.unwrap();
        assert_eq!(
            read_frame(&mut client).await,
            (TYPE_WINDOW_UPDATE, FLAG_ACK, 3, 0, Vec::new())
        );
        assert_eq!(read_frame(&mut client).await, (TYPE_PING, FLAG_ACK, 0, 42, Vec::new()));
    }

    #[tokio::test]
    async fn receive_window() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let mut session = Session::new(server);

        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, FLAG_SYN, 1, 0, &[]))
            .await
            .unwrap();
        let mut stream = accept(&mut session).await;
        let _driver = drive(session);
        assert_eq!(read_frame(&mut client).await.1, FLAG_ACK);

        // Window is updated after half of it is read
        client
            .write_all(&data_frame(0, 1, &vec![0x11; WINDOW_SIZE as usize / 2]))
            .await
            .unwrap();
        let mut buf = vec![0u8; WINDOW_SIZE as usize / 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            read_frame(&mut client).await,
            (TYPE_WINDOW_UPDATE, 0, 1, WINDOW_SIZE / 2, Vec::new())
        );
    }

    #[tokio::test]
    async fn receive_window_exceeded() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let mut session = Session::new(server);

        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, FLAG_SYN, 1, 0, &[]))
            .await
            .unwrap();
        let _stream = accept(&mut session).await;

        let chunk = vec![0u8; WINDOW_SIZE as usize / 2];
        for _ in 0..3 {
            client.write_all(&data_frame(0, 1, &chunk)).await.unwrap();
        }
        let err = time::timeout(TIMEOUT, session.accept()).await.unwrap().err();
        assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn send_window() {
        let (mut client, server) = tokio::io::duplex(4 * 1024 * 1024);
        let mut session = Session::new(server);

        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, FLAG_SYN, 1, 0, &[]))
            .await
            .unwrap();
        let mut stream = accept(&mut session).await;
        let _driver = drive(session);
        assert_eq!(read_frame(&mut client).await.1, FLAG_ACK);

        let payload = vec![0x22; WINDOW_SIZE as usize + 1000];
        let writer = tokio::spawn(async move {
            stream.write_all(&payload).await.unwrap();
            stream
        });

        // Only the window is sent before the window update
        let mut received = 0;
        while received < WINDOW_SIZE as usize {
            let (ty, _, _, _, data) = read_frame(&mut client).await;
            assert_eq!(ty, TYPE_DATA);
            assert!(data.len() <= MAX_FRAME_SIZE);
            received += data.len();
        }
        assert_eq!(received, WINDOW_SIZE as usize);
        time::sleep(Duration::from_millis(100)).await;
        assert!(!writer.is_finished());

        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, 0, 1, 1000, &[]))
            .await
            .unwrap();
        let (_, _, _, _, data) = read_frame(&mut client).await;
        assert_eq!(data.len(), 1000);
        time::timeout(TIMEOUT, writer).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reset_by_client() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        let mut data = data_frame(FLAG_SYN, 1, b"hello");
        data.extend(frame(TYPE_WINDOW_UPDATE, FLAG_RST, 1, 0, &[]));
        client.write_all(&data).await.unwrap();

        let mut stream = accept(&mut session).await;
        let _driver = drive(session);

        let mut buf = Vec::new();
        let err = time::timeout(TIMEOUT, stream.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(buf, b"hello");
        assert_eq!(
            stream.write_all(b"data").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn reset_on_drop() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        let mut data = data_frame(FLAG_SYN, 1, b"a");
        data.extend(data_frame(FLAG_SYN, 3, b"b"));
        client.write_all(&data).await.unwrap();
        let stream1 = accept(&mut session).await;
        let mut stream3 = accept(&mut session).await;
        let _driver = drive(session);
        assert_eq!(read_frame(&mut client).await.2, 1);
        assert_eq!(read_frame(&mut client).await.2, 3);

        // Dropped without FIN, like a failed relay
        drop(stream1);
        assert_eq!(
            read_frame(&mut client).await,
            (TYPE_WINDOW_UPDATE, FLAG_RST, 1, 0, Vec::new())
        );

        // Dropped after FIN, the client can still read and close
        stream3.write_all(b"bye").await.unwrap();
        stream3.shutdown().await.unwrap();
        drop(stream3);
        assert_eq!(read_frame(&mut client).await.4, b"bye");
        assert_eq!(read_frame(&mut client).await.1, FLAG_FIN);

        // But it's reset if the client keeps sending
        client.write_all(&data_frame(0, 3, b"more")).await.unwrap();
        assert_eq!(
            read_frame(&mut client).await,
            (TYPE_WINDOW_UPDATE, FLAG_RST, 3, 0, Vec::new())
        );
    }

    #[tokio::test]
    async fn stream_limit() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let session = Session::new(server);
        let driver = drive(session);

        let mut data = Vec::new();
        for i in 0..=MAX_STREAMS as u32 {
            data.extend(frame(TYPE_WINDOW_UPDATE, FLAG_SYN, i * 2 + 1, 0, &[]));
        }
        client.write_all(&data).await.unwrap();

        for i in 0..MAX_STREAMS as u32 {
            assert_eq!(
                read_frame(&mut client).await,
                (TYPE_WINDOW_UPDATE, FLAG_ACK, i * 2 + 1, 0, Vec::new())
            );
        }
        let rejected = MAX_STREAMS as u32 * 2 + 1;
        assert_eq!(
            read_frame(&mut client).await,
            (TYPE_WINDOW_UPDATE, FLAG_ACK | FLAG_RST, rejected, 0, Vec::new())
        );

        drop(client);
        assert_eq!(
            time::timeout(TIMEOUT, driver).await.unwrap().unwrap().len(),
            MAX_STREAMS
        );
    }

    #[tokio::test]
    async fn session_closed() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        client
            .write_all(&frame(TYPE_WINDOW_UPDATE, FLAG_SYN, 1, 0, &[]))
            .await
            .unwrap();
        let mut stream = accept(&mut session).await;
        let driver = drive(session);

        drop(client);
        time::timeout(TIMEOUT, driver).await.unwrap().unwrap();

        // Not EOF, relays must be aborted
        let mut buf = Vec::new();
        let err = stream.read_to_end(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(
            stream.write_all(b"data").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
