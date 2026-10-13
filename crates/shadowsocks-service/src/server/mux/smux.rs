//! smux (v1) session of sing-mux, compatible with xtaci/smux
//!
//! Frames are `[version u8][command u8][length u16 LE][stream id u32 LE][data]`.
//! Version 1 has no flow control, so reading frames stops when streams don't read their data,
//! and FIN closes both directions of a stream.

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

const VERSION: u8 = 1;

const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;

const HEADER_SIZE: usize = 8;
/// Maximum data length of frames sent, same as smux
const MAX_FRAME_SIZE: usize = 32 * 1024;
/// Data received but not read by streams, same as smux
const MAX_RECEIVE_BUFFER: usize = 4 * 1024 * 1024;
/// Data written by streams but not sent
const MAX_SEND_BUFFER: usize = 1024 * 1024;

fn encode_header(cmd: u8, len: usize, stream_id: u32) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[0] = VERSION;
    header[1] = cmd;
    header[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    header[4..8].copy_from_slice(&stream_id.to_le_bytes());
    header
}

#[derive(Default)]
struct StreamState {
    buffer: VecDeque<Bytes>,
    fin_received: bool,
    session_closed: bool,
    dropped: bool,
    read_waker: Option<Waker>,
}

impl StreamState {
    fn wake(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }
}

type SharedStreamState = Arc<Mutex<StreamState>>;

struct Shared {
    streams: Mutex<HashMap<u32, SharedStreamState>>,
    // Streams not dropped, including those with FIN received
    alive: AtomicUsize,
    receive_budget: Semaphore,
    send_budget: Arc<Semaphore>,
    sender: mpsc::UnboundedSender<Frame>,
}

/// Server side smux session
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
                receive_budget: Semaphore::new(MAX_RECEIVE_BUFFER),
                send_budget: Arc::new(Semaphore::new(MAX_SEND_BUFFER)),
                sender,
            }),
            closed: false,
        }
    }

    /// Accepts a stream, `None` if the session is closed.
    ///
    /// Not cancel safe.
    pub(super) async fn accept(&mut self) -> io::Result<Option<SmuxStream>> {
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

        // Streams with FIN received have been removed, they are still readable until EOF
        let streams = std::mem::take(&mut *self.shared.streams.lock().unwrap());
        for state in streams.values() {
            let mut state = state.lock().unwrap();
            state.session_closed = true;
            state.wake();
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
async fn read_frames<R>(reader: &mut R, shared: &Arc<Shared>) -> io::Result<Option<SmuxStream>>
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
        let cmd = header[1];
        let len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let stream_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported smux version {version}"),
            ));
        }
        if cmd != CMD_PSH && len != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("smux command {cmd} with {len} bytes of data"),
            ));
        }

        match cmd {
            CMD_PSH => {
                let mut data = BytesMut::zeroed(len);
                reader.read_exact(&mut data).await?;
                if data.is_empty() {
                    continue;
                }

                // Data of unknown streams is dropped
                let Some(state) = shared.streams.lock().unwrap().get(&stream_id).cloned() else {
                    continue;
                };

                // Waits until streams read enough data
                shared
                    .receive_budget
                    .acquire_many(len as u32)
                    .await
                    .map_err(io::Error::other)?
                    .forget();

                let mut state = state.lock().unwrap();
                if state.dropped {
                    shared.receive_budget.add_permits(len);
                    continue;
                }
                state.buffer.push_back(data.freeze());
                state.wake();
            }
            CMD_SYN => {
                let mut streams = shared.streams.lock().unwrap();
                if streams.contains_key(&stream_id) {
                    continue;
                }
                if shared.alive.load(Ordering::Relaxed) >= MAX_STREAMS {
                    // smux has no reset, the stream is closed immediately
                    let _ = shared
                        .sender
                        .send(Frame::new(&encode_header(CMD_FIN, 0, stream_id), Bytes::new(), None));
                    continue;
                }

                let state = SharedStreamState::default();
                streams.insert(stream_id, state.clone());
                shared.alive.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(SmuxStream {
                    stream_id,
                    state,
                    shared: shared.clone(),
                    send_budget: PollSemaphore::new(shared.send_budget.clone()),
                    fin_sent: false,
                }));
            }
            CMD_FIN => {
                let state = shared.streams.lock().unwrap().remove(&stream_id);
                if let Some(state) = state {
                    let mut state = state.lock().unwrap();
                    state.fin_received = true;
                    state.wake();
                }
            }
            CMD_NOP => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported smux command {cmd}"),
                ));
            }
        }
    }
}

/// Stream of a smux session
pub(super) struct SmuxStream {
    stream_id: u32,
    state: SharedStreamState,
    shared: Arc<Shared>,
    send_budget: PollSemaphore,
    fin_sent: bool,
}

impl SmuxStream {
    fn send_fin(&mut self) {
        if !self.fin_sent {
            self.fin_sent = true;
            let _ = self.shared.sender.send(Frame::new(
                &encode_header(CMD_FIN, 0, self.stream_id),
                Bytes::new(),
                None,
            ));
        }
    }
}

impl AsyncRead for SmuxStream {
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
            drop(state);
            this.shared.receive_budget.add_permits(n);
            return Poll::Ready(Ok(()));
        }

        if state.fin_received {
            return Poll::Ready(Ok(()));
        }
        if state.session_closed {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }

        match state.read_waker {
            Some(ref waker) if waker.will_wake(cx.waker()) => {}
            _ => state.read_waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // The client's stream is closed after FIN
        if this.fin_sent || this.state.lock().unwrap().fin_received {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let len = cmp::min(buf.len(), MAX_FRAME_SIZE);
        let Some(permit) = ready!(this.send_budget.poll_acquire_many(cx, len as u32)) else {
            // Session closed
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };

        let frame = Frame::new(
            &encode_header(CMD_PSH, len, this.stream_id),
            Bytes::copy_from_slice(&buf[..len]),
            Some(permit),
        );
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
        self.get_mut().send_fin();
        Poll::Ready(Ok(()))
    }
}

impl Drop for SmuxStream {
    fn drop(&mut self) {
        let unread = {
            let mut state = self.state.lock().unwrap();
            state.dropped = true;
            let unread = state.buffer.iter().map(Bytes::len).sum();
            state.buffer.clear();
            unread
        };
        self.shared.receive_budget.add_permits(unread);
        self.shared.alive.fetch_sub(1, Ordering::Relaxed);

        // The stream has been removed if FIN is received, the ID may be used by a new stream
        let mut streams = self.shared.streams.lock().unwrap();
        if streams
            .get(&self.stream_id)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            streams.remove(&self.stream_id);
        }
        drop(streams);

        self.send_fin();
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::{
        io::{AsyncWriteExt, DuplexStream},
        time,
    };

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn frame(cmd: u8, stream_id: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = encode_header(cmd, data.len(), stream_id).to_vec();
        buf.extend_from_slice(data);
        buf
    }

    async fn read_frame(client: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
        time::timeout(TIMEOUT, async {
            let mut header = [0u8; HEADER_SIZE];
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], VERSION);
            let len = u16::from_le_bytes([header[2], header[3]]) as usize;
            let mut data = vec![0u8; len];
            client.read_exact(&mut data).await.unwrap();
            (
                header[1],
                u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
                data,
            )
        })
        .await
        .expect("read frame timeout")
    }

    async fn accept<T>(session: &mut Session<T>) -> SmuxStream
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        time::timeout(TIMEOUT, session.accept())
            .await
            .expect("accept timeout")
            .unwrap()
            .expect("stream")
    }

    async fn read_to_end(stream: &mut SmuxStream) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        time::timeout(TIMEOUT, stream.read_to_end(&mut buf))
            .await
            .expect("read timeout")?;
        Ok(buf)
    }

    fn assert_send<T: Send + Unpin + 'static>(_: &T) {}

    /// Keeps reading frames of the session, which drives streams
    fn drive<T>(mut session: Session<T>) -> tokio::task::JoinHandle<()>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        tokio::spawn(async move { while let Ok(Some(..)) = session.accept().await {} })
    }

    #[tokio::test]
    async fn read_stream() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        let mut data = frame(CMD_SYN, 3, &[]);
        data.extend(frame(CMD_PSH, 3, b"hello "));
        // Empty data is not EOF
        data.extend(frame(CMD_PSH, 3, b""));
        data.extend(frame(CMD_NOP, 0, &[]));
        data.extend(frame(CMD_PSH, 3, b"world"));
        data.extend(frame(CMD_FIN, 3, &[]));
        client.write_all(&data).await.unwrap();

        let mut stream = accept(&mut session).await;
        assert_send(&stream);
        let _driver = drive(session);
        assert_eq!(read_to_end(&mut stream).await.unwrap(), b"hello world");

        // The client's stream is closed after FIN
        let err = stream.write_all(b"data").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn write_stream() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        client.write_all(&frame(CMD_SYN, 3, &[])).await.unwrap();
        let mut stream = accept(&mut session).await;

        let payload: Vec<u8> = (0..70000u32).map(|i| i as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        // Little endian header
        let mut header = [0u8; HEADER_SIZE];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [VERSION, CMD_PSH, 0x00, 0x80, 3, 0, 0, 0]);
        let mut received = vec![0u8; MAX_FRAME_SIZE];
        client.read_exact(&mut received).await.unwrap();

        // FIN is sent after all data
        loop {
            let (cmd, stream_id, data) = read_frame(&mut client).await;
            assert_eq!(stream_id, 3);
            if cmd == CMD_FIN {
                break;
            }
            assert_eq!(cmd, CMD_PSH);
            assert!(data.len() <= MAX_FRAME_SIZE);
            received.extend(data);
        }
        assert_eq!(received, payload);

        // Writes after shutdown fail
        assert!(stream.write_all(b"data").await.is_err());
    }

    #[tokio::test]
    async fn drop_sends_fin() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        client.write_all(&frame(CMD_SYN, 3, &[])).await.unwrap();
        let mut stream = accept(&mut session).await;
        stream.write_all(b"bye").await.unwrap();
        drop(stream);

        assert_eq!(read_frame(&mut client).await, (CMD_PSH, 3, b"bye".to_vec()));
        assert_eq!(read_frame(&mut client).await, (CMD_FIN, 3, Vec::new()));
    }

    #[tokio::test]
    async fn ignore_unknown_streams() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        let mut data = frame(CMD_SYN, 3, &[]);
        data.extend(frame(CMD_PSH, 3, b"a"));
        data.extend(frame(CMD_PSH, 99, b"unknown"));
        data.extend(frame(CMD_FIN, 99, &[]));
        // Duplicated
        data.extend(frame(CMD_SYN, 3, &[]));
        data.extend(frame(CMD_PSH, 3, b"b"));
        data.extend(frame(CMD_FIN, 3, &[]));
        data.extend(frame(CMD_SYN, 5, &[]));
        data.extend(frame(CMD_FIN, 5, &[]));
        client.write_all(&data).await.unwrap();

        let mut stream3 = accept(&mut session).await;
        let mut stream5 = accept(&mut session).await;
        assert_eq!(stream5.stream_id, 5);
        let _driver = drive(session);
        assert_eq!(read_to_end(&mut stream3).await.unwrap(), b"ab");
        assert_eq!(read_to_end(&mut stream5).await.unwrap(), b"");
    }

    #[tokio::test]
    async fn protocol_errors() {
        let frames = [
            {
                let mut f = frame(CMD_SYN, 3, &[]);
                f[0] = 2;
                f
            },
            // UPD of version 2
            frame(4, 3, &[0; 8]),
            frame(CMD_NOP, 0, b"data"),
        ];

        for data in frames {
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let mut session = Session::new(server);
            client.write_all(&data).await.unwrap();

            let err = time::timeout(TIMEOUT, session.accept()).await.unwrap().err();
            assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
            assert!(session.accept().await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn receive_backpressure() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        // Stream 3 receives more data than the budget, which blocks stream 5
        let chunk = vec![0x33; MAX_FRAME_SIZE];
        let frames = MAX_RECEIVE_BUFFER / MAX_FRAME_SIZE + 1;
        let writer = tokio::spawn(async move {
            client.write_all(&frame(CMD_SYN, 3, &[])).await.unwrap();
            for _ in 0..frames {
                client.write_all(&frame(CMD_PSH, 3, &chunk)).await.unwrap();
            }
            client.write_all(&frame(CMD_SYN, 5, &[])).await.unwrap();
            client
        });

        let mut stream3 = accept(&mut session).await;
        let accept5 = tokio::spawn(async move {
            let stream = session.accept().await;
            (session, stream)
        });

        time::sleep(Duration::from_millis(200)).await;
        assert!(!accept5.is_finished(), "stream 5 should be blocked");

        let mut buf = vec![0u8; 2 * MAX_FRAME_SIZE];
        stream3.read_exact(&mut buf).await.unwrap();

        let (_session, stream5) = time::timeout(TIMEOUT, accept5).await.unwrap().unwrap();
        assert_eq!(stream5.unwrap().unwrap().stream_id, 5);

        // The rest of stream 3's data is still readable
        let mut rest = vec![0u8; (frames - 2) * MAX_FRAME_SIZE];
        stream3.read_exact(&mut rest).await.unwrap();
        assert!(rest.iter().all(|b| *b == 0x33));
        drop(writer);
    }

    #[tokio::test]
    async fn session_closed() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        client.write_all(&frame(CMD_SYN, 3, &[])).await.unwrap();
        let mut stream = accept(&mut session).await;
        let driver = drive(session);

        drop(client);
        time::timeout(TIMEOUT, driver).await.unwrap().unwrap();

        // Not EOF, relays must be aborted
        let err = read_to_end(&mut stream).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        let err = stream.write_all(b"data").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn stream_limit() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let mut session = Session::new(server);

        let mut data = Vec::new();
        for i in 0..=MAX_STREAMS as u32 {
            data.extend(frame(CMD_SYN, i * 2 + 3, &[]));
        }
        client.write_all(&data).await.unwrap();

        let mut streams = Vec::new();
        for _ in 0..MAX_STREAMS {
            streams.push(accept(&mut session).await);
        }
        let _driver = drive(session);

        // The stream over the limit is closed immediately
        let rejected = MAX_STREAMS as u32 * 2 + 3;
        assert_eq!(read_frame(&mut client).await, (CMD_FIN, rejected, Vec::new()));
    }

    #[tokio::test]
    async fn reused_stream_id() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);

        let mut data = frame(CMD_SYN, 3, &[]);
        data.extend(frame(CMD_FIN, 3, &[]));
        data.extend(frame(CMD_SYN, 3, &[]));
        client.write_all(&data).await.unwrap();

        let old = accept(&mut session).await;
        let mut new = accept(&mut session).await;
        let _driver = drive(session);

        // Dropping the old stream doesn't remove the new one
        drop(old);
        assert_eq!(read_frame(&mut client).await, (CMD_FIN, 3, Vec::new()));

        let mut data = frame(CMD_PSH, 3, b"new");
        data.extend(frame(CMD_FIN, 3, &[]));
        client.write_all(&data).await.unwrap();
        assert_eq!(read_to_end(&mut new).await.unwrap(), b"new");
    }

    #[tokio::test]
    async fn concurrent_echo() {
        const STREAMS: u32 = 8;
        const LEN: usize = 100_000;

        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(server);
        tokio::spawn(async move {
            while let Ok(Some(stream)) = session.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    tokio::io::copy(&mut reader, &mut writer).await.unwrap();
                    writer.shutdown().await.unwrap();
                });
            }
        });

        let payload = |id: u32| -> Vec<u8> { (0..LEN as u32).map(|i| (i ^ id) as u8).collect() };

        let (mut reader, mut writer) = tokio::io::split(client);
        let mut sender = Some(tokio::spawn(async move {
            for id in 0..STREAMS {
                writer.write_all(&frame(CMD_SYN, id * 2 + 3, &[])).await.unwrap();
            }
            // Interleaved
            for offset in (0..LEN).step_by(10_000) {
                for id in 0..STREAMS {
                    let data = payload(id);
                    writer
                        .write_all(&frame(CMD_PSH, id * 2 + 3, &data[offset..offset + 10_000]))
                        .await
                        .unwrap();
                }
            }
            writer
        }));

        // Echoed data, then FIN after the client's FIN
        let mut received: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut writer = None;
        let mut fin = 0;
        while fin < STREAMS {
            if writer.is_none() && received.values().map(Vec::len).sum::<usize>() == LEN * STREAMS as usize {
                let mut w = sender.take().unwrap().await.unwrap();
                for id in 0..STREAMS {
                    w.write_all(&frame(CMD_FIN, id * 2 + 3, &[])).await.unwrap();
                }
                writer = Some(w);
            }

            let mut header = [0u8; HEADER_SIZE];
            time::timeout(TIMEOUT, reader.read_exact(&mut header))
                .await
                .expect("read timeout")
                .unwrap();
            let len = u16::from_le_bytes([header[2], header[3]]) as usize;
            let stream_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            let mut data = vec![0u8; len];
            reader.read_exact(&mut data).await.unwrap();
            match header[1] {
                CMD_PSH => received.entry(stream_id).or_default().extend(data),
                CMD_FIN => fin += 1,
                cmd => panic!("unexpected command {cmd}"),
            }
        }

        for id in 0..STREAMS {
            assert_eq!(received[&(id * 2 + 3)], payload(id), "stream {}", id * 2 + 3);
        }
    }
}
