//! Frame writer of smux and yamux sessions

use std::io;

use bytes::Bytes;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt, BufWriter},
    sync::{OwnedSemaphorePermit, mpsc},
};

/// Maximum header size, 8 bytes of smux and 12 bytes of yamux
const MAX_HEADER_SIZE: usize = 12;
/// Frames are written in batches through a fixed size buffer
const WRITE_BUFFER_SIZE: usize = 64 * 1024;
const MAX_WRITE_FRAMES: usize = 64;

pub(super) struct Frame {
    header: [u8; MAX_HEADER_SIZE],
    header_len: usize,
    data: Bytes,
    // Send budget of data, returned after it is written
    _permit: Option<OwnedSemaphorePermit>,
}

impl Frame {
    pub(super) fn new(header: &[u8], data: Bytes, permit: Option<OwnedSemaphorePermit>) -> Self {
        let mut frame = Self {
            header: [0; MAX_HEADER_SIZE],
            header_len: header.len(),
            data,
            _permit: permit,
        };
        frame.header[..header.len()].copy_from_slice(header);
        frame
    }
}

/// Writes frames until all senders are dropped.
///
/// Writes are never cancelled, which are sticky in the AEAD stream.
pub(super) async fn write_frames<W>(writer: W, mut receiver: mpsc::UnboundedReceiver<Frame>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::with_capacity(WRITE_BUFFER_SIZE, writer);
    let mut frames = Vec::with_capacity(MAX_WRITE_FRAMES);

    while receiver.recv_many(&mut frames, MAX_WRITE_FRAMES).await > 0 {
        for frame in frames.drain(..) {
            writer.write_all(&frame.header[..frame.header_len]).await?;
            writer.write_all(&frame.data).await?;
        }

        if receiver.is_empty() {
            writer.flush().await?;
        }
    }

    Ok(())
}
