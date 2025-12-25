// Copyright 2024-2026 Farlight Networks, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Control stream handler.
//!
//! Manages reading and writing protocol messages on the dedicated control stream.

use crate::Error;
use quic_reverse_control::{BincodeCodec, Codec, FrameReader, FrameWriter, ProtocolMessage};
use quic_reverse_transport::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{trace, warn};

/// Handles reading protocol messages from the control stream.
pub struct ControlReader<R> {
    recv: R,
    frame_reader: FrameReader,
    codec: BincodeCodec,
    read_buf: Vec<u8>,
}

impl<R: RecvStream> ControlReader<R> {
    /// Creates a new control reader wrapping the receive stream.
    pub fn new(recv: R) -> Self {
        Self {
            recv,
            frame_reader: FrameReader::with_capacity(4096),
            codec: BincodeCodec::new(),
            read_buf: vec![0u8; 4096],
        }
    }

    /// Reads the next protocol message from the control stream.
    ///
    /// Returns `Ok(None)` if the stream has closed gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the message is malformed.
    pub async fn read_message(&mut self) -> Result<Option<ProtocolMessage>, Error> {
        loop {
            // Try to read a complete frame from buffered data
            match self.frame_reader.read_frame() {
                Ok(Some(frame_data)) => {
                    let message = self.codec.decode(&frame_data)?;
                    trace!(message = ?message_type(&message), len = frame_data.len(), "received message");
                    return Ok(Some(message));
                }
                Ok(None) => {
                    // Need more data
                }
                Err(e) => {
                    warn!(error = %e, "frame read error");
                    return Err(e.into());
                }
            }

            // Read more data from the stream
            let n = self.recv.read(&mut self.read_buf).await.map_err(|e| {
                warn!(error = %e, "control stream read error");
                Error::Transport(Box::new(e))
            })?;

            if n == 0 {
                // Stream closed
                if self.frame_reader.buffered_len() > 0 {
                    warn!(
                        buffered = self.frame_reader.buffered_len(),
                        "control stream closed with partial frame"
                    );
                    return Err(Error::protocol_violation(
                        "control stream closed with partial frame",
                    ));
                }
                trace!("control stream closed gracefully");
                return Ok(None);
            }

            trace!(bytes = n, "read from control stream");
            self.frame_reader.extend(&self.read_buf[..n]);
        }
    }
}

/// Returns a short type name for the message for logging.
const fn message_type(msg: &ProtocolMessage) -> &'static str {
    match msg {
        ProtocolMessage::Hello(_) => "Hello",
        ProtocolMessage::HelloAck(_) => "HelloAck",
        ProtocolMessage::OpenRequest(_) => "OpenRequest",
        ProtocolMessage::OpenResponse(_) => "OpenResponse",
        ProtocolMessage::StreamClose(_) => "StreamClose",
        ProtocolMessage::Ping(_) => "Ping",
        ProtocolMessage::Pong(_) => "Pong",
    }
}

/// Handles writing protocol messages to the control stream.
pub struct ControlWriter<S> {
    send: S,
    frame_writer: FrameWriter,
    codec: BincodeCodec,
}

impl<S: SendStream> ControlWriter<S> {
    /// Creates a new control writer wrapping the send stream.
    pub fn new(send: S) -> Self {
        Self {
            send,
            frame_writer: FrameWriter::with_capacity(4096),
            codec: BincodeCodec::new(),
        }
    }

    /// Writes a protocol message to the control stream.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding or writing fails.
    pub async fn write_message(&mut self, message: &ProtocolMessage) -> Result<(), Error> {
        // Encode the message
        let encoded = self.codec.encode(message)?;

        // Frame it
        self.frame_writer.write_frame(&encoded).map_err(|e| {
            warn!(error = %e, "frame write error");
            Error::Control(e)
        })?;

        // Write to the stream
        let bytes = self.frame_writer.take_bytes();
        trace!(message = ?message_type(message), len = bytes.len(), "sending message");
        self.send.write_all(&bytes).await.map_err(|e| {
            // Connection-related errors during shutdown are expected, log at trace level
            if is_connection_closed_error(&e) {
                trace!(error = %e, "control stream write failed (connection closed)");
            } else {
                warn!(error = %e, "control stream write error");
            }
            Error::Transport(Box::new(e))
        })?;

        Ok(())
    }

    /// Flushes the underlying stream.
    ///
    /// # Errors
    ///
    /// Returns an error if flushing fails.
    pub async fn flush(&mut self) -> Result<(), Error> {
        self.send
            .flush()
            .await
            .map_err(|e| Error::Transport(Box::new(e)))
    }

    /// Gracefully finishes the control stream.
    ///
    /// # Errors
    ///
    /// Returns an error if finishing fails.
    #[allow(dead_code)] // Public API for graceful shutdown
    pub async fn finish(mut self) -> Result<(), Error> {
        self.send
            .finish()
            .await
            .map_err(|e| Error::Transport(Box::new(e)))
    }
}

/// Combined control stream handler for both reading and writing.
pub struct ControlStream<S, R> {
    writer: ControlWriter<S>,
    reader: ControlReader<R>,
}

impl<S: SendStream, R: RecvStream> ControlStream<S, R> {
    /// Creates a new control stream handler.
    pub fn new(send: S, recv: R) -> Self {
        Self {
            writer: ControlWriter::new(send),
            reader: ControlReader::new(recv),
        }
    }

    /// Splits into separate reader and writer halves.
    pub fn split(self) -> (ControlWriter<S>, ControlReader<R>) {
        (self.writer, self.reader)
    }

    /// Reads the next protocol message.
    pub async fn read_message(&mut self) -> Result<Option<ProtocolMessage>, Error> {
        self.reader.read_message().await
    }

    /// Writes a protocol message.
    pub async fn write_message(&mut self, message: &ProtocolMessage) -> Result<(), Error> {
        self.writer.write_message(message).await
    }

    /// Flushes the write side.
    pub async fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush().await
    }
}

/// Returns true if the error indicates the connection was closed.
///
/// These errors are expected during graceful shutdown and should not
/// be logged at warn level.
fn is_connection_closed_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
    ) || e.to_string().to_lowercase().contains("connection lost")
}

#[cfg(test)]
mod tests {
    use super::*;
    use quic_reverse_control::{Features, Hello};
    use quic_reverse_transport::{mock_connection_pair, Connection};

    #[tokio::test]
    async fn control_stream_round_trip() {
        let (conn_a, conn_b) = mock_connection_pair();

        // Open a stream from A
        let accept_handle = tokio::spawn(async move { conn_b.accept_bi().await });

        let (send_a, recv_a) = conn_a.open_bi().await.expect("open should succeed");
        let (send_b, recv_b) = accept_handle
            .await
            .expect("task should complete")
            .expect("accept should succeed")
            .expect("should have stream");

        // Create control stream handlers
        // A writes on send_a → B reads on recv_b
        // B writes on send_b → A reads on recv_a
        // For bidirectional control: A uses (send_a, recv_a), B uses (send_b, recv_b)
        // This is a single bidirectional stream, so each side reads from their own recv
        let mut control_a = ControlStream::new(send_a, recv_a);
        let mut control_b = ControlStream::new(send_b, recv_b);

        // Send a Hello from A to B
        let hello = ProtocolMessage::Hello(Hello::new(Features::PING_PONG));
        control_a
            .write_message(&hello)
            .await
            .expect("write should succeed");
        control_a.flush().await.expect("flush should succeed");

        // Read it on B
        let received = control_b
            .read_message()
            .await
            .expect("read should succeed")
            .expect("should have message");

        assert_eq!(received, hello);
    }

    #[tokio::test]
    async fn multiple_messages() {
        let (conn_a, conn_b) = mock_connection_pair();

        let accept_handle = tokio::spawn(async move { conn_b.accept_bi().await });

        let (send_a, recv_a) = conn_a.open_bi().await.expect("open should succeed");
        let (send_b, recv_b) = accept_handle
            .await
            .expect("task should complete")
            .expect("accept should succeed")
            .expect("should have stream");

        let mut control_a = ControlStream::new(send_a, recv_a);
        let mut control_b = ControlStream::new(send_b, recv_b);

        // Send multiple messages
        let msg1 = ProtocolMessage::Hello(Hello::new(Features::empty()));
        let msg2 = ProtocolMessage::Ping(quic_reverse_control::Ping { sequence: 42 });
        let msg3 = ProtocolMessage::Pong(quic_reverse_control::Pong { sequence: 42 });

        control_a.write_message(&msg1).await.expect("write 1");
        control_a.write_message(&msg2).await.expect("write 2");
        control_a.write_message(&msg3).await.expect("write 3");
        control_a.flush().await.expect("flush");

        // Read all messages
        assert_eq!(control_b.read_message().await.unwrap(), Some(msg1));
        assert_eq!(control_b.read_message().await.unwrap(), Some(msg2));
        assert_eq!(control_b.read_message().await.unwrap(), Some(msg3));
    }

    #[tokio::test]
    async fn graceful_close_returns_none() {
        let (conn_a, conn_b) = mock_connection_pair();

        let accept_handle = tokio::spawn(async move { conn_b.accept_bi().await });

        let (send_a, recv_a) = conn_a.open_bi().await.expect("open should succeed");
        let (send_b, recv_b) = accept_handle
            .await
            .expect("task should complete")
            .expect("accept should succeed")
            .expect("should have stream");

        let (writer_a, _reader_a) = ControlStream::new(send_a, recv_a).split();
        let mut control_b = ControlStream::new(send_b, recv_b);

        // Finish the write side of A
        writer_a.finish().await.expect("finish should succeed");

        // Read on B should return None
        let result = control_b.read_message().await.expect("read should succeed");
        assert!(result.is_none());
    }
}
