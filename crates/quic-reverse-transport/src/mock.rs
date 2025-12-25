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

//! Mock transport implementation for testing.
//!
//! Provides in-memory implementations of the transport traits for use in
//! unit and integration tests without requiring actual QUIC connections.

use crate::traits::{Connection, RecvStream, SendStream};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Shared state between a pair of mock connections.
#[derive(Debug)]
struct SharedState {
    /// Streams opened by connection A, waiting to be accepted by B.
    a_to_b: VecDeque<(MockSendStream, MockRecvStream)>,
    /// Streams opened by connection B, waiting to be accepted by A.
    b_to_a: VecDeque<(MockSendStream, MockRecvStream)>,
    /// Waker for connection A waiting to accept.
    waker_a: Option<Waker>,
    /// Waker for connection B waiting to accept.
    waker_b: Option<Waker>,
    /// Whether connection A is closed.
    closed_a: bool,
    /// Whether connection B is closed.
    closed_b: bool,
}

/// Creates a connected pair of mock connections.
///
/// Data sent on one connection can be received on the other, simulating
/// a bidirectional QUIC connection.
#[must_use]
pub fn mock_connection_pair() -> (MockConnection, MockConnection) {
    let state = Arc::new(Mutex::new(SharedState {
        a_to_b: VecDeque::new(),
        b_to_a: VecDeque::new(),
        waker_a: None,
        waker_b: None,
        closed_a: false,
        closed_b: false,
    }));

    let conn_a = MockConnection {
        state: Arc::clone(&state),
        is_side_a: true,
    };

    let conn_b = MockConnection {
        state,
        is_side_a: false,
    };

    (conn_a, conn_b)
}

/// A mock QUIC connection for testing.
#[derive(Debug, Clone)]
pub struct MockConnection {
    state: Arc<Mutex<SharedState>>,
    is_side_a: bool,
}

/// Error type for mock connection operations.
#[derive(Debug, thiserror::Error)]
pub enum MockError {
    /// The connection has been closed.
    #[error("connection closed")]
    ConnectionClosed,
}

impl Connection for MockConnection {
    type SendStream = MockSendStream;
    type RecvStream = MockRecvStream;
    type OpenError = MockError;
    type AcceptError = MockError;

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::OpenError> {
        let (our_send, their_recv) = mock_stream_pair();
        let (their_send, our_recv) = mock_stream_pair();

        let mut state = self.state.lock().unwrap();

        // Check if we're closed
        if self.is_side_a && state.closed_a {
            return Err(MockError::ConnectionClosed);
        }
        if !self.is_side_a && state.closed_b {
            return Err(MockError::ConnectionClosed);
        }

        // Check if peer is closed
        if self.is_side_a && state.closed_b {
            return Err(MockError::ConnectionClosed);
        }
        if !self.is_side_a && state.closed_a {
            return Err(MockError::ConnectionClosed);
        }

        // Queue the stream pair for the peer to accept
        if self.is_side_a {
            state.a_to_b.push_back((their_send, their_recv));
            if let Some(waker) = state.waker_b.take() {
                waker.wake();
            }
        } else {
            state.b_to_a.push_back((their_send, their_recv));
            if let Some(waker) = state.waker_a.take() {
                waker.wake();
            }
        }

        Ok((our_send, our_recv))
    }

    async fn accept_bi(
        &self,
    ) -> Result<Option<(Self::SendStream, Self::RecvStream)>, Self::AcceptError> {
        // Use a simple polling future
        std::future::poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();

            // Check if we're closed
            if self.is_side_a && state.closed_a {
                return Poll::Ready(Ok(None));
            }
            if !self.is_side_a && state.closed_b {
                return Poll::Ready(Ok(None));
            }

            // Try to get a stream from the peer's queue
            let stream = if self.is_side_a {
                state.b_to_a.pop_front()
            } else {
                state.a_to_b.pop_front()
            };

            if let Some((send, recv)) = stream {
                Poll::Ready(Ok(Some((send, recv))))
            } else {
                // Check if peer is closed
                if self.is_side_a && state.closed_b {
                    return Poll::Ready(Ok(None));
                }
                if !self.is_side_a && state.closed_a {
                    return Poll::Ready(Ok(None));
                }

                // Register waker and wait
                if self.is_side_a {
                    state.waker_a = Some(cx.waker().clone());
                } else {
                    state.waker_b = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await
    }

    fn close(&self, _code: u32, _reason: &[u8]) {
        let mut state = self.state.lock().unwrap();
        if self.is_side_a {
            state.closed_a = true;
            if let Some(waker) = state.waker_b.take() {
                waker.wake();
            }
        } else {
            state.closed_b = true;
            if let Some(waker) = state.waker_a.take() {
                waker.wake();
            }
        }
    }

    fn is_open(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.closed_a && !state.closed_b
    }
}

/// Shared buffer for a mock stream.
#[derive(Debug, Default)]
struct StreamBuffer {
    data: VecDeque<u8>,
    waker: Option<Waker>,
    finished: bool,
    reset: Option<u32>,
}

/// Creates a connected pair of mock streams.
///
/// Data written to the send stream can be read from the receive stream.
fn mock_stream_pair() -> (MockSendStream, MockRecvStream) {
    let buffer = Arc::new(Mutex::new(StreamBuffer::default()));

    let send = MockSendStream {
        buffer: Arc::clone(&buffer),
    };

    let recv = MockRecvStream { buffer };

    (send, recv)
}

/// A mock QUIC send stream for testing.
#[derive(Debug)]
pub struct MockSendStream {
    buffer: Arc<Mutex<StreamBuffer>>,
}

impl AsyncWrite for MockSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut buffer = self.buffer.lock().unwrap();

        if buffer.reset.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "stream reset",
            )));
        }

        buffer.data.extend(buf);

        if let Some(waker) = buffer.waker.take() {
            waker.wake();
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.finished = true;
        if let Some(waker) = buffer.waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl SendStream for MockSendStream {
    type FinishError = io::Error;

    async fn finish(&mut self) -> Result<(), Self::FinishError> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.finished = true;
        if let Some(waker) = buffer.waker.take() {
            waker.wake();
        }
        Ok(())
    }

    fn reset(&mut self, code: u32) {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.reset = Some(code);
        if let Some(waker) = buffer.waker.take() {
            waker.wake();
        }
    }
}

/// A mock QUIC receive stream for testing.
#[derive(Debug)]
pub struct MockRecvStream {
    buffer: Arc<Mutex<StreamBuffer>>,
}

impl AsyncRead for MockRecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut buffer = self.buffer.lock().unwrap();

        if let Some(code) = buffer.reset {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream reset with code {code}"),
            )));
        }

        if !buffer.data.is_empty() {
            let to_read = buf.remaining().min(buffer.data.len());
            for _ in 0..to_read {
                if let Some(byte) = buffer.data.pop_front() {
                    buf.put_slice(&[byte]);
                }
            }
            Poll::Ready(Ok(()))
        } else if buffer.finished {
            // EOF
            Poll::Ready(Ok(()))
        } else {
            buffer.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl RecvStream for MockRecvStream {
    fn stop(&mut self, _code: u32) {
        // For the mock, we just mark the buffer as finished
        let mut buffer = self.buffer.lock().unwrap();
        buffer.finished = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn mock_connection_open_accept() {
        let (conn_a, conn_b) = mock_connection_pair();

        // Spawn a task to accept on B
        let accept_task = tokio::spawn(async move { conn_b.accept_bi().await });

        // Open on A
        let (mut send_a, mut recv_a) = conn_a.open_bi().await.expect("open should succeed");

        // Accept on B should complete
        let (mut send_b, mut recv_b) = accept_task
            .await
            .expect("task should complete")
            .expect("accept should succeed")
            .expect("should have stream");

        // Write from A, read on B
        send_a
            .write_all(b"hello from A")
            .await
            .expect("write should succeed");
        send_a.finish().await.expect("finish should succeed");

        let mut buf = vec![0u8; 100];
        let n = recv_b.read(&mut buf).await.expect("read should succeed");
        assert_eq!(&buf[..n], b"hello from A");

        // Write from B, read on A
        send_b
            .write_all(b"hello from B")
            .await
            .expect("write should succeed");
        send_b.finish().await.expect("finish should succeed");

        let n = recv_a.read(&mut buf).await.expect("read should succeed");
        assert_eq!(&buf[..n], b"hello from B");
    }

    #[tokio::test]
    async fn mock_connection_close() {
        let (conn_a, conn_b) = mock_connection_pair();

        assert!(conn_a.is_open());
        assert!(conn_b.is_open());

        conn_a.close(0, b"bye");

        assert!(!conn_a.is_open());
        assert!(!conn_b.is_open());

        // Accept should return None after close
        let result = conn_b.accept_bi().await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn mock_stream_reset() {
        let (mut send, mut recv) = mock_stream_pair();

        send.write_all(b"some data").await.expect("write succeeds");
        send.reset(42);

        // Read should fail with reset
        let mut buf = [0u8; 100];
        let result = recv.read(&mut buf).await;
        assert!(result.is_err());
    }

    #[test]
    fn mock_connection_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockConnection>();
    }

    #[test]
    fn mock_streams_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MockSendStream>();
        assert_send::<MockRecvStream>();
    }
}
