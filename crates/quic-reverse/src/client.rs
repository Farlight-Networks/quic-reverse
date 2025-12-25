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

// Mutex::lock().unwrap() is the standard pattern in Rust. The lock only fails
// if the mutex is poisoned (a thread panicked while holding it), which indicates
// a bug elsewhere that should propagate. We also suppress the "missing # Panics"
// warning since these are not user-actionable panics.
#![allow(clippy::unwrap_used, clippy::missing_panics_doc)]

//! High-level session client for quic-reverse.
//!
//! The [`SessionClient`] provides a convenient, cloneable interface for
//! working with quic-reverse sessions. It handles message processing
//! internally, allowing concurrent stream operations.
//!
//! # Example
//!
//! ```ignore
//! use quic_reverse::{Session, SessionClient, Config, Role, Metadata};
//!
//! // Create and start a session
//! let session = Session::new(connection, Role::Server, config);
//! let handle = session.start().await?;
//!
//! // Convert to a client for easy concurrent use
//! let client = SessionClient::new(handle);
//!
//! // Open streams - can be called concurrently from multiple tasks
//! let (send, recv) = client.open("echo", Metadata::Empty).await?;
//! ```

use crate::control::{ControlReader, ControlWriter};
use crate::error::TimeoutKind;
use crate::registry::OpenResult;
use crate::session::{PendingPing, SessionHandle, SessionInner};
use crate::{Error, State};
use quic_reverse_control::{
    CloseCode, Metadata, OpenRequest, OpenResponse, OpenStatus, ProtocolMessage, RejectCode,
    ServiceId, StreamBind, StreamClose,
};
use quic_reverse_transport::Connection;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

/// Events delivered to the event handler callback.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// Peer requested to open a stream to one of our services.
    OpenRequest {
        /// The request ID (needed for accept/reject).
        request_id: u64,
        /// The requested service.
        service: ServiceId,
        /// Metadata from the request.
        metadata: Metadata,
    },
    /// A stream was closed by the peer.
    StreamClosed {
        /// The logical stream ID.
        logical_stream_id: u64,
        /// The close code.
        code: CloseCode,
    },
    /// Ping received from peer (pong sent automatically).
    PingReceived {
        /// The ping sequence number.
        sequence: u64,
    },
    /// Session is closing.
    Closing {
        /// The close code.
        code: CloseCode,
        /// Optional reason.
        reason: Option<String>,
    },
}

/// A high-level, cloneable client for quic-reverse sessions.
///
/// `SessionClient` wraps a [`SessionHandle`] and provides a more convenient
/// API for working with quic-reverse sessions. It:
///
/// - Is cloneable, allowing use from multiple tasks
/// - Automatically processes incoming messages in a background task
/// - Delivers events via a channel for handling incoming requests
///
/// # Usage
///
/// For the **relay** (stream opener) side:
/// ```ignore
/// let client = SessionClient::new(handle);
/// let (send, recv) = client.open("echo", Metadata::Empty).await?;
/// ```
///
/// For the **edge** (stream acceptor) side:
/// ```ignore
/// let (client, mut events) = SessionClient::with_events(handle);
/// while let Some(event) = events.recv().await {
///     if let ClientEvent::OpenRequest { request_id, service, .. } = event {
///         let stream_id = 1;
///         client.accept_open(request_id, stream_id).await?;
///         let (send, recv) = connection.open_bi().await?;
///         // Handle the stream...
///     }
/// }
/// ```
pub struct SessionClient<C: Connection> {
    /// Shared session state from the original [`SessionHandle`].
    inner: Arc<SessionInner<C>>,
    /// Mutex-protected writer for sending control messages.
    writer: Arc<Mutex<ControlWriter<C::SendStream>>>,
    /// Handle to the background message processor task.
    processor_handle: Arc<JoinHandle<()>>,
}

impl<C: Connection> Clone for SessionClient<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            writer: Arc::clone(&self.writer),
            processor_handle: Arc::clone(&self.processor_handle),
        }
    }
}

impl<C: Connection> SessionClient<C> {
    /// Creates a new session client from a session handle.
    ///
    /// This spawns a background task to process incoming messages.
    /// Use [`with_events`](Self::with_events) if you need to handle
    /// incoming stream requests (edge device role).
    pub fn new(handle: SessionHandle<C>) -> Self {
        let (client, _events) = Self::with_events(handle);
        client
    }

    /// Creates a new session client with an event channel.
    ///
    /// Returns the client and a receiver for incoming events.
    /// Use this when you need to handle incoming stream requests
    /// (edge device role).
    pub fn with_events(handle: SessionHandle<C>) -> (Self, mpsc::Receiver<ClientEvent>) {
        // Create event channel
        let (event_tx, event_rx) = mpsc::channel(64);

        // Extract components from the handle
        let inner = handle.inner;
        let writer = Arc::new(Mutex::new(handle.writer));
        let reader = handle.reader;

        // Spawn the message processor
        let processor_inner = Arc::clone(&inner);
        let processor_writer = Arc::clone(&writer);
        let processor_handle = tokio::spawn(async move {
            run_message_processor(processor_inner, processor_writer, reader, event_tx).await;
        });

        let client = Self {
            inner,
            writer,
            processor_handle: Arc::new(processor_handle),
        };

        (client, event_rx)
    }

    /// Returns the current session state.
    #[must_use]
    pub fn state(&self) -> State {
        State::from_u8(self.inner.state.load(Ordering::SeqCst))
    }

    /// Returns true if the session is ready for operations.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state() == State::Ready
    }

    /// Returns a reference to the underlying connection.
    #[must_use]
    pub fn connection(&self) -> &C {
        &self.inner.connection
    }

    /// Opens a stream to a service on the peer.
    ///
    /// Sends an `OpenRequest` and waits for the peer to accept and
    /// open a data stream back.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session is not ready
    /// - The request limit has been reached
    /// - The peer rejects the request
    /// - The request times out
    pub async fn open(
        &self,
        service: impl Into<ServiceId>,
        metadata: Metadata,
    ) -> Result<(C::SendStream, C::RecvStream), Error> {
        if !self.is_ready() {
            return Err(Error::SessionClosed);
        }

        let service = service.into();

        // Create response channel
        let (response_tx, response_rx) = oneshot::channel();

        // Register pending request
        let request_id = {
            let mut registry = self.inner.registry.lock().unwrap();
            let request_id = registry.next_request_id();
            let request =
                OpenRequest::new(request_id, service.clone()).with_metadata(metadata.clone());
            if registry.register_pending(&request, response_tx).is_none() {
                return Err(Error::CapacityExceeded("too many pending open requests"));
            }
            request_id
        };

        debug!(request_id, service = %service.as_str(), "sending open request");

        // Send the request
        {
            let mut writer = self.writer.lock().await;
            let request = OpenRequest::new(request_id, service).with_metadata(metadata);
            writer
                .write_message(&ProtocolMessage::OpenRequest(request))
                .await?;
            writer.flush().await?;
        }

        // Wait for response with timeout
        let open_timeout = self.inner.config.open_timeout;
        let result = match timeout(open_timeout, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                // Channel closed - session closed
                let mut registry = self.inner.registry.lock().unwrap();
                registry.take_pending(request_id);
                return Err(Error::SessionClosed);
            }
            Err(_) => {
                // Timeout
                let mut registry = self.inner.registry.lock().unwrap();
                registry.take_pending(request_id);
                return Err(Error::Timeout(TimeoutKind::OpenRequest));
            }
        };

        match result {
            OpenResult::Accepted { logical_stream_id } => {
                debug!(request_id, logical_stream_id, "open request accepted");

                // Accept the data stream with timeout
                let bind_timeout = self.inner.config.stream_bind_timeout;
                let stream_result = timeout(bind_timeout, self.inner.connection.accept_bi()).await;

                match stream_result {
                    Ok(Ok(Some((send, mut recv)))) => {
                        // Read and verify the StreamBind frame
                        let mut bind_buf = [0u8; StreamBind::ENCODED_SIZE];
                        let read_result =
                            timeout(bind_timeout, recv.read_exact(&mut bind_buf)).await;

                        match read_result {
                            Ok(Ok(_)) => {
                                // Decode and verify the StreamBind
                                match StreamBind::decode(&bind_buf) {
                                    Some(bind) if bind.logical_stream_id == logical_stream_id => {
                                        info!(
                                            request_id,
                                            logical_stream_id, "stream bound successfully"
                                        );
                                        Ok((send, recv))
                                    }
                                    Some(bind) => {
                                        warn!(
                                            request_id,
                                            expected = logical_stream_id,
                                            received = bind.logical_stream_id,
                                            "stream bind ID mismatch"
                                        );
                                        Err(Error::protocol_violation(format!(
                                            "stream bind ID mismatch: expected {}, got {}",
                                            logical_stream_id, bind.logical_stream_id
                                        )))
                                    }
                                    None => {
                                        warn!(request_id, "invalid stream bind frame");
                                        Err(Error::protocol_violation("invalid stream bind frame"))
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                warn!(request_id, error = %e, "failed to read stream bind");
                                Err(Error::Transport(Box::new(e)))
                            }
                            Err(_) => {
                                warn!(request_id, "timeout reading stream bind");
                                Err(Error::Timeout(TimeoutKind::StreamBind))
                            }
                        }
                    }
                    Ok(Ok(None)) => Err(Error::protocol_violation(
                        "connection closed while waiting for stream",
                    )),
                    Ok(Err(e)) => Err(Error::Transport(Box::new(e))),
                    Err(_) => Err(Error::Timeout(TimeoutKind::StreamBind)),
                }
            }
            OpenResult::Rejected { code, reason } => {
                warn!(request_id, ?code, ?reason, "open request rejected");
                Err(Error::StreamRejected { code, reason })
            }
        }
    }

    /// Accepts an incoming open request.
    ///
    /// Call this in response to a [`ClientEvent::OpenRequest`] event.
    /// After calling this, open a data stream back to the peer using
    /// the underlying connection.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the response fails.
    pub async fn accept_open(&self, request_id: u64, logical_stream_id: u64) -> Result<(), Error> {
        let mut writer = self.writer.lock().await;
        let response = OpenResponse::accepted(request_id, logical_stream_id);
        writer
            .write_message(&ProtocolMessage::OpenResponse(response))
            .await?;
        writer.flush().await
    }

    /// Rejects an incoming open request.
    ///
    /// Call this in response to a [`ClientEvent::OpenRequest`] event
    /// when you cannot or do not want to handle the request.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the response fails.
    pub async fn reject_open(
        &self,
        request_id: u64,
        code: RejectCode,
        reason: Option<String>,
    ) -> Result<(), Error> {
        let mut writer = self.writer.lock().await;
        let response = OpenResponse::rejected(request_id, code, reason);
        writer
            .write_message(&ProtocolMessage::OpenResponse(response))
            .await?;
        writer.flush().await
    }

    /// Binds a data stream to a logical stream ID.
    ///
    /// After accepting an open request with [`accept_open`](Self::accept_open),
    /// open a bidirectional stream and call this method to bind it to the
    /// logical stream ID you provided. The peer will verify the binding before
    /// using the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the bind frame fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // After receiving ClientEvent::OpenRequest { request_id, service, .. }
    /// client.accept_open(request_id, stream_id).await?;
    ///
    /// // Open the data stream and bind it
    /// let (mut send, recv) = connection.open_bi().await?;
    /// client.bind_stream(&mut send, stream_id).await?;
    ///
    /// // Now the stream is ready for use
    /// ```
    pub async fn bind_stream<S: tokio::io::AsyncWriteExt + Unpin>(
        &self,
        send: &mut S,
        logical_stream_id: u64,
    ) -> Result<(), Error> {
        let bind_frame = StreamBind::new(logical_stream_id);
        send.write_all(&bind_frame.encode())
            .await
            .map_err(|e| Error::Transport(Box::new(e)))?;
        send.flush()
            .await
            .map_err(|e| Error::Transport(Box::new(e)))?;
        Ok(())
    }

    /// Sends a ping and waits for the pong response.
    ///
    /// Returns the round-trip time on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is closed, sending fails, or the ping times out.
    pub async fn ping(&self) -> Result<Duration, Error> {
        if !self.is_ready() {
            return Err(Error::SessionClosed);
        }

        let sequence = self.inner.next_ping_seq.fetch_add(1, Ordering::SeqCst);
        let (response_tx, response_rx) = oneshot::channel();
        let sent_at = Instant::now();

        // Register pending ping
        {
            let mut pending = self.inner.pending_pings.lock().unwrap();
            pending.insert(
                sequence,
                PendingPing {
                    sent_at,
                    response_tx,
                },
            );
        }

        // Send the ping
        {
            let mut writer = self.writer.lock().await;
            let ping = quic_reverse_control::Ping { sequence };
            writer.write_message(&ProtocolMessage::Ping(ping)).await?;
            writer.flush().await?;
        }

        // Wait for pong with timeout
        let ping_timeout = self.inner.config.ping_timeout;
        match timeout(ping_timeout, response_rx).await {
            Ok(Ok(())) => {
                let rtt = sent_at.elapsed();
                debug!(sequence, ?rtt, "ping completed");
                Ok(rtt)
            }
            Ok(Err(_)) => Err(Error::SessionClosed),
            Err(_) => {
                let mut pending = self.inner.pending_pings.lock().unwrap();
                pending.remove(&sequence);
                Err(Error::Timeout(TimeoutKind::Ping))
            }
        }
    }

    /// Closes the session gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the close message fails.
    pub async fn close(&self, code: CloseCode, reason: Option<String>) -> Result<(), Error> {
        self.inner
            .state
            .store(State::Closing as u8, Ordering::SeqCst);

        let mut writer = self.writer.lock().await;
        let close_msg = StreamClose {
            logical_stream_id: 0,
            code,
            reason,
        };
        writer
            .write_message(&ProtocolMessage::StreamClose(close_msg))
            .await?;
        writer.flush().await
    }

    /// Notifies the peer that a stream has been closed.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the close message fails.
    pub async fn close_stream(
        &self,
        logical_stream_id: u64,
        code: CloseCode,
        reason: Option<String>,
    ) -> Result<(), Error> {
        let mut writer = self.writer.lock().await;
        let close_msg = StreamClose {
            logical_stream_id,
            code,
            reason,
        };
        writer
            .write_message(&ProtocolMessage::StreamClose(close_msg))
            .await?;
        writer.flush().await
    }
}

impl<C: Connection> Drop for SessionClient<C> {
    fn drop(&mut self) {
        // Only abort if we're the last reference
        if Arc::strong_count(&self.processor_handle) == 1 {
            self.processor_handle.abort();
        }
    }
}

/// Background message processor.
async fn run_message_processor<C: Connection>(
    inner: Arc<SessionInner<C>>,
    writer: Arc<Mutex<ControlWriter<C::SendStream>>>,
    mut reader: ControlReader<C::RecvStream>,
    event_tx: mpsc::Sender<ClientEvent>,
) {
    debug!("message processor started");
    loop {
        debug!("message processor: waiting for next message");
        match reader.read_message().await {
            Ok(Some(msg)) => {
                debug!(
                    "message processor: received message {:?}",
                    message_type(&msg)
                );
                if let Err(should_break) = handle_message(&inner, &writer, msg, &event_tx).await {
                    if should_break {
                        debug!("message processor: breaking loop");
                        break;
                    }
                }
            }
            Ok(None) => {
                debug!("control stream closed");
                inner.state.store(State::Closed as u8, Ordering::SeqCst);
                break;
            }
            Err(e) => {
                error!("message read error: {}", e);
                inner
                    .state
                    .store(State::Disconnected as u8, Ordering::SeqCst);
                break;
            }
        }
    }
    debug!("message processor exited");
}

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

/// Handles a single incoming message.
/// Returns Ok(()) to continue, Err(true) to break, Err(false) to continue with warning.
async fn handle_message<C: Connection>(
    inner: &Arc<SessionInner<C>>,
    writer: &Arc<Mutex<ControlWriter<C::SendStream>>>,
    msg: ProtocolMessage,
    event_tx: &mpsc::Sender<ClientEvent>,
) -> Result<(), bool> {
    match msg {
        ProtocolMessage::OpenRequest(req) => {
            // Peer wants to open a stream to us
            let _ = event_tx
                .send(ClientEvent::OpenRequest {
                    request_id: req.request_id,
                    service: req.service,
                    metadata: req.metadata,
                })
                .await;
            Ok(())
        }

        ProtocolMessage::OpenResponse(resp) => {
            // Response to one of our open requests
            let mut registry = inner.registry.lock().unwrap();
            if let Some(pending) = registry.take_pending(resp.request_id) {
                let result = match resp.status {
                    OpenStatus::Accepted => OpenResult::Accepted {
                        logical_stream_id: resp.logical_stream_id.unwrap_or(0),
                    },
                    OpenStatus::Rejected(code) => OpenResult::Rejected {
                        code,
                        reason: resp.reason,
                    },
                };
                let _ = pending.response_tx.send(result);
            }
            Ok(())
        }

        ProtocolMessage::Ping(ping) => {
            // Auto-respond with Pong
            trace!(sequence = ping.sequence, "received ping, sending pong");
            let mut w = writer.lock().await;
            let pong = quic_reverse_control::Pong {
                sequence: ping.sequence,
            };
            if let Err(e) = w.write_message(&ProtocolMessage::Pong(pong)).await {
                warn!("failed to send pong: {}", e);
            }
            let _ = w.flush().await;

            let _ = event_tx
                .send(ClientEvent::PingReceived {
                    sequence: ping.sequence,
                })
                .await;
            Ok(())
        }

        ProtocolMessage::Pong(pong) => {
            // Resolve pending ping
            let mut pending = inner.pending_pings.lock().unwrap();
            if let Some(pending_ping) = pending.remove(&pong.sequence) {
                let _ = pending_ping.response_tx.send(());
            }
            Ok(())
        }

        ProtocolMessage::StreamClose(sc) => {
            if sc.logical_stream_id == 0 {
                // Session-level close
                info!(code = ?sc.code, reason = ?sc.reason, "peer closed session");
                inner.state.store(State::Closing as u8, Ordering::SeqCst);
                let _ = event_tx
                    .send(ClientEvent::Closing {
                        code: sc.code,
                        reason: sc.reason,
                    })
                    .await;
                Err(true) // Break the loop
            } else {
                // Stream-level close
                let _ = event_tx
                    .send(ClientEvent::StreamClosed {
                        logical_stream_id: sc.logical_stream_id,
                        code: sc.code,
                    })
                    .await;
                Ok(())
            }
        }

        ProtocolMessage::Hello(_) | ProtocolMessage::HelloAck(_) => {
            warn!("received unexpected Hello/HelloAck after negotiation");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Role, Session};
    use quic_reverse_transport::mock_connection_pair;

    async fn create_session_pair() -> (
        SessionHandle<quic_reverse_transport::MockConnection>,
        SessionHandle<quic_reverse_transport::MockConnection>,
    ) {
        let (conn_client, conn_server) = mock_connection_pair();

        let client_session = Session::new(conn_client, Role::Client, Config::new());
        let server_session = Session::new(conn_server, Role::Server, Config::new());

        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let client_handle = client_start.await.unwrap().unwrap();
        let server_handle = server_start.await.unwrap().unwrap();

        (client_handle, server_handle)
    }

    #[tokio::test]
    async fn client_creation() {
        let (client_handle, _server_handle) = create_session_pair().await;

        let client = SessionClient::new(client_handle);
        assert!(client.is_ready());
    }

    #[tokio::test]
    async fn client_is_cloneable() {
        let (client_handle, _server_handle) = create_session_pair().await;

        let client = SessionClient::new(client_handle);
        let client2 = client.clone();

        assert!(client.is_ready());
        assert!(client2.is_ready());
    }

    #[tokio::test]
    async fn ping_pong_via_client() {
        let (client_handle, server_handle) = create_session_pair().await;

        let client = SessionClient::new(client_handle);
        let _server = SessionClient::new(server_handle);

        // Give the server's message processor time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        let rtt = client.ping().await.expect("ping should succeed");
        assert!(rtt < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn open_and_accept_stream() {
        let (client_handle, server_handle) = create_session_pair().await;

        // Server (edge) will handle open requests
        let (server_client, mut server_events) = SessionClient::with_events(server_handle);
        let server_conn = server_client.connection().clone();

        // Spawn server event handler
        let server_task = tokio::spawn(async move {
            while let Some(event) = server_events.recv().await {
                if let ClientEvent::OpenRequest {
                    request_id,
                    service,
                    ..
                } = event
                {
                    if service.as_str() == "echo" {
                        let logical_stream_id = 1;
                        server_client
                            .accept_open(request_id, logical_stream_id)
                            .await
                            .unwrap();

                        // Open data stream and bind it
                        let (mut send, mut recv) = server_conn.open_bi().await.unwrap();
                        server_client
                            .bind_stream(&mut send, logical_stream_id)
                            .await
                            .unwrap();

                        // Echo one message
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 32];
                        let n = recv.read(&mut buf).await.unwrap();
                        send.write_all(&buf[..n]).await.unwrap();
                        send.flush().await.unwrap();
                        break;
                    }
                }
            }
        });

        // Client opens a stream
        let client = SessionClient::new(client_handle);

        // Small delay to ensure server is ready
        tokio::time::sleep(Duration::from_millis(10)).await;

        let (mut send, mut recv) = client
            .open("echo", Metadata::Empty)
            .await
            .expect("open should succeed");

        // Exchange data
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        send.write_all(b"hello").await.unwrap();
        send.flush().await.unwrap();

        let mut buf = [0u8; 32];
        let n = recv.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn reject_unknown_service() {
        let (client_handle, server_handle) = create_session_pair().await;

        // Server rejects unknown services
        let (server_client, mut server_events) = SessionClient::with_events(server_handle);

        let server_task = tokio::spawn(async move {
            while let Some(event) = server_events.recv().await {
                if let ClientEvent::OpenRequest {
                    request_id,
                    service,
                    ..
                } = event
                {
                    server_client
                        .reject_open(
                            request_id,
                            RejectCode::UnsupportedService,
                            Some(format!("unknown: {}", service.as_str())),
                        )
                        .await
                        .unwrap();
                    break;
                }
            }
        });

        let client = SessionClient::new(client_handle);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = client.open("foobar", Metadata::Empty).await;
        assert!(matches!(result, Err(Error::StreamRejected { .. })));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn graceful_close() {
        let (client_handle, server_handle) = create_session_pair().await;

        let (_server_client, mut server_events) = SessionClient::with_events(server_handle);
        let client = SessionClient::new(client_handle);

        // Server listens for close
        let server_task = tokio::spawn(async move {
            while let Some(event) = server_events.recv().await {
                if let ClientEvent::Closing { code, .. } = event {
                    assert_eq!(code, CloseCode::Normal);
                    break;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        client
            .close(CloseCode::Normal, Some("goodbye".into()))
            .await
            .unwrap();

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn stream_bind_mismatch_rejected() {
        let (client_handle, server_handle) = create_session_pair().await;

        // Server will accept but bind with wrong ID
        let (server_client, mut server_events) = SessionClient::with_events(server_handle);
        let server_conn = server_client.connection().clone();

        let server_task = tokio::spawn(async move {
            while let Some(event) = server_events.recv().await {
                if let ClientEvent::OpenRequest {
                    request_id,
                    service,
                    ..
                } = event
                {
                    if service.as_str() == "test" {
                        // Accept with logical_stream_id=1
                        server_client.accept_open(request_id, 1).await.unwrap();

                        // But bind with wrong ID (99)
                        let (mut send, _recv) = server_conn.open_bi().await.unwrap();
                        server_client.bind_stream(&mut send, 99).await.unwrap();
                        break;
                    }
                }
            }
        });

        let client = SessionClient::new(client_handle);
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should fail because stream bind ID doesn't match
        let result = client.open("test", Metadata::Empty).await;
        assert!(matches!(result, Err(Error::ProtocolViolation { .. })));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn stream_bind_invalid_magic_rejected() {
        let (client_handle, server_handle) = create_session_pair().await;

        // Server will send garbage instead of StreamBind
        let (server_client, mut server_events) = SessionClient::with_events(server_handle);
        let server_conn = server_client.connection().clone();

        let server_task = tokio::spawn(async move {
            while let Some(event) = server_events.recv().await {
                if let ClientEvent::OpenRequest {
                    request_id,
                    service,
                    ..
                } = event
                {
                    if service.as_str() == "test" {
                        server_client.accept_open(request_id, 1).await.unwrap();

                        // Send garbage instead of valid StreamBind
                        let (mut send, _recv) = server_conn.open_bi().await.unwrap();
                        use tokio::io::AsyncWriteExt;
                        send.write_all(&[0u8; StreamBind::ENCODED_SIZE])
                            .await
                            .unwrap();
                        send.flush().await.unwrap();
                        break;
                    }
                }
            }
        });

        let client = SessionClient::new(client_handle);
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should fail because stream bind is invalid
        let result = client.open("test", Metadata::Empty).await;
        assert!(matches!(result, Err(Error::ProtocolViolation { .. })));

        server_task.await.unwrap();
    }
}
