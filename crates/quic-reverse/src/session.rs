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

//! Session management for quic-reverse.
//!
//! The `Session` type wraps a QUIC connection and provides the high-level API
//! for reverse-initiated stream operations.

use crate::control::{ControlReader, ControlStream, ControlWriter};
use crate::error::TimeoutKind;
use crate::negotiation::{negotiate_client, negotiate_server, NegotiatedParams};
use crate::registry::{OpenResult, StreamRegistry};
use crate::state::State;
use crate::{Config, Error, Role};
use quic_reverse_control::{
    CloseCode, Metadata, OpenRequest, OpenResponse, OpenStatus, ProtocolMessage, RejectCode,
    ServiceId, StreamClose,
};
use quic_reverse_transport::Connection;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, trace, warn};

/// Inner session state shared between [`Session`] and [`SessionHandle`].
pub(crate) struct SessionInner<C: Connection> {
    /// The underlying QUIC connection.
    pub(crate) connection: C,
    /// Session configuration.
    pub(crate) config: Config,
    /// Our role in the session.
    pub(crate) role: Role,
    /// Current session state.
    pub(crate) state: AtomicU8,
    /// Parameters from successful negotiation.
    pub(crate) negotiated: Mutex<Option<NegotiatedParams>>,
    /// Registry for tracking streams.
    pub(crate) registry: Mutex<StreamRegistry>,
    /// Next ping sequence number.
    pub(crate) next_ping_seq: AtomicU64,
    /// Pending pings awaiting pong responses.
    pub(crate) pending_pings: Mutex<HashMap<u64, PendingPing>>,
}

/// A pending ping awaiting a pong response.
pub(crate) struct PendingPing {
    /// When the ping was sent.
    pub(crate) sent_at: Instant,
    /// Channel to notify when pong is received.
    pub(crate) response_tx: oneshot::Sender<()>,
}

/// A quic-reverse session over a QUIC connection.
///
/// The session provides the main API for:
/// - Initiating reverse streams to the peer
/// - Accepting incoming stream requests from the peer
/// - Managing the session lifecycle
///
/// # Example
///
/// ```ignore
/// use quic_reverse::{Session, Config, Role};
///
/// // Create a session as the client
/// let session = Session::new(connection, Role::Client, Config::default());
///
/// // Start the session (performs negotiation)
/// let mut handle = session.start().await?;
///
/// // Open a reverse stream
/// let (send, recv) = handle.open("ssh", Metadata::Empty).await?;
/// ```
pub struct Session<C: Connection> {
    inner: Arc<SessionInner<C>>,
}

impl<C: Connection> Clone for Session<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C: Connection> Session<C> {
    /// Creates a new session wrapping the given connection.
    ///
    /// The session starts in the `Init` state. Call [`start`](Self::start)
    /// to begin negotiation.
    #[must_use]
    pub fn new(connection: C, role: Role, config: Config) -> Self {
        let registry =
            StreamRegistry::new(config.max_inflight_opens, config.max_concurrent_streams);

        debug!(
            %role,
            max_inflight = config.max_inflight_opens,
            max_concurrent = config.max_concurrent_streams,
            "session created"
        );

        Self {
            inner: Arc::new(SessionInner {
                connection,
                config,
                role,
                state: AtomicU8::new(State::Init as u8),
                negotiated: Mutex::new(None),
                registry: Mutex::new(registry),
                next_ping_seq: AtomicU64::new(1),
                pending_pings: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Returns the current session state.
    #[must_use]
    pub fn state(&self) -> State {
        State::from_u8(self.inner.state.load(Ordering::SeqCst))
    }

    /// Returns the session role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.inner.role
    }

    /// Returns the negotiated parameters, if negotiation has completed.
    #[must_use]
    pub fn negotiated_params(&self) -> Option<NegotiatedParams> {
        self.inner.negotiated.lock().unwrap().clone()
    }

    /// Returns true if the session is ready for stream operations.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state() == State::Ready
    }

    /// Returns true if the connection was lost.
    #[must_use]
    pub fn is_disconnected(&self) -> bool {
        self.state() == State::Disconnected
    }

    /// Returns a reference to the underlying connection.
    #[must_use]
    pub fn connection(&self) -> &C {
        &self.inner.connection
    }

    /// Starts the session by performing negotiation.
    ///
    /// This opens the control stream and performs the `Hello`/`HelloAck`
    /// handshake with the peer. On success, the session transitions
    /// to the `Ready` state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The control stream cannot be opened/accepted
    /// - Negotiation fails (version mismatch, timeout, etc.)
    /// - The session is not in the `Init` state
    #[instrument(skip(self), fields(role = %self.inner.role))]
    pub async fn start(&self) -> Result<SessionHandle<C>, Error> {
        // Validate we're in Init state
        if self.state() != State::Init {
            warn!(state = %self.state(), "cannot start session in non-init state");
            return Err(Error::protocol_violation(format!(
                "cannot start session in {} state",
                self.state()
            )));
        }

        // Validate config
        self.inner.config.validate()?;

        // Transition to Negotiating
        self.set_state(State::Negotiating);
        debug!("transitioning to negotiating state");

        // Open or accept the control stream based on role
        let (control_send, control_recv) = match self.inner.role {
            Role::Client => {
                // Client opens the control stream
                debug!("opening control stream");
                self.inner.connection.open_bi().await.map_err(|e| {
                    error!(error = %e, "failed to open control stream");
                    Error::Transport(Box::new(e))
                })?
            }
            Role::Server => {
                // Server accepts the control stream
                debug!("waiting for control stream");
                self.inner
                    .connection
                    .accept_bi()
                    .await
                    .map_err(|e| {
                        error!(error = %e, "failed to accept control stream");
                        Error::Transport(Box::new(e))
                    })?
                    .ok_or_else(|| {
                        error!("connection closed before control stream");
                        Error::protocol_violation("connection closed before control stream")
                    })?
            }
        };

        let mut control = ControlStream::new(control_send, control_recv);
        debug!("control stream established");

        // Perform negotiation with timeout
        let negotiation_timeout = self.inner.config.negotiation_timeout;
        debug!(?negotiation_timeout, "starting negotiation");

        let negotiate_result = match self.inner.role {
            Role::Client => {
                timeout(
                    negotiation_timeout,
                    negotiate_client(&mut control, &self.inner.config),
                )
                .await
            }
            Role::Server => {
                timeout(
                    negotiation_timeout,
                    negotiate_server(&mut control, &self.inner.config),
                )
                .await
            }
        };

        let params = if let Ok(result) = negotiate_result {
            result?
        } else {
            warn!("negotiation timed out");
            self.set_state(State::Closed);
            return Err(Error::Timeout(TimeoutKind::Negotiation));
        };

        // Store negotiated parameters
        info!(
            version = params.version,
            features = ?params.features,
            remote_agent = ?params.remote_agent,
            "negotiation complete"
        );
        *self.inner.negotiated.lock().unwrap() = Some(params);

        // Transition to Ready
        self.set_state(State::Ready);
        info!("session ready");

        // Split the control stream for the session handle
        let (writer, reader) = control.split();

        Ok(SessionHandle {
            inner: Arc::clone(&self.inner),
            writer,
            reader,
        })
    }

    /// Sets the session state.
    fn set_state(&self, state: State) {
        self.inner.state.store(state as u8, Ordering::SeqCst);
    }
}

/// Active session handle with control stream access.
///
/// This handle is returned from [`Session::start`] and provides
/// methods for stream operations and message processing.
///
/// For a more convenient API that supports concurrent operations,
/// wrap this handle in a [`SessionClient`](crate::SessionClient) using
/// [`SessionClient::new`](crate::SessionClient::new).
pub struct SessionHandle<C: Connection> {
    pub(crate) inner: Arc<SessionInner<C>>,
    pub(crate) writer: ControlWriter<C::SendStream>,
    pub(crate) reader: ControlReader<C::RecvStream>,
}

impl<C: Connection> SessionHandle<C> {
    /// Returns the session state.
    #[must_use]
    pub fn state(&self) -> State {
        State::from_u8(self.inner.state.load(Ordering::SeqCst))
    }

    /// Returns the negotiated parameters.
    #[must_use]
    pub fn negotiated_params(&self) -> Option<NegotiatedParams> {
        self.inner.negotiated.lock().unwrap().clone()
    }

    /// Returns true if the session is ready for stream operations.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state() == State::Ready
    }

    /// Returns true if the connection was lost.
    #[must_use]
    pub fn is_disconnected(&self) -> bool {
        self.state() == State::Disconnected
    }

    /// Opens a reverse stream to the peer.
    ///
    /// Sends an `OpenRequest` for the specified service and waits for
    /// the peer to accept and bind the stream.
    ///
    /// # Arguments
    ///
    /// * `service` - The service identifier
    /// * `metadata` - Optional metadata to send with the request
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session is not ready
    /// - The request limit has been reached
    /// - The peer rejects the request
    /// - The request times out
    #[instrument(skip(self, metadata), fields(service = %service.as_ref()))]
    pub async fn open(
        &mut self,
        service: impl Into<ServiceId> + AsRef<str>,
        metadata: Metadata,
    ) -> Result<(C::SendStream, C::RecvStream), Error> {
        if !self.is_ready() {
            warn!("cannot open stream: session not ready");
            return Err(Error::SessionClosed);
        }

        let service = service.into();

        // Generate request ID and create pending entry
        let (response_tx, response_rx) = oneshot::channel();
        let request_id = {
            let mut registry = self.inner.registry.lock().unwrap();
            let request_id = registry.next_request_id();
            let request =
                OpenRequest::new(request_id, service.clone()).with_metadata(metadata.clone());

            if registry.register_pending(&request, response_tx).is_none() {
                warn!(
                    request_id,
                    "capacity exceeded: too many pending open requests"
                );
                return Err(Error::CapacityExceeded("too many pending open requests"));
            }

            request_id
        };

        debug!(request_id, service = %service.as_str(), "sending open request");

        // Send the open request
        let request = OpenRequest::new(request_id, service).with_metadata(metadata);
        self.writer
            .write_message(&ProtocolMessage::OpenRequest(request))
            .await?;
        self.writer.flush().await?;

        // Wait for the response with timeout
        let open_timeout = self.inner.config.open_timeout;
        let result = match timeout(open_timeout, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                // Channel closed - session closed
                // Clean up the pending entry
                warn!(request_id, "session closed while waiting for response");
                let mut registry = self.inner.registry.lock().unwrap();
                registry.take_pending(request_id);
                return Err(Error::SessionClosed);
            }
            Err(_) => {
                // Timeout - clean up the pending entry
                warn!(request_id, ?open_timeout, "open request timed out");
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

                let (send, recv) = match stream_result {
                    Ok(Ok(Some(streams))) => streams,
                    Ok(Ok(None)) => {
                        error!(request_id, "connection closed while waiting for stream");
                        return Err(Error::protocol_violation(
                            "connection closed while waiting for stream",
                        ));
                    }
                    Ok(Err(e)) => {
                        error!(request_id, error = %e, "transport error while binding stream");
                        return Err(Error::Transport(Box::new(e)));
                    }
                    Err(_) => {
                        warn!(request_id, ?bind_timeout, "stream bind timed out");
                        return Err(Error::Timeout(TimeoutKind::StreamBind));
                    }
                };

                // Register the active stream
                {
                    let mut registry = self.inner.registry.lock().unwrap();
                    registry.register_active(
                        logical_stream_id,
                        ServiceId::from(""),
                        Metadata::Empty,
                        request_id,
                    );
                }

                info!(request_id, logical_stream_id, "stream opened successfully");
                Ok((send, recv))
            }
            OpenResult::Rejected { code, reason } => {
                warn!(request_id, ?code, ?reason, "open request rejected");
                Err(Error::StreamRejected { code, reason })
            }
        }
    }

    /// Processes the next incoming control message.
    ///
    /// This should be called in a loop to handle incoming messages
    /// from the peer. Returns `None` when the control stream closes.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the control stream fails.
    pub async fn process_message(&mut self) -> Result<Option<ControlEvent>, Error> {
        let Some(message) = self.reader.read_message().await? else {
            debug!("control stream closed");
            return Ok(None);
        };

        match message {
            ProtocolMessage::OpenRequest(req) => {
                // Peer wants to open a stream to us
                debug!(
                    request_id = req.request_id,
                    service = %req.service.as_str(),
                    "received open request"
                );
                Ok(Some(ControlEvent::OpenRequest {
                    request_id: req.request_id,
                    service: req.service,
                    metadata: req.metadata,
                }))
            }

            ProtocolMessage::OpenResponse(resp) => {
                // Response to one of our open requests
                let accepted = matches!(resp.status, OpenStatus::Accepted);
                debug!(
                    request_id = resp.request_id,
                    accepted,
                    logical_stream_id = ?resp.logical_stream_id,
                    "received open response"
                );
                let mut registry = self.inner.registry.lock().unwrap();
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
                Ok(Some(ControlEvent::OpenResponseReceived {
                    request_id: resp.request_id,
                    accepted,
                }))
            }

            ProtocolMessage::Ping(ping_msg) => {
                // Auto-respond with Pong
                trace!(sequence = ping_msg.sequence, "received ping, sending pong");
                let pong_msg = quic_reverse_control::Pong {
                    sequence: ping_msg.sequence,
                };
                self.writer
                    .write_message(&ProtocolMessage::Pong(pong_msg))
                    .await?;
                self.writer.flush().await?;
                Ok(Some(ControlEvent::Ping {
                    sequence: ping_msg.sequence,
                }))
            }

            ProtocolMessage::Pong(pong) => {
                // Resolve pending ping if any
                trace!(sequence = pong.sequence, "received pong");
                let mut pending = self.inner.pending_pings.lock().unwrap();
                if let Some(pending_ping) = pending.remove(&pong.sequence) {
                    let rtt = pending_ping.sent_at.elapsed();
                    trace!(sequence = pong.sequence, ?rtt, "ping resolved");
                    let _ = pending_ping.response_tx.send(());
                }
                Ok(Some(ControlEvent::Pong {
                    sequence: pong.sequence,
                }))
            }

            ProtocolMessage::Hello(_) | ProtocolMessage::HelloAck(_) => {
                // These should only appear during negotiation
                warn!("received unexpected Hello/HelloAck after negotiation");
                Err(Error::protocol_violation(
                    "unexpected Hello/HelloAck after negotiation",
                ))
            }

            ProtocolMessage::StreamClose(sc) => {
                // logical_stream_id 0 indicates session-level close
                if sc.logical_stream_id == 0 {
                    info!(code = ?sc.code, reason = ?sc.reason, "received session close");
                    self.set_state(State::Closing);
                    Ok(Some(ControlEvent::CloseReceived {
                        code: sc.code,
                        reason: sc.reason,
                    }))
                } else {
                    debug!(
                        logical_stream_id = sc.logical_stream_id,
                        code = ?sc.code,
                        "received stream close"
                    );
                    Ok(Some(ControlEvent::StreamClose {
                        logical_stream_id: sc.logical_stream_id,
                        code: sc.code,
                    }))
                }
            }
        }
    }

    /// Sends an `OpenResponse` accepting a stream request.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the response fails.
    #[instrument(skip(self))]
    pub async fn accept_open(
        &mut self,
        request_id: u64,
        logical_stream_id: u64,
    ) -> Result<(), Error> {
        debug!(request_id, logical_stream_id, "accepting open request");
        let response = OpenResponse::accepted(request_id, logical_stream_id);
        self.writer
            .write_message(&ProtocolMessage::OpenResponse(response))
            .await?;
        self.writer.flush().await
    }

    /// Sends an `OpenResponse` rejecting a stream request.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the response fails.
    #[instrument(skip(self))]
    pub async fn reject_open(
        &mut self,
        request_id: u64,
        code: RejectCode,
        reason: Option<String>,
    ) -> Result<(), Error> {
        debug!(request_id, ?code, ?reason, "rejecting open request");
        let response = OpenResponse::rejected(request_id, code, reason);
        self.writer
            .write_message(&ProtocolMessage::OpenResponse(response))
            .await?;
        self.writer.flush().await
    }

    /// Notifies the peer that a stream has been closed.
    ///
    /// This should be called when the application finishes with a stream
    /// to inform the peer. The peer will receive a `StreamClose` event.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is closed or sending the message fails.
    #[instrument(skip(self))]
    pub async fn close_stream(
        &mut self,
        logical_stream_id: u64,
        code: CloseCode,
        reason: Option<String>,
    ) -> Result<(), Error> {
        if !self.is_ready() {
            warn!(logical_stream_id, "cannot close stream: session not ready");
            return Err(Error::SessionClosed);
        }

        debug!(logical_stream_id, ?code, ?reason, "closing stream");

        // Remove from registry
        {
            let mut registry = self.inner.registry.lock().unwrap();
            registry.remove_active(logical_stream_id);
        }

        let close_msg = StreamClose {
            logical_stream_id,
            code,
            reason,
        };
        self.writer
            .write_message(&ProtocolMessage::StreamClose(close_msg))
            .await?;
        self.writer.flush().await
    }

    /// Sends a ping and waits for the pong response.
    ///
    /// This can be used to check if the peer is still responsive and to
    /// measure round-trip latency. Returns the round-trip time on success.
    ///
    /// # Errors
    ///
    /// Returns `Error::Timeout(TimeoutKind::Ping)` if no pong is received
    /// within the configured `ping_timeout`.
    #[instrument(skip(self))]
    pub async fn ping(&mut self) -> Result<std::time::Duration, Error> {
        if !self.is_ready() {
            warn!("cannot ping: session not ready");
            return Err(Error::SessionClosed);
        }

        // Generate sequence number
        let sequence = self.inner.next_ping_seq.fetch_add(1, Ordering::SeqCst);
        trace!(sequence, "sending ping");

        // Create response channel
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
        let ping_msg = quic_reverse_control::Ping { sequence };
        self.writer
            .write_message(&ProtocolMessage::Ping(ping_msg))
            .await?;
        self.writer.flush().await?;

        // Wait for pong with timeout
        let ping_timeout = self.inner.config.ping_timeout;
        match timeout(ping_timeout, response_rx).await {
            Ok(Ok(())) => {
                let rtt = sent_at.elapsed();
                debug!(sequence, ?rtt, "ping completed");
                Ok(rtt)
            }
            Ok(Err(_)) => {
                // Channel closed - session closed
                warn!(sequence, "session closed while waiting for pong");
                Err(Error::SessionClosed)
            }
            Err(_) => {
                // Timeout - clean up pending ping
                warn!(sequence, ?ping_timeout, "ping timed out");
                let mut pending = self.inner.pending_pings.lock().unwrap();
                pending.remove(&sequence);
                Err(Error::Timeout(TimeoutKind::Ping))
            }
        }
    }

    /// Closes the session.
    ///
    /// Sends a `StreamClose` message with `logical_stream_id` 0 to indicate
    /// session close, and transitions to the `Closing` state.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is already closed or sending the message fails.
    #[instrument(skip(self))]
    pub async fn close(&mut self, code: CloseCode, reason: Option<String>) -> Result<(), Error> {
        if !self.is_ready() && self.state() != State::Closing {
            warn!("cannot close: session already closed");
            return Err(Error::SessionClosed);
        }

        info!(?code, ?reason, "closing session");
        self.set_state(State::Closing);

        // Use logical_stream_id 0 to indicate session-level close
        let close_msg = StreamClose {
            logical_stream_id: 0,
            code,
            reason,
        };
        self.writer
            .write_message(&ProtocolMessage::StreamClose(close_msg))
            .await?;
        self.writer.flush().await
    }

    /// Sets the session state.
    fn set_state(&self, state: State) {
        self.inner.state.store(state as u8, Ordering::SeqCst);
    }
}

/// Events that can occur on the control stream.
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// Peer requested to open a stream.
    OpenRequest {
        /// The request ID.
        request_id: u64,
        /// The requested service.
        service: ServiceId,
        /// Metadata from the request.
        metadata: Metadata,
    },
    /// Response to our open request was received.
    OpenResponseReceived {
        /// The request ID this is responding to.
        request_id: u64,
        /// Whether the request was accepted.
        accepted: bool,
    },
    /// Peer initiated close.
    CloseReceived {
        /// The close code.
        code: CloseCode,
        /// Optional reason string.
        reason: Option<String>,
    },
    /// Ping received (pong auto-sent).
    Ping {
        /// The ping sequence number.
        sequence: u64,
    },
    /// Pong received in response to our ping.
    Pong {
        /// The pong sequence number.
        sequence: u64,
    },
    /// Stream close notification.
    StreamClose {
        /// The logical stream ID being closed.
        logical_stream_id: u64,
        /// The close code.
        code: CloseCode,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use quic_reverse_control::Features;
    use quic_reverse_transport::mock_connection_pair;

    #[tokio::test]
    async fn session_creation() {
        let (conn_client, _conn_server) = mock_connection_pair();

        let config = Config::new()
            .with_features(Features::PING_PONG)
            .with_agent("test/1.0");

        let session = Session::new(conn_client, Role::Client, config);

        assert_eq!(session.state(), State::Init);
        assert_eq!(session.role(), Role::Client);
        assert!(session.negotiated_params().is_none());
    }

    #[tokio::test]
    async fn session_start_and_negotiate() {
        let (conn_client, conn_server) = mock_connection_pair();

        let client_config = Config::new()
            .with_features(Features::PING_PONG)
            .with_agent("client/1.0");

        let server_config = Config::new()
            .with_features(Features::PING_PONG)
            .with_agent("server/1.0");

        let client_session = Session::new(conn_client, Role::Client, client_config);
        let server_session = Session::new(conn_server, Role::Server, server_config);

        // Keep references for later assertions
        let client_session_ref = client_session.clone();
        let server_session_ref = server_session.clone();

        // Start both sessions concurrently
        let client_handle = tokio::spawn(async move { client_session.start().await });
        let server_handle = tokio::spawn(async move { server_session.start().await });

        // Wait for both to complete
        let client_result = client_handle.await.expect("client task");
        let server_result = server_handle.await.expect("server task");

        // Both should succeed
        assert!(client_result.is_ok(), "client failed");
        assert!(server_result.is_ok(), "server failed");

        // Both should be in Ready state
        assert_eq!(client_session_ref.state(), State::Ready);
        assert_eq!(server_session_ref.state(), State::Ready);

        // Both should have negotiated params
        let client_params = client_session_ref
            .negotiated_params()
            .expect("client params");
        let server_params = server_session_ref
            .negotiated_params()
            .expect("server params");

        assert_eq!(client_params.version, server_params.version);
        assert_eq!(client_params.features, Features::PING_PONG);

        // Should see each other's agent strings
        assert_eq!(client_params.remote_agent.as_deref(), Some("server/1.0"));
        assert_eq!(server_params.remote_agent.as_deref(), Some("client/1.0"));
    }

    #[tokio::test]
    async fn cannot_start_twice() {
        let (conn_client, conn_server) = mock_connection_pair();

        let client_session = Session::new(conn_client, Role::Client, Config::new());
        let server_session = Session::new(conn_server, Role::Server, Config::new());

        // Keep reference for later
        let client_session_ref = client_session.clone();

        // Start both
        let client_handle = tokio::spawn(async move { client_session.start().await });
        let server_handle = tokio::spawn(async move { server_session.start().await });

        let _ = client_handle.await;
        let _ = server_handle.await;

        // Try to start again - should fail
        let result = client_session_ref.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ping_pong_exchange() {
        let (conn_client, conn_server) = mock_connection_pair();

        let config = Config::new().with_features(Features::PING_PONG);

        let client_session = Session::new(conn_client, Role::Client, config.clone());
        let server_session = Session::new(conn_server, Role::Server, config);

        // Start both and get handles
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let mut client_handle = client_start.await.unwrap().unwrap();
        let mut server_handle = server_start.await.unwrap().unwrap();

        // Send a ping from client
        let ping = quic_reverse_control::Ping { sequence: 42 };
        client_handle
            .writer
            .write_message(&ProtocolMessage::Ping(ping))
            .await
            .unwrap();
        client_handle.writer.flush().await.unwrap();

        // Server should receive it and auto-respond
        let event = server_handle.process_message().await.unwrap().unwrap();
        assert!(matches!(event, ControlEvent::Ping { sequence: 42 }));

        // Client should receive the pong
        let event = client_handle.process_message().await.unwrap().unwrap();
        assert!(matches!(event, ControlEvent::Pong { sequence: 42 }));
    }

    #[tokio::test]
    async fn close_session() {
        let (conn_client, conn_server) = mock_connection_pair();

        let client_session = Session::new(conn_client, Role::Client, Config::new());
        let server_session = Session::new(conn_server, Role::Server, Config::new());

        // Keep references
        let client_session_ref = client_session.clone();
        let server_session_ref = server_session.clone();

        // Start both
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let mut client_handle = client_start.await.unwrap().unwrap();
        let mut server_handle = server_start.await.unwrap().unwrap();

        // Client initiates close
        client_handle
            .close(CloseCode::Normal, Some("goodbye".into()))
            .await
            .unwrap();

        // Server receives close event
        let event = server_handle.process_message().await.unwrap().unwrap();
        match event {
            ControlEvent::CloseReceived { code, reason } => {
                assert_eq!(code, CloseCode::Normal);
                assert_eq!(reason.as_deref(), Some("goodbye"));
            }
            _ => panic!("expected CloseReceived"),
        }

        assert_eq!(client_session_ref.state(), State::Closing);
        assert_eq!(server_session_ref.state(), State::Closing);
    }

    #[tokio::test]
    async fn stream_open_and_accept() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::mpsc;

        let (conn_client, conn_server) = mock_connection_pair();

        let client_session = Session::new(conn_client, Role::Client, Config::new());
        let server_session = Session::new(conn_server, Role::Server, Config::new());

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let client_handle = client_start.await.unwrap().unwrap();
        let mut server_handle = server_start.await.unwrap().unwrap();

        // Split client handle for concurrent message processing and open
        // We need channels to coordinate between the two client tasks
        let (open_done_tx, mut open_done_rx) = mpsc::channel::<(
            quic_reverse_transport::MockSendStream,
            quic_reverse_transport::MockRecvStream,
        )>(1);

        // Client: Spawn message processor that will receive the OpenResponse
        let client_inner = Arc::clone(&client_handle.inner);
        let mut client_reader = client_handle.reader;
        let client_msg_processor = tokio::spawn(async move {
            // Wait for OpenResponse
            let msg = client_reader.read_message().await.unwrap().unwrap();
            if let ProtocolMessage::OpenResponse(resp) = msg {
                let accepted = matches!(resp.status, OpenStatus::Accepted);
                let mut registry = client_inner.registry.lock().unwrap();
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
                accepted
            } else {
                panic!("expected OpenResponse");
            }
        });

        // Client: Spawn the open request
        let client_inner2 = Arc::clone(&client_handle.inner);
        let mut client_writer = client_handle.writer;
        let client_open = tokio::spawn(async move {
            // Generate request ID and create pending entry
            let (response_tx, response_rx) = oneshot::channel();
            let request_id = {
                let mut registry = client_inner2.registry.lock().unwrap();
                let request_id = registry.next_request_id();
                let request = OpenRequest::new(request_id, "ssh").with_metadata(Metadata::Empty);
                registry.register_pending(&request, response_tx).unwrap();
                request_id
            };

            // Send the open request
            let request = OpenRequest::new(request_id, "ssh").with_metadata(Metadata::Empty);
            client_writer
                .write_message(&ProtocolMessage::OpenRequest(request))
                .await
                .unwrap();
            client_writer.flush().await.unwrap();

            // Wait for the response (will be delivered by the message processor)
            let result = response_rx.await.unwrap();

            match result {
                OpenResult::Accepted { .. } => {
                    // Accept the data stream
                    let (send, recv) = client_inner2.connection.accept_bi().await.unwrap().unwrap();
                    open_done_tx.send((send, recv)).await.unwrap();
                }
                OpenResult::Rejected { code, reason } => {
                    panic!("rejected: {code:?} {reason:?}");
                }
            }
        });

        // Server: Process the open request
        let event = server_handle.process_message().await.unwrap().unwrap();
        let (request_id, service) = match event {
            ControlEvent::OpenRequest {
                request_id,
                service,
                ..
            } => (request_id, service),
            _ => panic!("expected OpenRequest, got {event:?}"),
        };
        assert_eq!(service.as_str(), "ssh");

        // Server: Accept the request
        let logical_stream_id = 1;
        server_handle
            .accept_open(request_id, logical_stream_id)
            .await
            .unwrap();

        // Server: Open the data stream back to client
        let (mut server_send, mut server_recv) =
            server_handle.inner.connection.open_bi().await.unwrap();

        // Wait for client tasks to complete
        client_msg_processor.await.unwrap();
        client_open.await.unwrap();

        // Get the client streams
        let (mut client_send, mut client_recv) = open_done_rx.recv().await.unwrap();

        // Exchange data bidirectionally
        server_send.write_all(b"hello from server").await.unwrap();
        server_send.flush().await.unwrap();

        let mut buf = [0u8; 32];
        let n = client_recv.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from server");

        client_send.write_all(b"hello from client").await.unwrap();
        client_send.flush().await.unwrap();

        let n = server_recv.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from client");
    }

    #[tokio::test]
    async fn stream_open_rejected() {
        use tokio::sync::mpsc;

        let (conn_client, conn_server) = mock_connection_pair();

        let client_session = Session::new(conn_client, Role::Client, Config::new());
        let server_session = Session::new(conn_server, Role::Server, Config::new());

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let client_handle = client_start.await.unwrap().unwrap();
        let mut server_handle = server_start.await.unwrap().unwrap();

        // Channel to receive the rejection result
        let (result_tx, mut result_rx) = mpsc::channel::<Result<(), Error>>(1);

        // Client: Spawn message processor
        let client_inner = Arc::clone(&client_handle.inner);
        let mut client_reader = client_handle.reader;
        let client_msg_processor = tokio::spawn(async move {
            let msg = client_reader.read_message().await.unwrap().unwrap();
            if let ProtocolMessage::OpenResponse(resp) = msg {
                let mut registry = client_inner.registry.lock().unwrap();
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
            }
        });

        // Client: Spawn the open request
        let client_inner2 = Arc::clone(&client_handle.inner);
        let mut client_writer = client_handle.writer;
        let client_open = tokio::spawn(async move {
            let (response_tx, response_rx) = oneshot::channel();
            let request_id = {
                let mut registry = client_inner2.registry.lock().unwrap();
                let request_id = registry.next_request_id();
                let request =
                    OpenRequest::new(request_id, "unknown").with_metadata(Metadata::Empty);
                registry.register_pending(&request, response_tx).unwrap();
                request_id
            };

            let request = OpenRequest::new(request_id, "unknown").with_metadata(Metadata::Empty);
            client_writer
                .write_message(&ProtocolMessage::OpenRequest(request))
                .await
                .unwrap();
            client_writer.flush().await.unwrap();

            let result = response_rx.await.unwrap();
            match result {
                OpenResult::Accepted { .. } => {
                    result_tx.send(Ok(())).await.unwrap();
                }
                OpenResult::Rejected { code, reason } => {
                    result_tx
                        .send(Err(Error::StreamRejected { code, reason }))
                        .await
                        .unwrap();
                }
            }
        });

        // Server: Process and reject the request
        let event = server_handle.process_message().await.unwrap().unwrap();
        let request_id = match event {
            ControlEvent::OpenRequest { request_id, .. } => request_id,
            _ => panic!("expected OpenRequest"),
        };

        server_handle
            .reject_open(
                request_id,
                RejectCode::UnsupportedService,
                Some("not available".into()),
            )
            .await
            .unwrap();

        // Wait for client tasks
        client_msg_processor.await.unwrap();
        client_open.await.unwrap();

        // Get the rejection result
        let result = result_rx.recv().await.unwrap();
        match result {
            Err(Error::StreamRejected { code, reason }) => {
                assert_eq!(code, RejectCode::UnsupportedService);
                assert_eq!(reason.as_deref(), Some("not available"));
            }
            other => panic!("expected StreamRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_close_notification() {
        use tokio::sync::mpsc;

        let (conn_client, conn_server) = mock_connection_pair();

        let client_session = Session::new(conn_client, Role::Client, Config::new());
        let server_session = Session::new(conn_server, Role::Server, Config::new());

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let client_handle = client_start.await.unwrap().unwrap();
        let mut server_handle = server_start.await.unwrap().unwrap();

        // Set up the stream as before
        let (open_done_tx, mut open_done_rx) = mpsc::channel::<u64>(1);

        // Client: Message processor
        let client_inner = Arc::clone(&client_handle.inner);
        let mut client_reader = client_handle.reader;
        let client_msg_processor = tokio::spawn(async move {
            // First: OpenResponse
            let msg = client_reader.read_message().await.unwrap().unwrap();
            if let ProtocolMessage::OpenResponse(resp) = msg {
                let mut registry = client_inner.registry.lock().unwrap();
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
            }

            // Second: StreamClose
            let msg = client_reader.read_message().await.unwrap().unwrap();
            if let ProtocolMessage::StreamClose(sc) = msg {
                (sc.logical_stream_id, sc.code, sc.reason)
            } else {
                panic!("expected StreamClose");
            }
        });

        // Client: Open request
        let client_inner2 = Arc::clone(&client_handle.inner);
        let mut client_writer = client_handle.writer;
        let client_open = tokio::spawn(async move {
            let (response_tx, response_rx) = oneshot::channel();
            let request_id = {
                let mut registry = client_inner2.registry.lock().unwrap();
                let request_id = registry.next_request_id();
                let request = OpenRequest::new(request_id, "ssh").with_metadata(Metadata::Empty);
                registry.register_pending(&request, response_tx).unwrap();
                request_id
            };

            let request = OpenRequest::new(request_id, "ssh").with_metadata(Metadata::Empty);
            client_writer
                .write_message(&ProtocolMessage::OpenRequest(request))
                .await
                .unwrap();
            client_writer.flush().await.unwrap();

            let result = response_rx.await.unwrap();
            if let OpenResult::Accepted { logical_stream_id } = result {
                open_done_tx.send(logical_stream_id).await.unwrap();
            }
        });

        // Server: Process open request
        let event = server_handle.process_message().await.unwrap().unwrap();
        let request_id = match event {
            ControlEvent::OpenRequest { request_id, .. } => request_id,
            _ => panic!("expected OpenRequest"),
        };

        // Server: Accept
        let logical_stream_id = 42;
        server_handle
            .accept_open(request_id, logical_stream_id)
            .await
            .unwrap();

        // Wait for client to receive the stream ID
        client_open.await.unwrap();
        let received_id = open_done_rx.recv().await.unwrap();
        assert_eq!(received_id, logical_stream_id);

        // Server: Close the stream
        server_handle
            .close_stream(logical_stream_id, CloseCode::Normal, Some("done".into()))
            .await
            .unwrap();

        // Client should receive the close notification
        let (close_id, close_code, close_reason) = client_msg_processor.await.unwrap();
        assert_eq!(close_id, logical_stream_id);
        assert_eq!(close_code, CloseCode::Normal);
        assert_eq!(close_reason.as_deref(), Some("done"));
    }

    #[tokio::test]
    async fn open_respects_inflight_limit() {
        let (conn_client, conn_server) = mock_connection_pair();

        // Configure with a very low limit
        let client_config = Config::new().with_max_inflight_opens(2);
        let server_config = Config::new();

        let client_session = Session::new(conn_client, Role::Client, client_config);
        let server_session = Session::new(conn_server, Role::Server, server_config);

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let client_handle = client_start.await.unwrap().unwrap();
        let _server_handle = server_start.await.unwrap().unwrap();

        // Access the inner directly to simulate multiple pending opens
        let inner = Arc::clone(&client_handle.inner);
        let mut writer = client_handle.writer;

        // Register two pending opens (filling the limit)
        {
            let mut registry = inner.registry.lock().unwrap();
            let (tx1, _rx1) = oneshot::channel();
            let (tx2, _rx2) = oneshot::channel();
            let req1 = OpenRequest::new(1, "service1");
            let req2 = OpenRequest::new(2, "service2");
            assert!(registry.register_pending(&req1, tx1).is_some());
            assert!(registry.register_pending(&req2, tx2).is_some());
        }

        // Try to open a third - should fail with capacity exceeded
        let (response_tx, _response_rx) = oneshot::channel();
        let result = {
            let mut registry = inner.registry.lock().unwrap();
            let request_id = registry.next_request_id();
            let request = OpenRequest::new(request_id, "service3");
            registry.register_pending(&request, response_tx)
        };

        assert!(result.is_none(), "should fail due to limit");

        // Clean up - send a dummy message to prevent hanging
        let _ = writer
            .write_message(&ProtocolMessage::Ping(quic_reverse_control::Ping {
                sequence: 0,
            }))
            .await;
    }

    #[tokio::test]
    async fn open_request_timeout() {
        use std::time::Duration;

        let (conn_client, conn_server) = mock_connection_pair();

        // Configure with a very short timeout
        let client_config = Config::new().with_open_timeout(Duration::from_millis(50));
        let server_config = Config::new();

        let client_session = Session::new(conn_client, Role::Client, client_config);
        let server_session = Session::new(conn_server, Role::Server, server_config);

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let mut client_handle = client_start.await.unwrap().unwrap();
        let _server_handle = server_start.await.unwrap().unwrap();

        // Client tries to open, but server never responds
        let result = client_handle.open("ssh", Metadata::Empty).await;

        // Should timeout
        match result {
            Err(Error::Timeout(TimeoutKind::OpenRequest)) => {}
            other => panic!("expected OpenRequest timeout, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_bind_timeout() {
        use std::time::Duration;

        let (conn_client, conn_server) = mock_connection_pair();

        // Configure with a very short bind timeout
        let client_config = Config::new()
            .with_open_timeout(Duration::from_secs(5))
            .with_stream_bind_timeout(Duration::from_millis(50));
        let server_config = Config::new();

        let client_session = Session::new(conn_client, Role::Client, client_config);
        let server_session = Session::new(conn_server, Role::Server, server_config);

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let client_handle = client_start.await.unwrap().unwrap();
        let mut server_handle = server_start.await.unwrap().unwrap();

        // Split client handle for concurrent operation
        let client_inner_open = Arc::clone(&client_handle.inner);
        let client_inner_msg = Arc::clone(&client_handle.inner);
        let mut client_writer = client_handle.writer;
        let mut client_reader = client_handle.reader;

        // Client: Open request task
        let client_open = tokio::spawn(async move {
            // Send open request manually
            let (response_tx, response_rx) = oneshot::channel();
            let request_id = {
                let mut registry = client_inner_open.registry.lock().unwrap();
                let request_id = registry.next_request_id();
                let request = OpenRequest::new(request_id, "ssh").with_metadata(Metadata::Empty);
                registry.register_pending(&request, response_tx).unwrap();
                request_id
            };

            let request = OpenRequest::new(request_id, "ssh").with_metadata(Metadata::Empty);
            client_writer
                .write_message(&ProtocolMessage::OpenRequest(request))
                .await
                .unwrap();
            client_writer.flush().await.unwrap();

            // Wait for the response
            let result = response_rx.await.unwrap();

            // Try to accept the stream with timeout
            match result {
                OpenResult::Accepted { .. } => {
                    let bind_timeout = Duration::from_millis(50);
                    match timeout(bind_timeout, client_inner_open.connection.accept_bi()).await {
                        Ok(Ok(Some(streams))) => Ok(streams),
                        Ok(Ok(None)) => Err(Error::SessionClosed),
                        Ok(Err(e)) => Err(Error::Transport(Box::new(e))),
                        Err(_) => Err(Error::Timeout(TimeoutKind::StreamBind)),
                    }
                }
                OpenResult::Rejected { code, reason } => {
                    Err(Error::StreamRejected { code, reason })
                }
            }
        });

        // Client: Message processor
        let client_msg_processor = tokio::spawn(async move {
            let msg = client_reader.read_message().await.unwrap().unwrap();
            if let ProtocolMessage::OpenResponse(resp) = msg {
                let mut registry = client_inner_msg.registry.lock().unwrap();
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
            }
        });

        // Server: Accept the request but DON'T open the data stream
        let event = server_handle.process_message().await.unwrap().unwrap();
        let request_id = match event {
            ControlEvent::OpenRequest { request_id, .. } => request_id,
            _ => panic!("expected OpenRequest"),
        };

        // Accept but don't open data stream - client should timeout on bind
        server_handle.accept_open(request_id, 1).await.unwrap();

        // Wait for client message processor
        let _ = client_msg_processor.await;

        // The open task should fail with stream bind timeout
        let result = client_open.await.unwrap();
        match result {
            Err(Error::Timeout(TimeoutKind::StreamBind)) => {}
            other => panic!("expected StreamBind timeout, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn negotiation_timeout() {
        use std::time::Duration;

        let (conn_client, _conn_server) = mock_connection_pair();

        // Configure with a very short negotiation timeout
        let client_config = Config::new().with_negotiation_timeout(Duration::from_millis(50));

        let client_session = Session::new(conn_client, Role::Client, client_config);

        // Client tries to start, but server never responds (no server started)
        let result = client_session.start().await;

        // Should timeout during negotiation
        assert!(
            matches!(result, Err(Error::Timeout(TimeoutKind::Negotiation))),
            "expected Negotiation timeout, got: {:?}",
            result.as_ref().map(|_| "Ok(SessionHandle)")
        );

        // Session should be in Closed state
        assert_eq!(client_session.state(), State::Closed);
    }

    #[tokio::test]
    async fn ping_returns_rtt() {
        use std::time::Duration;

        let (conn_client, conn_server) = mock_connection_pair();

        let client_session = Session::new(conn_client, Role::Client, Config::new());
        let server_session = Session::new(conn_server, Role::Server, Config::new());

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let client_handle = client_start.await.unwrap().unwrap();
        let mut server_handle = server_start.await.unwrap().unwrap();

        // Split client handle for concurrent ping and message processing
        let client_inner = Arc::clone(&client_handle.inner);
        let mut client_writer = client_handle.writer;
        let mut client_reader = client_handle.reader;

        // Client: Send ping task
        let ping_task = tokio::spawn(async move {
            // Generate sequence number
            let sequence = client_inner.next_ping_seq.fetch_add(1, Ordering::SeqCst);

            // Create response channel
            let (response_tx, response_rx) = oneshot::channel();
            let sent_at = Instant::now();

            // Register pending ping
            {
                let mut pending = client_inner.pending_pings.lock().unwrap();
                pending.insert(
                    sequence,
                    PendingPing {
                        sent_at,
                        response_tx,
                    },
                );
            }

            // Send the ping
            let ping_msg = quic_reverse_control::Ping { sequence };
            client_writer
                .write_message(&ProtocolMessage::Ping(ping_msg))
                .await
                .unwrap();
            client_writer.flush().await.unwrap();

            // Wait for pong
            response_rx.await.unwrap();
            sent_at.elapsed()
        });

        // Client: Message processor that receives Pong
        let client_inner2 = Arc::clone(&client_handle.inner);
        let client_msg_processor = tokio::spawn(async move {
            let msg = client_reader.read_message().await.unwrap().unwrap();
            if let ProtocolMessage::Pong(pong) = msg {
                let mut pending = client_inner2.pending_pings.lock().unwrap();
                if let Some(pending_ping) = pending.remove(&pong.sequence) {
                    let _ = pending_ping.response_tx.send(());
                }
            }
        });

        // Server: Process the ping (auto-responds with pong)
        let event = server_handle.process_message().await.unwrap().unwrap();
        assert!(matches!(event, ControlEvent::Ping { sequence: 1 }));

        // Wait for client tasks
        let _ = client_msg_processor.await;
        let rtt = ping_task.await.unwrap();

        // RTT should be positive but small (local mock connection)
        assert!(rtt < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn ping_timeout() {
        use std::time::Duration;

        let (conn_client, conn_server) = mock_connection_pair();

        // Configure with a very short ping timeout
        let client_config = Config::new().with_ping_timeout(Duration::from_millis(50));
        let server_config = Config::new();

        let client_session = Session::new(conn_client, Role::Client, client_config);
        let server_session = Session::new(conn_server, Role::Server, server_config);

        // Start both sessions
        let client_start = tokio::spawn(async move { client_session.start().await });
        let server_start = tokio::spawn(async move { server_session.start().await });

        let mut client_handle = client_start.await.unwrap().unwrap();
        let _server_handle = server_start.await.unwrap().unwrap();

        // Client sends ping, but server never processes it (no pong)
        let result = client_handle.ping().await;

        // Should timeout
        match result {
            Err(Error::Timeout(TimeoutKind::Ping)) => {}
            other => panic!("expected Ping timeout, got: {other:?}"),
        }
    }
}
