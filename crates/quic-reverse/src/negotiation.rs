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

//! Protocol negotiation.
//!
//! Handles the Hello/HelloAck handshake to establish protocol version
//! and feature set.

use crate::control::ControlStream;
use crate::error::NegotiationError;
use crate::Config;
use quic_reverse_control::{Features, Hello, HelloAck, ProtocolMessage, PROTOCOL_VERSION};
use quic_reverse_transport::{RecvStream, SendStream};
use tracing::{debug, instrument, trace, warn};

/// Result of successful negotiation.
#[derive(Debug, Clone)]
pub struct NegotiatedParams {
    /// The negotiated protocol version.
    pub version: u16,
    /// The negotiated feature set (intersection of both peers).
    pub features: Features,
    /// The remote peer's agent string, if provided.
    pub remote_agent: Option<String>,
}

/// Performs the client-side negotiation.
///
/// The client sends `Hello` first, then waits for the server's `Hello`,
/// then sends `HelloAck`.
#[instrument(skip_all, name = "negotiate_client")]
pub async fn negotiate_client<S: SendStream, R: RecvStream>(
    control: &mut ControlStream<S, R>,
    config: &Config,
) -> Result<NegotiatedParams, NegotiationError> {
    // Build our Hello
    let mut our_hello = Hello::new(config.features);
    if let Some(ref agent) = config.agent {
        our_hello = our_hello.with_agent(agent.clone());
    }

    // Send our Hello
    trace!(version = PROTOCOL_VERSION, features = ?config.features, "sending Hello");
    control
        .write_message(&ProtocolMessage::Hello(our_hello))
        .await
        .map_err(|_| NegotiationError::Timeout)?;
    control
        .flush()
        .await
        .map_err(|_| NegotiationError::Timeout)?;

    // Wait for server's Hello
    let their_hello = match control.read_message().await {
        Ok(Some(ProtocolMessage::Hello(h))) => {
            trace!(
                version = h.protocol_version,
                features = ?h.features,
                agent = ?h.agent,
                "received server Hello"
            );
            h
        }
        Ok(Some(_)) => {
            warn!("received unexpected message during negotiation");
            return Err(NegotiationError::UnexpectedMessage);
        }
        Ok(None) | Err(_) => return Err(NegotiationError::Timeout),
    };

    // Validate version compatibility
    if !config
        .supported_versions
        .contains(&their_hello.protocol_version)
    {
        warn!(
            local = ?config.supported_versions,
            remote = their_hello.protocol_version,
            "version mismatch"
        );
        return Err(NegotiationError::VersionMismatch {
            local: config.supported_versions.clone(),
            remote: their_hello.protocol_version,
        });
    }

    // Compute negotiated parameters
    let negotiated_version = their_hello.protocol_version.min(PROTOCOL_VERSION);
    let negotiated_features = config.features & their_hello.features;

    // Send HelloAck
    trace!(version = negotiated_version, features = ?negotiated_features, "sending HelloAck");
    let ack = HelloAck {
        selected_version: negotiated_version,
        selected_features: negotiated_features,
    };
    control
        .write_message(&ProtocolMessage::HelloAck(ack))
        .await
        .map_err(|_| NegotiationError::Timeout)?;
    control
        .flush()
        .await
        .map_err(|_| NegotiationError::Timeout)?;

    // Wait for their HelloAck to confirm
    match control.read_message().await {
        Ok(Some(ProtocolMessage::HelloAck(their_ack))) => {
            trace!(
                version = their_ack.selected_version,
                features = ?their_ack.selected_features,
                "received server HelloAck"
            );
            // Verify consistency
            if their_ack.selected_version != negotiated_version {
                warn!(
                    expected = negotiated_version,
                    received = their_ack.selected_version,
                    "server HelloAck version mismatch"
                );
                return Err(NegotiationError::VersionMismatch {
                    local: vec![negotiated_version],
                    remote: their_ack.selected_version,
                });
            }
        }
        Ok(Some(_)) => {
            warn!("received unexpected message instead of HelloAck");
            return Err(NegotiationError::UnexpectedMessage);
        }
        Ok(None) | Err(_) => return Err(NegotiationError::Timeout),
    }

    debug!(
        version = negotiated_version,
        features = ?negotiated_features,
        remote_agent = ?their_hello.agent,
        "client negotiation complete"
    );

    Ok(NegotiatedParams {
        version: negotiated_version,
        features: negotiated_features,
        remote_agent: their_hello.agent,
    })
}

/// Performs the server-side negotiation.
///
/// The server waits for the client's `Hello`, sends its own `Hello`,
/// waits for `HelloAck`, then sends its own `HelloAck`.
#[instrument(skip_all, name = "negotiate_server")]
pub async fn negotiate_server<S: SendStream, R: RecvStream>(
    control: &mut ControlStream<S, R>,
    config: &Config,
) -> Result<NegotiatedParams, NegotiationError> {
    // Wait for client's Hello
    let their_hello = match control.read_message().await {
        Ok(Some(ProtocolMessage::Hello(h))) => {
            trace!(
                version = h.protocol_version,
                features = ?h.features,
                agent = ?h.agent,
                "received client Hello"
            );
            h
        }
        Ok(Some(_)) => {
            warn!("received unexpected message during negotiation");
            return Err(NegotiationError::UnexpectedMessage);
        }
        Ok(None) | Err(_) => return Err(NegotiationError::Timeout),
    };

    // Validate version compatibility
    if !config
        .supported_versions
        .contains(&their_hello.protocol_version)
    {
        warn!(
            local = ?config.supported_versions,
            remote = their_hello.protocol_version,
            "version mismatch"
        );
        return Err(NegotiationError::VersionMismatch {
            local: config.supported_versions.clone(),
            remote: their_hello.protocol_version,
        });
    }

    // Build and send our Hello
    trace!(version = PROTOCOL_VERSION, features = ?config.features, "sending Hello");
    let mut our_hello = Hello::new(config.features);
    if let Some(ref agent) = config.agent {
        our_hello = our_hello.with_agent(agent.clone());
    }
    control
        .write_message(&ProtocolMessage::Hello(our_hello))
        .await
        .map_err(|_| NegotiationError::Timeout)?;
    control
        .flush()
        .await
        .map_err(|_| NegotiationError::Timeout)?;

    // Wait for their HelloAck
    let their_ack = match control.read_message().await {
        Ok(Some(ProtocolMessage::HelloAck(ack))) => {
            trace!(
                version = ack.selected_version,
                features = ?ack.selected_features,
                "received client HelloAck"
            );
            ack
        }
        Ok(Some(_)) => {
            warn!("received unexpected message instead of HelloAck");
            return Err(NegotiationError::UnexpectedMessage);
        }
        Ok(None) | Err(_) => return Err(NegotiationError::Timeout),
    };

    // Verify the selected parameters make sense
    let negotiated_version = their_hello.protocol_version.min(PROTOCOL_VERSION);
    let negotiated_features = config.features & their_hello.features;

    if their_ack.selected_version != negotiated_version {
        warn!(
            expected = negotiated_version,
            received = their_ack.selected_version,
            "client HelloAck version mismatch"
        );
        return Err(NegotiationError::VersionMismatch {
            local: vec![negotiated_version],
            remote: their_ack.selected_version,
        });
    }

    // Send our HelloAck
    trace!(version = negotiated_version, features = ?negotiated_features, "sending HelloAck");
    let our_ack = HelloAck {
        selected_version: negotiated_version,
        selected_features: negotiated_features,
    };
    control
        .write_message(&ProtocolMessage::HelloAck(our_ack))
        .await
        .map_err(|_| NegotiationError::Timeout)?;
    control
        .flush()
        .await
        .map_err(|_| NegotiationError::Timeout)?;

    debug!(
        version = negotiated_version,
        features = ?negotiated_features,
        remote_agent = ?their_hello.agent,
        "server negotiation complete"
    );

    Ok(NegotiatedParams {
        version: negotiated_version,
        features: negotiated_features,
        remote_agent: their_hello.agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlStream;
    use quic_reverse_transport::{mock_connection_pair, Connection};

    #[tokio::test]
    async fn successful_negotiation() {
        let (conn_client, conn_server) = mock_connection_pair();

        let client_config = Config::new()
            .with_features(Features::PING_PONG | Features::STRUCTURED_METADATA)
            .with_agent("test-client/1.0");

        let server_config = Config::new()
            .with_features(Features::PING_PONG)
            .with_agent("test-server/1.0");

        // Spawn client negotiation
        let client_handle = tokio::spawn(async move {
            let (send, recv) = conn_client.open_bi().await.expect("open");
            let mut control = ControlStream::new(send, recv);
            negotiate_client(&mut control, &client_config).await
        });

        // Server accepts and negotiates
        let (send, recv) = conn_server
            .accept_bi()
            .await
            .expect("accept")
            .expect("stream");
        let mut server_control = ControlStream::new(send, recv);
        let server_result = negotiate_server(&mut server_control, &server_config).await;

        let client_result = client_handle.await.expect("client task");

        // Both should succeed
        let client_params = client_result.expect("client negotiation");
        let server_params = server_result.expect("server negotiation");

        // Should agree on version and features
        assert_eq!(client_params.version, PROTOCOL_VERSION);
        assert_eq!(server_params.version, PROTOCOL_VERSION);

        // Features should be intersection (only PING_PONG)
        assert_eq!(client_params.features, Features::PING_PONG);
        assert_eq!(server_params.features, Features::PING_PONG);

        // Should see each other's agent strings
        assert_eq!(
            client_params.remote_agent.as_deref(),
            Some("test-server/1.0")
        );
        assert_eq!(
            server_params.remote_agent.as_deref(),
            Some("test-client/1.0")
        );
    }

    #[tokio::test]
    async fn version_mismatch() {
        // Test that when client receives server's Hello with an unsupported version,
        // the client detects the mismatch.
        // Note: The Hello message's protocol_version field is always PROTOCOL_VERSION (1).
        // The supported_versions config is used to validate the received version.

        let (conn_client, conn_server) = mock_connection_pair();

        // Client only accepts version 99 (not the actual PROTOCOL_VERSION which is 1)
        let client_config = Config::new().with_versions(vec![99]);
        // Server uses default config (supports version 1)
        let server_config = Config::new();

        // Client opens stream
        let (client_send, client_recv) = conn_client.open_bi().await.expect("open");
        let mut client_control = ControlStream::new(client_send, client_recv);

        // Server accepts
        let (server_send, server_recv) = conn_server
            .accept_bi()
            .await
            .expect("accept")
            .expect("stream");
        let mut server_control = ControlStream::new(server_send, server_recv);

        // Run both negotiations concurrently
        let client_handle =
            tokio::spawn(
                async move { negotiate_client(&mut client_control, &client_config).await },
            );

        let server_handle =
            tokio::spawn(
                async move { negotiate_server(&mut server_control, &server_config).await },
            );

        // Client should fail because server's Hello has version 1, but client only accepts 99
        let client_result = client_handle.await.expect("client task");
        assert!(
            matches!(
                client_result,
                Err(NegotiationError::VersionMismatch { remote: 1, .. })
            ),
            "expected version mismatch, got: {client_result:?}"
        );

        // Server task will be stuck waiting for HelloAck, abort it
        server_handle.abort();
    }

    #[tokio::test]
    async fn no_common_features_still_succeeds() {
        let (conn_client, conn_server) = mock_connection_pair();

        // Different feature sets with no overlap
        let client_config = Config::new().with_features(Features::PING_PONG);
        let server_config = Config::new().with_features(Features::STRUCTURED_METADATA);

        let client_handle = tokio::spawn(async move {
            let (send, recv) = conn_client.open_bi().await.expect("open");
            let mut control = ControlStream::new(send, recv);
            negotiate_client(&mut control, &client_config).await
        });

        let (send, recv) = conn_server
            .accept_bi()
            .await
            .expect("accept")
            .expect("stream");
        let mut server_control = ControlStream::new(send, recv);
        let server_result = negotiate_server(&mut server_control, &server_config).await;

        let client_result = client_handle.await.expect("client task");

        // Both should succeed with empty feature set
        let client_params = client_result.expect("client negotiation");
        let server_params = server_result.expect("server negotiation");

        assert!(client_params.features.is_empty());
        assert!(server_params.features.is_empty());
    }
}
