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

//! Error types for quic-reverse sessions.

use quic_reverse_control::RejectCode;
use thiserror::Error;

/// Errors that can occur during session operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Negotiation failed during session startup.
    #[error("negotiation failed: {0}")]
    NegotiationFailed(#[from] NegotiationError),

    /// Protocol violation detected.
    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(TimeoutKind),

    /// Transport-level error.
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Stream open request was rejected by the peer.
    #[error("stream rejected: {code}{}", reason.as_ref().map(|r| format!(": {r}")).unwrap_or_default())]
    StreamRejected {
        /// The rejection code.
        code: RejectCode,
        /// Optional reason message.
        reason: Option<String>,
    },

    /// Session has been closed.
    #[error("session closed")]
    SessionClosed,

    /// Connection to peer was lost.
    #[error("disconnected")]
    Disconnected,

    /// Capacity limit reached.
    #[error("capacity limit reached: {0}")]
    CapacityExceeded(&'static str),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// Control protocol error.
    #[error("control protocol error: {0}")]
    Control(#[from] quic_reverse_control::ControlError),

    /// Codec error during message encoding/decoding.
    #[error("codec error: {0}")]
    Codec(#[from] quic_reverse_control::CodecError),
}

impl Error {
    /// Creates a transport error from any error type.
    pub fn transport<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Transport(Box::new(error))
    }

    /// Creates a protocol violation error.
    pub fn protocol_violation(message: impl Into<String>) -> Self {
        Self::ProtocolViolation(message.into())
    }

    /// Creates a stream rejected error.
    #[must_use]
    pub const fn stream_rejected(code: RejectCode, reason: Option<String>) -> Self {
        Self::StreamRejected { code, reason }
    }
}

/// Errors that can occur during negotiation.
#[derive(Debug, Error)]
pub enum NegotiationError {
    /// No compatible protocol version found.
    #[error("no compatible protocol version: local supports {local:?}, remote supports {remote}")]
    VersionMismatch {
        /// Versions supported locally.
        local: Vec<u16>,
        /// Version offered by remote.
        remote: u16,
    },

    /// Required feature not supported by peer.
    #[error("required feature not supported: {0}")]
    MissingFeature(String),

    /// Unexpected message received during negotiation.
    #[error("unexpected message during negotiation")]
    UnexpectedMessage,

    /// Negotiation timed out.
    #[error("negotiation timed out")]
    Timeout,
}

/// Types of timeout that can occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    /// Timeout waiting for negotiation to complete.
    Negotiation,
    /// Timeout waiting for an `OpenResponse`.
    OpenRequest,
    /// Timeout waiting for a stream to be bound after acceptance.
    StreamBind,
    /// Timeout waiting for a ping response.
    Ping,
}

impl std::fmt::Display for TimeoutKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Negotiation => write!(f, "negotiation"),
            Self::OpenRequest => write!(f, "open request"),
            Self::StreamBind => write!(f, "stream bind"),
            Self::Ping => write!(f, "ping"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = Error::stream_rejected(RejectCode::Unauthorized, Some("denied".into()));
        assert!(err.to_string().contains("unauthorized"));
        assert!(err.to_string().contains("denied"));
    }

    #[test]
    fn timeout_kind_display() {
        assert_eq!(TimeoutKind::Negotiation.to_string(), "negotiation");
        assert_eq!(TimeoutKind::OpenRequest.to_string(), "open request");
    }

    #[test]
    fn negotiation_error_display() {
        let err = NegotiationError::VersionMismatch {
            local: vec![1, 2],
            remote: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("[1, 2]"));
        assert!(msg.contains("3"));
    }
}
