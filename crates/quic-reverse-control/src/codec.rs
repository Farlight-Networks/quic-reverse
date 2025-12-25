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

//! Codec abstraction for message serialization.
//!
//! This module provides a trait for pluggable serialization codecs,
//! with a default bincode implementation for efficiency.

use crate::ProtocolMessage;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Errors that can occur during codec operations.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Serialization failed.
    #[error("serialization failed: {0}")]
    Serialize(String),

    /// Deserialization failed.
    #[error("deserialization failed: {0}")]
    Deserialize(String),
}

/// Trait for message serialization codecs.
///
/// Implementations must be thread-safe as they may be shared across
/// async tasks.
pub trait Codec: Send + Sync + 'static {
    /// Encodes a value to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn encode<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, CodecError>;

    /// Decodes bytes to a value.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    fn decode<T: DeserializeOwned>(&self, data: &[u8]) -> Result<T, CodecError>;

    /// Encodes a protocol message.
    ///
    /// This is a convenience method that delegates to `encode`.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn encode_message(&self, message: &ProtocolMessage) -> Result<Vec<u8>, CodecError> {
        self.encode(message)
    }

    /// Decodes a protocol message.
    ///
    /// This is a convenience method that delegates to `decode`.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    fn decode_message(&self, data: &[u8]) -> Result<ProtocolMessage, CodecError> {
        self.decode(data)
    }
}

/// Bincode codec for efficient binary serialization.
///
/// This is the default codec used by quic-reverse. It provides compact
/// binary encoding with good performance.
#[derive(Debug, Clone, Copy, Default)]
pub struct BincodeCodec;

impl BincodeCodec {
    /// Creates a new bincode codec.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Codec for BincodeCodec {
    fn encode<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, CodecError> {
        bincode::serialize(value).map_err(|e| CodecError::Serialize(e.to_string()))
    }

    fn decode<T: DeserializeOwned>(&self, data: &[u8]) -> Result<T, CodecError> {
        bincode::deserialize(data).map_err(|e| CodecError::Deserialize(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Features, Hello, OpenRequest, OpenResponse, OpenStatus, RejectCode, ServiceId};

    #[test]
    fn bincode_hello_round_trip() {
        let codec = BincodeCodec::new();
        let hello =
            Hello::new(Features::PING_PONG | Features::STRUCTURED_METADATA).with_agent("test/1.0");
        let message = ProtocolMessage::Hello(hello.clone());

        let encoded = codec
            .encode_message(&message)
            .expect("encode should succeed");
        let decoded = codec
            .decode_message(&encoded)
            .expect("decode should succeed");

        match decoded {
            ProtocolMessage::Hello(h) => {
                assert_eq!(h.protocol_version, hello.protocol_version);
                assert_eq!(h.features, hello.features);
                assert_eq!(h.agent, hello.agent);
            }
            _ => panic!("expected Hello message"),
        }
    }

    #[test]
    fn bincode_open_request_round_trip() {
        let codec = BincodeCodec::new();
        let request = OpenRequest::new(42, ServiceId::new("ssh"));
        let message = ProtocolMessage::OpenRequest(request.clone());

        let encoded = codec
            .encode_message(&message)
            .expect("encode should succeed");
        let decoded = codec
            .decode_message(&encoded)
            .expect("decode should succeed");

        match decoded {
            ProtocolMessage::OpenRequest(r) => {
                assert_eq!(r.request_id, request.request_id);
                assert_eq!(r.service, request.service);
            }
            _ => panic!("expected OpenRequest message"),
        }
    }

    #[test]
    fn bincode_open_response_accepted_round_trip() {
        let codec = BincodeCodec::new();
        let response = OpenResponse::accepted(42, 100);
        let message = ProtocolMessage::OpenResponse(response.clone());

        let encoded = codec
            .encode_message(&message)
            .expect("encode should succeed");
        let decoded = codec
            .decode_message(&encoded)
            .expect("decode should succeed");

        match decoded {
            ProtocolMessage::OpenResponse(r) => {
                assert_eq!(r.request_id, response.request_id);
                assert_eq!(r.status, OpenStatus::Accepted);
                assert_eq!(r.logical_stream_id, Some(100));
            }
            _ => panic!("expected OpenResponse message"),
        }
    }

    #[test]
    fn bincode_open_response_rejected_round_trip() {
        let codec = BincodeCodec::new();
        let response =
            OpenResponse::rejected(42, RejectCode::Unauthorized, Some("access denied".into()));
        let message = ProtocolMessage::OpenResponse(response);

        let encoded = codec
            .encode_message(&message)
            .expect("encode should succeed");
        let decoded = codec
            .decode_message(&encoded)
            .expect("decode should succeed");

        match decoded {
            ProtocolMessage::OpenResponse(r) => {
                assert_eq!(r.request_id, 42);
                assert_eq!(r.status, OpenStatus::Rejected(RejectCode::Unauthorized));
                assert_eq!(r.reason.as_deref(), Some("access denied"));
                assert!(r.logical_stream_id.is_none());
            }
            _ => panic!("expected OpenResponse message"),
        }
    }

    #[test]
    fn bincode_decode_invalid_data() {
        let codec = BincodeCodec::new();
        let invalid_data = &[0xff, 0xff, 0xff, 0xff];
        let result: Result<ProtocolMessage, _> = codec.decode(invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn codec_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BincodeCodec>();
    }
}
