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

//! Protocol message definitions.
//!
//! This module defines all control plane messages exchanged between peers
//! during a quic-reverse session.

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Identifies a logical service for multiplexing.
///
/// Services are identified by string names such as "ssh", "http", or "tcp".
/// The service ID is used to route incoming stream requests to the appropriate
/// handler.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceId(pub String);

impl ServiceId {
    /// Creates a new service identifier.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the service name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for ServiceId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for ServiceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Metadata attached to stream open requests.
///
/// Metadata can be empty, raw bytes, or a structured key-value map.
/// The format is negotiated during the `Hello`/`HelloAck` exchange.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Metadata {
    /// No metadata.
    #[default]
    Empty,
    /// Raw byte payload.
    Bytes(Vec<u8>),
    /// Structured key-value pairs.
    Structured(HashMap<String, MetadataValue>),
}

/// A value within structured metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetadataValue {
    /// String value.
    String(String),
    /// Integer value.
    Integer(i64),
    /// Boolean value.
    Boolean(bool),
    /// Binary data.
    Bytes(Vec<u8>),
}

impl Eq for MetadataValue {}

bitflags! {
    /// Feature flags negotiated during `Hello`/`HelloAck` exchange.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Features: u32 {
        /// Support for structured metadata in `OpenRequest`.
        const STRUCTURED_METADATA = 0b0000_0001;
        /// Support for Ping/Pong keep-alive messages.
        const PING_PONG = 0b0000_0010;
        /// Support for stream priority hints.
        const STREAM_PRIORITY = 0b0000_0100;
    }
}

impl Default for Features {
    fn default() -> Self {
        Self::empty()
    }
}

bitflags! {
    /// Flags for `OpenRequest` messages.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct OpenFlags: u8 {
        /// Request a unidirectional stream (send only).
        const UNIDIRECTIONAL = 0b0000_0001;
        /// High priority stream hint.
        const HIGH_PRIORITY = 0b0000_0010;
    }
}

impl Default for OpenFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// All protocol messages that can be exchanged on the control stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolMessage {
    /// Initial handshake message.
    Hello(Hello),
    /// Handshake acknowledgment.
    HelloAck(HelloAck),
    /// Request to open a reverse stream.
    OpenRequest(OpenRequest),
    /// Response to an open request.
    OpenResponse(OpenResponse),
    /// Notification that a stream has closed.
    StreamClose(StreamClose),
    /// Keep-alive ping.
    Ping(Ping),
    /// Keep-alive pong.
    Pong(Pong),
}

/// Initial handshake message sent by both peers.
///
/// Each peer sends a Hello message after the QUIC connection is established.
/// The messages are used to negotiate protocol version and features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version supported by this peer.
    pub protocol_version: u16,
    /// Feature flags supported by this peer.
    pub features: Features,
    /// Optional agent identifier (e.g., "quic-reverse/0.1.0").
    pub agent: Option<String>,
}

impl Hello {
    /// Creates a new Hello message with the current protocol version.
    #[must_use]
    pub const fn new(features: Features) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            features,
            agent: None,
        }
    }

    /// Sets the agent identifier.
    #[must_use]
    pub fn with_agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = Some(agent.into());
        self
    }
}

/// Handshake acknowledgment confirming negotiated parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Selected protocol version (highest mutually supported).
    pub selected_version: u16,
    /// Selected feature set (intersection of both peers' features).
    pub selected_features: Features,
}

/// Request to open a reverse stream.
///
/// Sent by the peer that wants to initiate a reverse stream. The receiving
/// peer will respond with an `OpenResponse` and, if accepted, open a new
/// QUIC stream back to the initiator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenRequest {
    /// Unique identifier for this request, used to correlate responses.
    pub request_id: u64,
    /// Target service identifier.
    pub service: ServiceId,
    /// Optional metadata for the stream.
    pub metadata: Metadata,
    /// Request flags.
    pub flags: OpenFlags,
}

impl OpenRequest {
    /// Creates a new open request for the specified service.
    #[must_use]
    pub fn new(request_id: u64, service: impl Into<ServiceId>) -> Self {
        Self {
            request_id,
            service: service.into(),
            metadata: Metadata::Empty,
            flags: OpenFlags::empty(),
        }
    }

    /// Sets the metadata for this request.
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Sets the flags for this request.
    #[must_use]
    pub const fn with_flags(mut self, flags: OpenFlags) -> Self {
        self.flags = flags;
        self
    }
}

/// Response to an `OpenRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenResponse {
    /// Request ID from the corresponding `OpenRequest`.
    pub request_id: u64,
    /// Result of the open request.
    pub status: OpenStatus,
    /// Optional reason message (typically for rejections).
    pub reason: Option<String>,
    /// Logical stream ID assigned to this stream (if accepted).
    pub logical_stream_id: Option<u64>,
}

impl OpenResponse {
    /// Creates an accepted response with the given logical stream ID.
    #[must_use]
    pub const fn accepted(request_id: u64, logical_stream_id: u64) -> Self {
        Self {
            request_id,
            status: OpenStatus::Accepted,
            reason: None,
            logical_stream_id: Some(logical_stream_id),
        }
    }

    /// Creates a rejected response with the given code and optional reason.
    #[must_use]
    pub const fn rejected(request_id: u64, code: RejectCode, reason: Option<String>) -> Self {
        Self {
            request_id,
            status: OpenStatus::Rejected(code),
            reason,
            logical_stream_id: None,
        }
    }
}

/// Status of an `OpenRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenStatus {
    /// Request accepted; stream will be opened.
    Accepted,
    /// Request rejected with the given code.
    Rejected(RejectCode),
}

/// Reason codes for rejecting an `OpenRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RejectCode {
    /// The requested service is not available.
    ServiceUnavailable,
    /// The requested service is not supported.
    UnsupportedService,
    /// Resource limits have been exceeded.
    LimitExceeded,
    /// The request is not authorized.
    Unauthorized,
    /// An internal error occurred.
    InternalError,
}

impl std::fmt::Display for RejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceUnavailable => write!(f, "service unavailable"),
            Self::UnsupportedService => write!(f, "unsupported service"),
            Self::LimitExceeded => write!(f, "limit exceeded"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::InternalError => write!(f, "internal error"),
        }
    }
}

/// Notification that a stream has closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamClose {
    /// Logical stream ID of the closed stream.
    pub logical_stream_id: u64,
    /// Close code indicating the reason.
    pub code: CloseCode,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

impl StreamClose {
    /// Creates a normal close notification.
    #[must_use]
    pub const fn normal(logical_stream_id: u64) -> Self {
        Self {
            logical_stream_id,
            code: CloseCode::Normal,
            reason: None,
        }
    }

    /// Creates an error close notification.
    #[must_use]
    pub fn error(logical_stream_id: u64, reason: impl Into<String>) -> Self {
        Self {
            logical_stream_id,
            code: CloseCode::Error,
            reason: Some(reason.into()),
        }
    }
}

/// Close codes for `StreamClose` messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloseCode {
    /// Normal closure.
    Normal,
    /// Error condition.
    Error,
    /// Timeout expired.
    Timeout,
    /// Stream was reset.
    Reset,
}

impl CloseCode {
    /// Returns the numeric code for wire transmission.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Error => 1,
            Self::Timeout => 2,
            Self::Reset => 3,
        }
    }
}

/// Keep-alive ping message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    /// Sequence number for matching with Pong responses.
    pub sequence: u64,
}

/// Keep-alive pong response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong {
    /// Sequence number from the corresponding Ping.
    pub sequence: u64,
}

/// Stream binding frame sent on data streams.
///
/// When a data stream is opened, the first frame sent must be a `StreamBind`
/// to identify which logical stream this QUIC stream belongs to. This allows
/// the receiving peer to match the data stream with the corresponding
/// `OpenRequest`/`OpenResponse` exchange.
///
/// # Wire Format
///
/// The stream bind frame is encoded as:
/// - 4 bytes: magic number (`0x51524256`, "QRBV" for "Quic Reverse Bind Version")
/// - 1 byte: version (currently 1)
/// - 8 bytes: `logical_stream_id` (big-endian u64)
///
/// Total: 13 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamBind {
    /// Logical stream ID assigned during `OpenResponse`.
    pub logical_stream_id: u64,
}

impl StreamBind {
    /// Magic number identifying the stream bind frame.
    pub const MAGIC: [u8; 4] = [0x51, 0x52, 0x42, 0x56]; // "QRBV"

    /// Current stream bind version.
    pub const VERSION: u8 = 1;

    /// Size of the encoded stream bind frame.
    pub const ENCODED_SIZE: usize = 13; // 4 + 1 + 8

    /// Creates a new stream bind frame.
    #[must_use]
    pub const fn new(logical_stream_id: u64) -> Self {
        Self { logical_stream_id }
    }

    /// Encodes the stream bind to bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[0..4].copy_from_slice(&Self::MAGIC);
        buf[4] = Self::VERSION;
        buf[5..13].copy_from_slice(&self.logical_stream_id.to_be_bytes());
        buf
    }

    /// Decodes a stream bind from bytes.
    ///
    /// Returns `None` if the magic number is invalid or the version is unsupported.
    #[must_use]
    pub fn decode(buf: &[u8; Self::ENCODED_SIZE]) -> Option<Self> {
        if buf[0..4] != Self::MAGIC {
            return None;
        }
        if buf[4] != Self::VERSION {
            return None;
        }
        let logical_stream_id = u64::from_be_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        Some(Self { logical_stream_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Property-based testing with proptest
    mod proptest_tests {
        use super::*;
        use crate::{BincodeCodec, Codec};
        use proptest::prelude::*;

        // Strategy for generating arbitrary Features
        fn arb_features() -> impl Strategy<Value = Features> {
            (0u32..8).prop_map(Features::from_bits_truncate)
        }

        // Strategy for generating arbitrary OpenFlags
        fn arb_open_flags() -> impl Strategy<Value = OpenFlags> {
            (0u8..4).prop_map(OpenFlags::from_bits_truncate)
        }

        // Strategy for generating arbitrary ServiceId
        fn arb_service_id() -> impl Strategy<Value = ServiceId> {
            "[a-z][a-z0-9_-]{0,31}".prop_map(ServiceId::new)
        }

        // Strategy for generating arbitrary MetadataValue
        fn arb_metadata_value() -> impl Strategy<Value = MetadataValue> {
            prop_oneof![
                ".*".prop_map(MetadataValue::String),
                any::<i64>().prop_map(MetadataValue::Integer),
                any::<bool>().prop_map(MetadataValue::Boolean),
                prop::collection::vec(any::<u8>(), 0..64).prop_map(MetadataValue::Bytes),
            ]
        }

        // Strategy for generating arbitrary Metadata
        fn arb_metadata() -> impl Strategy<Value = Metadata> {
            prop_oneof![
                Just(Metadata::Empty),
                prop::collection::vec(any::<u8>(), 0..128).prop_map(Metadata::Bytes),
                prop::collection::hash_map("[a-z]{1,16}", arb_metadata_value(), 0..8)
                    .prop_map(Metadata::Structured),
            ]
        }

        // Strategy for generating arbitrary RejectCode
        fn arb_reject_code() -> impl Strategy<Value = RejectCode> {
            prop_oneof![
                Just(RejectCode::ServiceUnavailable),
                Just(RejectCode::UnsupportedService),
                Just(RejectCode::LimitExceeded),
                Just(RejectCode::Unauthorized),
                Just(RejectCode::InternalError),
            ]
        }

        // Strategy for generating arbitrary CloseCode
        fn arb_close_code() -> impl Strategy<Value = CloseCode> {
            prop_oneof![
                Just(CloseCode::Normal),
                Just(CloseCode::Reset),
                Just(CloseCode::Timeout),
                Just(CloseCode::Error),
            ]
        }

        // Strategy for generating arbitrary Hello
        fn arb_hello() -> impl Strategy<Value = Hello> {
            (arb_features(), proptest::option::of(".*")).prop_map(|(features, agent)| {
                let mut hello = Hello::new(features);
                hello.agent = agent;
                hello
            })
        }

        // Strategy for generating arbitrary HelloAck
        fn arb_hello_ack() -> impl Strategy<Value = HelloAck> {
            (any::<u16>(), arb_features()).prop_map(|(version, features)| HelloAck {
                selected_version: version,
                selected_features: features,
            })
        }

        // Strategy for generating arbitrary OpenRequest
        fn arb_open_request() -> impl Strategy<Value = OpenRequest> {
            (
                any::<u64>(),
                arb_service_id(),
                arb_metadata(),
                arb_open_flags(),
            )
                .prop_map(|(request_id, service, metadata, flags)| OpenRequest {
                    request_id,
                    service,
                    metadata,
                    flags,
                })
        }

        // Strategy for generating arbitrary OpenResponse
        fn arb_open_response() -> impl Strategy<Value = OpenResponse> {
            (
                any::<u64>(),
                prop_oneof![
                    Just(OpenStatus::Accepted),
                    arb_reject_code().prop_map(OpenStatus::Rejected),
                ],
                proptest::option::of(".*"),
                proptest::option::of(any::<u64>()),
            )
                .prop_map(|(request_id, status, reason, logical_stream_id)| {
                    OpenResponse {
                        request_id,
                        status,
                        reason,
                        logical_stream_id,
                    }
                })
        }

        // Strategy for generating arbitrary StreamClose
        fn arb_stream_close() -> impl Strategy<Value = StreamClose> {
            (any::<u64>(), arb_close_code(), proptest::option::of(".*")).prop_map(
                |(logical_stream_id, code, reason)| StreamClose {
                    logical_stream_id,
                    code,
                    reason,
                },
            )
        }

        // Strategy for generating arbitrary Ping
        fn arb_ping() -> impl Strategy<Value = Ping> {
            any::<u64>().prop_map(|sequence| Ping { sequence })
        }

        // Strategy for generating arbitrary Pong
        fn arb_pong() -> impl Strategy<Value = Pong> {
            any::<u64>().prop_map(|sequence| Pong { sequence })
        }

        // Strategy for generating arbitrary ProtocolMessage
        fn arb_protocol_message() -> impl Strategy<Value = ProtocolMessage> {
            prop_oneof![
                arb_hello().prop_map(ProtocolMessage::Hello),
                arb_hello_ack().prop_map(ProtocolMessage::HelloAck),
                arb_open_request().prop_map(ProtocolMessage::OpenRequest),
                arb_open_response().prop_map(ProtocolMessage::OpenResponse),
                arb_stream_close().prop_map(ProtocolMessage::StreamClose),
                arb_ping().prop_map(ProtocolMessage::Ping),
                arb_pong().prop_map(ProtocolMessage::Pong),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]

            #[test]
            fn protocol_message_round_trip(msg in arb_protocol_message()) {
                let codec = BincodeCodec::new();
                let encoded = codec.encode(&msg).expect("encoding should succeed");
                let decoded: ProtocolMessage = codec.decode(&encoded).expect("decoding should succeed");
                prop_assert_eq!(msg, decoded);
            }

            #[test]
            fn hello_round_trip(msg in arb_hello()) {
                let codec = BincodeCodec::new();
                let wrapped = ProtocolMessage::Hello(msg.clone());
                let encoded = codec.encode(&wrapped).expect("encoding should succeed");
                let decoded: ProtocolMessage = codec.decode(&encoded).expect("decoding should succeed");
                prop_assert_eq!(ProtocolMessage::Hello(msg), decoded);
            }

            #[test]
            fn open_request_round_trip(msg in arb_open_request()) {
                let codec = BincodeCodec::new();
                let wrapped = ProtocolMessage::OpenRequest(msg.clone());
                let encoded = codec.encode(&wrapped).expect("encoding should succeed");
                let decoded: ProtocolMessage = codec.decode(&encoded).expect("decoding should succeed");
                prop_assert_eq!(ProtocolMessage::OpenRequest(msg), decoded);
            }

            #[test]
            fn stream_bind_round_trip(id in any::<u64>()) {
                let bind = StreamBind::new(id);
                let encoded = bind.encode();
                let decoded = StreamBind::decode(&encoded).expect("decode should succeed");
                prop_assert_eq!(bind.logical_stream_id, decoded.logical_stream_id);
            }

            #[test]
            fn service_id_preserves_content(s in "[a-z][a-z0-9_-]{0,63}") {
                let id = ServiceId::new(&s);
                prop_assert_eq!(id.as_str(), s.as_str());
                prop_assert_eq!(format!("{id}"), s);
            }
        }
    }

    #[test]
    fn service_id_from_str() {
        let id: ServiceId = "ssh".into();
        assert_eq!(id.as_str(), "ssh");
    }

    #[test]
    fn service_id_display() {
        let id = ServiceId::new("http");
        assert_eq!(format!("{id}"), "http");
    }

    #[test]
    fn hello_with_agent() {
        let hello = Hello::new(Features::PING_PONG).with_agent("test/1.0");
        assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
        assert_eq!(hello.features, Features::PING_PONG);
        assert_eq!(hello.agent.as_deref(), Some("test/1.0"));
    }

    #[test]
    fn open_request_builder() {
        let req = OpenRequest::new(42, "tcp")
            .with_metadata(Metadata::Bytes(vec![1, 2, 3]))
            .with_flags(OpenFlags::HIGH_PRIORITY);

        assert_eq!(req.request_id, 42);
        assert_eq!(req.service.as_str(), "tcp");
        assert_eq!(req.metadata, Metadata::Bytes(vec![1, 2, 3]));
        assert!(req.flags.contains(OpenFlags::HIGH_PRIORITY));
    }

    #[test]
    fn open_response_accepted() {
        let resp = OpenResponse::accepted(42, 100);
        assert_eq!(resp.request_id, 42);
        assert_eq!(resp.status, OpenStatus::Accepted);
        assert_eq!(resp.logical_stream_id, Some(100));
    }

    #[test]
    fn open_response_rejected() {
        let resp = OpenResponse::rejected(42, RejectCode::Unauthorized, Some("denied".into()));
        assert_eq!(resp.request_id, 42);
        assert_eq!(resp.status, OpenStatus::Rejected(RejectCode::Unauthorized));
        assert_eq!(resp.reason.as_deref(), Some("denied"));
        assert_eq!(resp.logical_stream_id, None);
    }

    #[test]
    fn stream_close_normal() {
        let close = StreamClose::normal(99);
        assert_eq!(close.logical_stream_id, 99);
        assert_eq!(close.code, CloseCode::Normal);
        assert!(close.reason.is_none());
    }

    #[test]
    fn features_intersection() {
        let a = Features::PING_PONG | Features::STRUCTURED_METADATA;
        let b = Features::PING_PONG | Features::STREAM_PRIORITY;
        let intersection = a & b;
        assert_eq!(intersection, Features::PING_PONG);
    }

    #[test]
    fn stream_bind_encode_decode() {
        let bind = StreamBind::new(0x0102_0304_0506_0708);
        let encoded = bind.encode();

        // Check magic number
        assert_eq!(&encoded[0..4], &StreamBind::MAGIC);
        // Check version
        assert_eq!(encoded[4], StreamBind::VERSION);
        // Check logical_stream_id (big-endian)
        assert_eq!(
            &encoded[5..13],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );

        // Decode and verify
        let decoded = StreamBind::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.logical_stream_id, 0x0102_0304_0506_0708);
    }

    #[test]
    fn stream_bind_invalid_magic() {
        let mut buf = [0u8; StreamBind::ENCODED_SIZE];
        buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Wrong magic
        buf[4] = StreamBind::VERSION;
        assert!(StreamBind::decode(&buf).is_none());
    }

    #[test]
    fn stream_bind_invalid_version() {
        let mut buf = [0u8; StreamBind::ENCODED_SIZE];
        buf[0..4].copy_from_slice(&StreamBind::MAGIC);
        buf[4] = 0xFF; // Wrong version
        assert!(StreamBind::decode(&buf).is_none());
    }
}
