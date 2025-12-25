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

//! Control protocol implementation for quic-reverse.
//!
//! This crate provides the control plane protocol used by quic-reverse sessions,
//! including message types, framing, and codec abstractions.

mod codec;
mod error;
mod framing;
mod messages;

pub use codec::{BincodeCodec, Codec, CodecError};
pub use error::ControlError;
pub use framing::{decode_frame, encode_frame, FrameReader, FrameWriter, MAX_FRAME_SIZE};
pub use messages::{
    CloseCode, Features, Hello, HelloAck, Metadata, MetadataValue, OpenFlags, OpenRequest,
    OpenResponse, OpenStatus, Ping, Pong, ProtocolMessage, RejectCode, ServiceId, StreamBind,
    StreamClose, PROTOCOL_VERSION,
};
