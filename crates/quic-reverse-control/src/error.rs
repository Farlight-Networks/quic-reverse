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

//! Error types for the control protocol.

use thiserror::Error;

/// Errors that can occur during control protocol operations.
#[derive(Debug, Error)]
pub enum ControlError {
    /// Frame exceeds the maximum allowed size.
    #[error("frame size {size} exceeds maximum {max}", max = crate::MAX_FRAME_SIZE)]
    FrameTooLarge {
        /// The actual frame size.
        size: usize,
    },

    /// Unexpected end of input while reading a frame.
    #[error("unexpected end of input: expected {expected} bytes, got {actual}")]
    UnexpectedEof {
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes available.
        actual: usize,
    },

    /// Codec error during serialization or deserialization.
    #[error("codec error: {0}")]
    Codec(#[from] crate::CodecError),

    /// I/O error during read or write operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid protocol message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Protocol version mismatch.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
}
