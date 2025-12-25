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

//! Length-prefixed framing for control messages.
//!
//! All control messages are transmitted as length-prefixed frames:
//!
//! ```text
//! ┌──────────────────┬─────────────────────────────────┐
//! │  Length (4 bytes)│         Payload (N bytes)       │
//! │    big-endian    │      codec-encoded message      │
//! └──────────────────┴─────────────────────────────────┘
//! ```
//!
//! The maximum frame size is 64KB to prevent memory exhaustion attacks.

use crate::ControlError;
use bytes::{Buf, BufMut, BytesMut};

/// Maximum frame size (64KB).
///
/// Frames larger than this will be rejected to prevent memory exhaustion.
pub const MAX_FRAME_SIZE: usize = 65536;

/// Length prefix size in bytes.
const LENGTH_PREFIX_SIZE: usize = 4;

/// Reads length-prefixed frames from a byte buffer.
///
/// This struct maintains internal state for incremental parsing,
/// allowing frames to be read from partial data as it arrives.
#[derive(Debug, Default)]
pub struct FrameReader {
    /// Buffer for accumulating incoming data.
    buffer: BytesMut,
}

impl FrameReader {
    /// Creates a new frame reader.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Creates a new frame reader with the specified initial capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Appends data to the internal buffer.
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Attempts to read a complete frame from the buffer.
    ///
    /// Returns `Ok(Some(data))` if a complete frame is available,
    /// `Ok(None)` if more data is needed, or an error if the frame
    /// is invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame size exceeds `MAX_FRAME_SIZE`.
    pub fn read_frame(&mut self) -> Result<Option<Vec<u8>>, ControlError> {
        // Need at least the length prefix
        if self.buffer.len() < LENGTH_PREFIX_SIZE {
            return Ok(None);
        }

        // Peek at the length without consuming
        let length = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;

        // Validate frame size
        if length > MAX_FRAME_SIZE {
            return Err(ControlError::FrameTooLarge { size: length });
        }

        // Check if we have the complete frame
        let total_length = LENGTH_PREFIX_SIZE + length;
        if self.buffer.len() < total_length {
            return Ok(None);
        }

        // Consume the length prefix
        self.buffer.advance(LENGTH_PREFIX_SIZE);

        // Extract the payload
        let payload = self.buffer.split_to(length).to_vec();

        Ok(Some(payload))
    }

    /// Returns the number of bytes currently buffered.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Writes length-prefixed frames to a byte buffer.
#[derive(Debug, Default)]
pub struct FrameWriter {
    /// Buffer for constructing outgoing frames.
    buffer: BytesMut,
}

impl FrameWriter {
    /// Creates a new frame writer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Creates a new frame writer with the specified initial capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Writes a frame with the given payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload exceeds `MAX_FRAME_SIZE`.
    pub fn write_frame(&mut self, payload: &[u8]) -> Result<(), ControlError> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(ControlError::FrameTooLarge {
                size: payload.len(),
            });
        }

        // Reserve space for length prefix + payload
        self.buffer.reserve(LENGTH_PREFIX_SIZE + payload.len());

        // Write length prefix (big-endian u32)
        #[allow(clippy::cast_possible_truncation)]
        self.buffer.put_u32(payload.len() as u32);

        // Write payload
        self.buffer.extend_from_slice(payload);

        Ok(())
    }

    /// Takes the accumulated bytes from the buffer.
    ///
    /// This clears the internal buffer and returns the data.
    pub fn take_bytes(&mut self) -> Vec<u8> {
        self.buffer.split().to_vec()
    }

    /// Returns a reference to the accumulated bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns the number of bytes currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Encodes a payload into a length-prefixed frame.
///
/// This is a convenience function for one-shot encoding.
///
/// # Errors
///
/// Returns an error if the payload exceeds `MAX_FRAME_SIZE`.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, ControlError> {
    let mut writer = FrameWriter::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
    writer.write_frame(payload)?;
    Ok(writer.take_bytes())
}

/// Decodes a length-prefixed frame, returning the payload.
///
/// This is a convenience function for one-shot decoding when the complete
/// frame is available.
///
/// # Errors
///
/// Returns an error if the frame is incomplete or exceeds `MAX_FRAME_SIZE`.
pub fn decode_frame(data: &[u8]) -> Result<Vec<u8>, ControlError> {
    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(ControlError::UnexpectedEof {
            expected: LENGTH_PREFIX_SIZE,
            actual: data.len(),
        });
    }

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if length > MAX_FRAME_SIZE {
        return Err(ControlError::FrameTooLarge { size: length });
    }

    let total_length = LENGTH_PREFIX_SIZE + length;
    if data.len() < total_length {
        return Err(ControlError::UnexpectedEof {
            expected: total_length,
            actual: data.len(),
        });
    }

    Ok(data[LENGTH_PREFIX_SIZE..total_length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let payload = b"hello, world!";
        let encoded = encode_frame(payload).expect("encode should succeed");
        let decoded = decode_frame(&encoded).expect("decode should succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn frame_reader_complete() {
        let mut reader = FrameReader::new();
        let payload = b"test payload";
        let frame = encode_frame(payload).expect("encode should succeed");

        reader.extend(&frame);
        let result = reader.read_frame().expect("read should succeed");
        assert_eq!(result, Some(payload.to_vec()));
        assert!(reader.is_empty());
    }

    #[test]
    fn frame_reader_incremental() {
        let mut reader = FrameReader::new();
        let payload = b"incremental test";
        let frame = encode_frame(payload).expect("encode should succeed");

        // Feed data byte by byte
        for (i, &byte) in frame.iter().enumerate() {
            reader.extend(&[byte]);

            if i < frame.len() - 1 {
                // Should return None until complete
                let result = reader.read_frame().expect("read should succeed");
                assert!(result.is_none(), "expected None at byte {i}");
            }
        }

        // Now should have complete frame
        let result = reader.read_frame().expect("read should succeed");
        assert_eq!(result, Some(payload.to_vec()));
    }

    #[test]
    fn frame_reader_multiple_frames() {
        let mut reader = FrameReader::new();
        let payload1 = b"first";
        let payload2 = b"second";

        let frame1 = encode_frame(payload1).expect("encode should succeed");
        let frame2 = encode_frame(payload2).expect("encode should succeed");

        // Extend with both frames at once
        reader.extend(&frame1);
        reader.extend(&frame2);

        let result1 = reader.read_frame().expect("read should succeed");
        assert_eq!(result1, Some(payload1.to_vec()));

        let result2 = reader.read_frame().expect("read should succeed");
        assert_eq!(result2, Some(payload2.to_vec()));

        assert!(reader.is_empty());
    }

    #[test]
    fn frame_too_large_on_encode() {
        let payload = vec![0u8; MAX_FRAME_SIZE + 1];
        let result = encode_frame(&payload);
        assert!(matches!(result, Err(ControlError::FrameTooLarge { .. })));
    }

    #[test]
    fn frame_too_large_on_decode() {
        // Craft a frame with an oversized length prefix
        let mut frame = Vec::new();
        let bad_length = (MAX_FRAME_SIZE + 1) as u32;
        frame.extend_from_slice(&bad_length.to_be_bytes());
        frame.extend_from_slice(&[0u8; 100]); // Some payload

        let mut reader = FrameReader::new();
        reader.extend(&frame);
        let result = reader.read_frame();
        assert!(matches!(result, Err(ControlError::FrameTooLarge { .. })));
    }

    #[test]
    fn decode_incomplete_length() {
        let result = decode_frame(&[0, 0, 0]); // Only 3 bytes
        assert!(matches!(result, Err(ControlError::UnexpectedEof { .. })));
    }

    #[test]
    fn decode_incomplete_payload() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&10u32.to_be_bytes()); // Says 10 bytes
        frame.extend_from_slice(&[1, 2, 3, 4, 5]); // Only 5 bytes

        let result = decode_frame(&frame);
        assert!(matches!(result, Err(ControlError::UnexpectedEof { .. })));
    }

    #[test]
    fn empty_frame() {
        let encoded = encode_frame(&[]).expect("encode should succeed");
        assert_eq!(encoded.len(), 4); // Just the length prefix

        let decoded = decode_frame(&encoded).expect("decode should succeed");
        assert!(decoded.is_empty());
    }

    #[test]
    fn frame_writer_multiple_frames() {
        let mut writer = FrameWriter::new();
        writer.write_frame(b"one").expect("write should succeed");
        writer.write_frame(b"two").expect("write should succeed");

        let bytes = writer.take_bytes();

        // Parse both frames back
        let mut reader = FrameReader::new();
        reader.extend(&bytes);

        assert_eq!(
            reader.read_frame().expect("read should succeed"),
            Some(b"one".to_vec())
        );
        assert_eq!(
            reader.read_frame().expect("read should succeed"),
            Some(b"two".to_vec())
        );
    }
}
