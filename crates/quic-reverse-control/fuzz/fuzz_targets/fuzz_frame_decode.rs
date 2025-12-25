//! Fuzz target for frame decoding.
//!
//! Tests that arbitrary byte sequences don't cause panics or undefined behavior
//! when parsed as frames.

#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_reverse_control::decode_frame;

fuzz_target!(|data: &[u8]| {
    // Try to decode the data as a frame.
    // This should never panic, regardless of input.
    let _ = decode_frame(data);
});

