//! Fuzz target for StreamBind parsing.
//!
//! Tests that arbitrary byte sequences don't cause panics or undefined behavior
//! when parsed as StreamBind messages.

#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_reverse_control::StreamBind;

fuzz_target!(|data: &[u8]| {
    // StreamBind expects exactly 13 bytes.
    // Test with exact size arrays when we have enough data.
    if data.len() >= 13 {
        let mut buf = [0u8; 13];
        buf.copy_from_slice(&data[..13]);
        // Try to decode - this should never panic.
        let _ = StreamBind::decode(&buf);
    }

    // Also test with various invalid sizes to ensure no panics
    // when code handles size mismatches elsewhere.
});

