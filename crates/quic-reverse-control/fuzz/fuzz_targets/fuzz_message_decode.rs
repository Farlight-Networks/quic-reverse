//! Fuzz target for message decoding.
//!
//! Tests that arbitrary byte sequences don't cause panics or undefined behavior
//! when parsed as protocol messages via the bincode codec.

#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_reverse_control::{BincodeCodec, Codec, ProtocolMessage};

fuzz_target!(|data: &[u8]| {
    let codec = BincodeCodec::new();
    
    // Try to decode the data as a protocol message.
    // This should never panic, regardless of input.
    let _: Result<ProtocolMessage, _> = codec.decode(data);
});

