# quic-reverse Architecture

This document describes the architecture and design rationale for quic-reverse.

## Design Philosophy

quic-reverse is designed as a protocol library, not an application framework. It provides the mechanisms for reverse-initiated streams over QUIC while leaving policy decisions to the application. The library handles connection negotiation, stream lifecycle, and multiplexing. Authentication, authorization, and application-level protocols remain the caller's responsibility.

## Crate Structure

The library is organized into three crates with clear separation of concerns.

### quic-reverse (main crate)

The public API crate that applications depend on. It provides:

- `Session` and `SessionHandle` for session management
- `SessionClient` for concurrent operations from multiple tasks
- `Config` for session configuration
- `Error` types for structured error handling
- `ControlEvent` for incoming control messages

This crate depends on both internal crates and re-exports types that applications need.

### quic-reverse-control

The protocol implementation crate containing:

- `ProtocolMessage` enum with all control message types
- `FrameReader` and `FrameWriter` for length-prefixed framing
- `Codec` trait and `BincodeCodec` for message serialization
- `StreamBind` for data stream binding

This crate has no transport dependencies and can be used independently for protocol-level testing or alternative implementations.

### quic-reverse-transport

The transport abstraction layer providing:

- `Connection`, `SendStream`, and `RecvStream` traits
- `QuinnConnection` adapter for production use with Quinn
- `MockConnection` for testing without network I/O

This separation allows the library to support alternative QUIC implementations without changes to the protocol or session logic.

## Key Design Decisions

### Dedicated Control Stream

The protocol uses a dedicated bidirectional stream for all control messages rather than mixing control and data on the same stream. This design choice provides several benefits:

1. The control channel remains available for concurrent operations while data streams are active
2. Stream lifecycle is cleaner since control messages don't interfere with application data
3. The protocol is more portable across QUIC implementations with different stream semantics

The first bidirectional stream opened after connection establishment becomes the control stream. Both peers send Hello messages simultaneously, followed by HelloAck to confirm negotiated parameters.

### Header-Bound Data Streams

Data streams begin with a StreamBind frame that correlates the QUIC stream to a logical stream ID from the control plane. This 13-byte header contains a magic number, version, and logical stream ID.

This design solves two problems:

1. **Stream visibility**: QUIC streams are not visible to `accept_bi()` until data is sent. The StreamBind frame triggers visibility while also serving a protocol purpose.

2. **Stream correlation**: The logical stream ID provides validated binding between control messages (OpenRequest/OpenResponse) and data streams, preventing accidental stream confusion.

### Session/SessionHandle Split

The `Session` type owns the connection and configuration. Calling `start()` performs negotiation and returns a `SessionHandle` that owns the control stream I/O.

This split serves several purposes:

1. The `Session` is clonable (Arc-based) for shared state access across tasks
2. The `SessionHandle` owns the control stream reader/writer, enforcing single-owner semantics for I/O
3. `SessionClient` wraps `SessionHandle` for concurrent access when needed

### Transport Abstraction

The library is generic over the QUIC implementation through the `Connection`, `SendStream`, and `RecvStream` traits. This abstraction:

1. Allows testing with `MockConnection` without network I/O
2. Enables support for alternative QUIC implementations
3. Keeps Quinn-specific types out of the public API

The cost is additional trait bounds on generic code, but the benefits for testing and portability outweigh this complexity.

### Event-Driven API

Rather than a callback-based hooks system, the library uses an event-driven API where the application runs a message processing loop:

```rust
loop {
    match handle.process_message().await? {
        Some(ControlEvent::OpenRequest { request_id, service, .. }) => {
            // Application decides to accept or reject
        }
        None => break,
        _ => {}
    }
}
```

This approach is more idiomatic in Rust, avoids lifetime complexity from callbacks, and gives the application explicit control over message handling timing.

### Logical Stream IDs

The library assigns its own logical stream IDs rather than exposing QUIC stream IDs. This provides:

1. Portability across QUIC implementations with different ID schemes
2. Independence from QUIC stream lifecycle
3. Consistent semantics regardless of transport

Logical IDs are assigned by the peer accepting an OpenRequest and communicated in the OpenResponse.

## Error Handling

Errors are categorized by source and recoverability:

- `Timeout` errors with `TimeoutKind` for different timeout types
- `Transport` errors wrapping underlying I/O failures
- `Protocol` errors for wire format violations
- `StreamRejected` for application-level rejections
- `SessionClosed` and `Disconnected` for connection state

This structure allows applications to handle different failure modes appropriately.

## Observability

The library uses the `tracing` crate for structured logging with consistent span and field conventions:

- `trace`: Low-level I/O operations
- `debug`: Protocol operations and state changes
- `info`: Session lifecycle events
- `warn`/`error`: Problems requiring attention

Spans include session and stream context for log correlation.

## Further Reading

- [PROTOCOL.md](PROTOCOL.md) - Wire protocol specification
- [crates/quic-reverse/examples/README.md](crates/quic-reverse/examples/README.md) - Example documentation

