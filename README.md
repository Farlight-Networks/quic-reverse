# quic-reverse

[![Crates.io](https://img.shields.io/crates/v/quic-reverse.svg)](https://crates.io/crates/quic-reverse)
[![Documentation](https://docs.rs/quic-reverse/badge.svg)](https://docs.rs/quic-reverse)
[![CI](https://github.com/Farlight-Networks/quic-reverse/actions/workflows/ci.yml/badge.svg)](https://github.com/Farlight-Networks/quic-reverse/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.75-blue.svg)](https://www.rust-lang.org/)
[![Downloads](https://img.shields.io/crates/d/quic-reverse.svg)](https://crates.io/crates/quic-reverse)

A Rust library for reverse-initiated, multiplexed streams over QUIC.

quic-reverse helps with the "reverse connection" problem: allowing services behind NAT or firewalls to accept incoming connections without exposing a public port. The library handles connection negotiation, stream lifecycle management, and multiplexing while staying out of authentication, certificate management, and application-level protocols.

## What can you build with quic-reverse?

quic-reverse is useful whenever a service behind NAT or a firewall needs to accept incoming connections without exposing a public port. Common use cases include:

- **Remote access tools** - SSH, RDP, or VNC tunneling through restrictive networks
- **IoT device management** - Push commands to devices that can only make outbound connections
- **Development tunnels** - Expose localhost services to the internet (similar to ngrok)
- **Edge-to-cloud connectivity** - Let edge nodes receive work from a central orchestrator
- **Multiplexed service proxies** - Route multiple logical services over a single QUIC connection

### What quic-reverse handles

- Connection negotiation and feature discovery
- Stream lifecycle (open requests, responses, graceful close)
- Logical stream multiplexing with service-based routing
- Keep-alive and timeout management

### What you provide

- The QUIC connection (quic-reverse abstracts over Quinn; you control TLS and certificates)
- Service handlers for incoming stream requests
- Application-level framing for your data streams

## Quick Start

```bash
# Run the echo server example
cargo run --example echo-server -p quic-reverse

# In another terminal, run the echo client
cargo run --example echo-client -p quic-reverse -- echo/uppercase "Hello World"
# Output: HELLO WORLD
```

See [Examples](#examples) for more details and [crates/quic-reverse/examples/](crates/quic-reverse/examples/) for full source code.

## Installation

Add quic-reverse to your `Cargo.toml`:

```toml
[dependencies]
quic-reverse = "0.1"
```

The library uses Quinn as the default QUIC implementation. If you need a different transport, disable default features:

```toml
[dependencies]
quic-reverse = { version = "0.1", default-features = false }
```

## Usage

### Server (Responder)

The server accepts incoming QUIC connections and handles stream open requests from clients.

```rust
use quic_reverse::{Config, ControlEvent, Role, Session};
use quic_reverse_transport::QuinnConnection;

// Wrap your Quinn connection
let quinn_conn = QuinnConnection::new(connection);
let config = Config::new().with_agent("my-server/1.0");

// Create and start the session
let session = Session::new(quinn_conn, Role::Server, config);
let mut handle = session.start().await?;

// Process control messages
loop {
    match handle.process_message().await? {
        Some(ControlEvent::OpenRequest { request_id, service, .. }) => {
            // Accept or reject based on service name
            if service.as_str() == "ssh" {
                handle.accept_open(request_id, stream_id).await?;
                // Open a data stream back to the client
                let (send, recv) = connection.open_bi().await?;
                // Handle the stream...
            } else {
                handle.reject_open(request_id, RejectCode::UnsupportedService, None).await?;
            }
        }
        Some(ControlEvent::CloseReceived { .. }) => break,
        None => break,
        _ => {}
    }
}
```

### Client (Requester)

The client initiates connections and requests streams to specific services.

```rust
use quic_reverse::{Config, Metadata, Role, Session};
use quic_reverse_transport::QuinnConnection;

let quinn_conn = QuinnConnection::new(connection);
let config = Config::new().with_agent("my-client/1.0");

let session = Session::new(quinn_conn, Role::Client, config);
let mut handle = session.start().await?;

// Request a stream to a service
let (mut send, mut recv) = handle.open("ssh", Metadata::Empty).await?;

// Use the stream for bidirectional communication
send.write_all(b"hello").await?;
```

## Architecture

quic-reverse is organized into three crates:

| Crate | Purpose |
|-------|---------|
| `quic-reverse` | Public API: Session, Config, Error types |
| `quic-reverse-control` | Protocol messages, framing, serialization |
| `quic-reverse-transport` | Transport traits, Quinn adapter, mock transport |

The protocol uses a dedicated control stream for signaling, separate from data streams:

```
Client                              Server
  │                                   │
  │──── Hello ─────────────────────►  │
  │◄─── Hello ─────────────────────── │
  │──── HelloAck ──────────────────►  │
  │◄─── HelloAck ──────────────────── │
  │                                   │
  │          [Session Ready]          │
  │                                   │
  │──── OpenRequest ───────────────►  │
  │◄─── OpenResponse (accept) ─────── │
  │◄════ Data Stream ════════════════►│
  │                                   │
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for design rationale and [PROTOCOL.md](PROTOCOL.md) for wire format details.

## Configuration

Sessions are configured using `Config`:

```rust
use quic_reverse::Config;
use std::time::Duration;

let config = Config::new()
    .with_agent("my-app/1.0")
    .with_open_timeout(Duration::from_secs(30))
    .with_ping_timeout(Duration::from_secs(10))
    .with_max_inflight_opens(16)
    .with_max_concurrent_streams(256);
```

### Timeouts

| Setting | Default | Description |
|---------|---------|-------------|
| `open_timeout` | 30s | How long to wait for an open request response |
| `stream_bind_timeout` | 10s | How long to wait for the data stream after acceptance |
| `negotiation_timeout` | 30s | How long to wait for the handshake to complete |
| `ping_timeout` | 10s | How long to wait for a pong response |

## Examples

The repository includes working examples demonstrating the library:

```bash
# Basic example using mock transport
cargo run --example basic -p quic-reverse

# Multi-service echo server (uses real QUIC)
cargo run --example echo-server -p quic-reverse

# Echo client
cargo run --example echo-client -p quic-reverse echo/uppercase "Hello World"
```

The echo server demonstrates multiplexing with three services:
- `echo/plain` - Returns input unchanged
- `echo/uppercase` - Returns input in uppercase
- `echo/reverse` - Returns input reversed

## Error Handling

The library provides structured error types for different failure modes:

```rust
use quic_reverse::{Error, TimeoutKind};

match handle.open("service", Metadata::Empty).await {
    Ok((send, recv)) => { /* use streams */ }
    Err(Error::Timeout(TimeoutKind::OpenRequest)) => { /* request timed out */ }
    Err(Error::StreamRejected { code, reason }) => { /* server rejected */ }
    Err(Error::SessionClosed) => { /* session ended */ }
    Err(e) => { /* other error */ }
}
```

## Observability

quic-reverse uses the `tracing` crate for structured logging. Enable tracing in your application:

```rust
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

Log levels follow this convention:
- `trace` - Low-level I/O operations
- `debug` - Protocol operations and state changes
- `info` - Session lifecycle events
- `warn`/`error` - Problems requiring attention

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Design rationale and architectural decisions
- [PROTOCOL.md](PROTOCOL.md) - Wire protocol specification
- [Examples README](crates/quic-reverse/examples/README.md) - Example documentation

## License

Licensed under Apache-2.0.
