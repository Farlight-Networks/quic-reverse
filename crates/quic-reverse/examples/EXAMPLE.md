# quic-reverse Examples

This directory contains examples demonstrating the core functionality of quic-reverse: reverse-initiated streams over QUIC.

## The Reverse Connection Pattern

In a typical client-server model, the client initiates a connection and requests services from the server. With quic-reverse, this is inverted: the edge device initiates the QUIC connection to a relay, but the relay opens streams to access services on the edge device.

This pattern is useful when the edge device is behind NAT or a firewall and cannot accept incoming connections.

```text
Edge Device (behind NAT)          Relay (public)
────────────────────────         ──────────────
     │                                  │
     │──── QUIC connect ───────────────>│  Edge initiates connection
     │                                  │
     │<─── open("echo") ───────────────│  Relay requests stream
     │                                  │
     │──── accept, send data stream ──>│  Edge opens data stream back
     │                                  │
     │<════ bidirectional data ════════>│
```

The edge device:
1. Initiates the QUIC connection to the relay (outbound only)
2. Runs `process_message()` to receive `OpenRequest` events from the relay
3. Accepts or rejects requests based on the service name
4. Opens data streams back to the relay for accepted requests

The relay:
1. Accepts incoming QUIC connections from edge devices
2. Calls `handle.open("service_name", ...)` to request streams to edge services
3. Receives data streams opened by the edge device
4. Communicates over the bidirectional stream

## Running the Examples

Open two terminals.

**Terminal 1: Start the relay**

```sh
cargo run --example relay
```

The relay will:
- Listen on 127.0.0.1:4433 for edge connections
- Write a self-signed certificate to a temp file for the edge to use

**Terminal 2: Start the edge device**

```sh
cargo run --example edge
```

The edge will:
- Read the relay's certificate from the temp file
- Connect to the relay
- Expose two services: `echo` and `time`

Once connected, the relay will automatically:
1. Open a stream to the `time` service and print the timestamp
2. Open a stream to the `echo` service and exchange a message
3. Attempt to open an unknown `foobar` service (demonstrating rejection)

## Available Services

The edge device exposes:

| Service | Description |
|---------|-------------|
| `echo`  | Echoes received data back to the sender |
| `time`  | Returns the current Unix timestamp |

## Example Files

| File | Description |
|------|-------------|
| `relay.rs` | Public relay server that opens streams to connected edge devices |
| `edge.rs` | Edge device behind NAT that exposes services to the relay |
| `common/mod.rs` | Shared TLS utilities for certificate generation |
| `basic.rs` | Minimal example showing session establishment with mock transport |

## Key Concepts Demonstrated

- **Session establishment**: Hello/HelloAck negotiation
- **Reverse stream opening**: Relay calls `handle.open()` to access edge services
- **Service multiplexing**: Multiple services on one connection
- **Request rejection**: Edge rejects unknown service requests
- **Graceful shutdown**: Proper session close handling
