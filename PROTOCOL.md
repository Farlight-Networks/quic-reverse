# quic-reverse Wire Protocol Specification

## Overview

The quic-reverse protocol enables reverse stream establishment over QUIC connections. This document specifies the wire format for control messages and data stream binding.

The protocol operates on a dedicated control stream (the first bidirectional stream opened after QUIC connection establishment) and uses header-bound data streams for application traffic.

## Protocol Version

Current version: 1

Version negotiation occurs during the Hello/HelloAck handshake. Both peers must agree on a common version to proceed.

## Control Stream

The control stream carries all protocol control messages using length-prefixed framing. The peer that opened the QUIC connection opens the first bidirectional stream, which becomes the control stream.

### Frame Format

All control messages are transmitted as length-prefixed frames:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Length (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Payload (variable)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Length field is a 32-bit big-endian unsigned integer specifying the payload size in bytes. The maximum frame size is 65536 bytes (64 KB). Frames exceeding this limit must be rejected.

### Message Encoding

The payload contains a bincode-encoded `ProtocolMessage` enum. Bincode is a compact binary serialization format. The message type is encoded as the first byte(s) of the payload (enum discriminant).

## Control Messages

### Hello

Sent by both peers after control stream establishment. Contains version and feature information.

| Field | Type | Description |
|-------|------|-------------|
| protocol_version | u16 | Protocol version supported (currently 1) |
| features | u32 | Bitfield of supported features |
| agent | Option\<String\> | Optional agent identifier |

Feature flags:
- Bit 0 (`0x01`): STRUCTURED_METADATA - Support for structured key-value metadata
- Bit 1 (`0x02`): PING_PONG - Support for keep-alive ping/pong messages
- Bit 2 (`0x04`): STREAM_PRIORITY - Support for stream priority hints

### HelloAck

Sent after receiving the peer's Hello. Confirms negotiated parameters.

| Field | Type | Description |
|-------|------|-------------|
| selected_version | u16 | Negotiated protocol version |
| selected_features | u32 | Intersection of both peers' features |

### OpenRequest

Requests the peer to open a reverse stream back to the sender.

| Field | Type | Description |
|-------|------|-------------|
| request_id | u64 | Unique request identifier for correlation |
| service | String | Target service identifier |
| metadata | Metadata | Optional request metadata |
| flags | u8 | Request flags |

Open flags:
- Bit 0 (`0x01`): UNIDIRECTIONAL - Request a unidirectional stream
- Bit 1 (`0x02`): HIGH_PRIORITY - High priority stream hint

Metadata variants:
- Empty: No metadata
- Bytes: Raw byte payload
- Structured: Key-value map (requires STRUCTURED_METADATA feature)

### OpenResponse

Response to an OpenRequest.

| Field | Type | Description |
|-------|------|-------------|
| request_id | u64 | Request ID from corresponding OpenRequest |
| status | OpenStatus | Accepted or Rejected with code |
| reason | Option\<String\> | Optional rejection reason |
| logical_stream_id | Option\<u64\> | Assigned stream ID (if accepted) |

Reject codes:
- ServiceUnavailable: Service temporarily unavailable
- UnsupportedService: Service not recognized
- LimitExceeded: Resource limits reached
- Unauthorized: Request not authorized
- InternalError: Internal processing error

### StreamClose

Notifies the peer that a stream has closed.

| Field | Type | Description |
|-------|------|-------------|
| logical_stream_id | u64 | Logical stream ID being closed |
| code | u8 | Close code |
| reason | Option\<String\> | Optional close reason |

Close codes:
- 0: Normal - Clean closure
- 1: Error - Error condition
- 2: Timeout - Timeout expired
- 3: Reset - Stream was reset

### Ping

Keep-alive ping message (requires PING_PONG feature).

| Field | Type | Description |
|-------|------|-------------|
| sequence | u64 | Sequence number for matching Pong |

### Pong

Response to a Ping message.

| Field | Type | Description |
|-------|------|-------------|
| sequence | u64 | Sequence number from corresponding Ping |

## Data Streams

Data streams carry application traffic. Each data stream is bound to a logical stream ID established through the OpenRequest/OpenResponse exchange.

### StreamBind Frame

The first bytes sent on a data stream must be a StreamBind frame. This frame correlates the QUIC stream with a logical stream ID from the control plane.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Magic (0x51524256 "QRBV")                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |                                               |
+-+-+-+-+-+-+-+-+         LogicalStreamId (64)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |
+-+-+-+-+-+-+-+-+
```

Total size: 13 bytes

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Magic | 0 | 4 | Magic bytes: `0x51`, `0x52`, `0x42`, `0x56` ("QRBV") |
| Version | 4 | 1 | StreamBind version (currently 1) |
| LogicalStreamId | 5 | 8 | Big-endian u64 logical stream ID |

The receiving peer must validate the magic bytes and version before processing. Invalid frames must result in stream rejection.

## Session Lifecycle

### Connection Establishment

1. One peer initiates a QUIC connection to the other
2. The initiator opens the first bidirectional stream (control stream)
3. Both peers send Hello messages simultaneously
4. Both peers send HelloAck messages after receiving the peer's Hello
5. The session enters the Ready state

### Reverse Stream Flow

1. Peer A sends OpenRequest with a unique request_id
2. Peer B receives the request and decides to accept or reject
3. Peer B sends OpenResponse with the same request_id
4. If accepted, Peer B opens a new QUIC bidirectional stream
5. Peer B sends StreamBind frame as first data on the new stream
6. Peer A receives the stream and validates the StreamBind
7. Both peers can now exchange application data on the stream

### Stream Closure

Either peer may close a stream at any time. The StreamClose message provides a mechanism for clean shutdown notification through the control stream, independent of QUIC stream reset.

### Session Termination

Sessions terminate when the QUIC connection closes. Graceful shutdown involves:
1. Finishing pending stream operations
2. Sending StreamClose for active streams
3. Closing the control stream
4. Closing the QUIC connection

## Error Handling

### Protocol Errors

Protocol violations result in immediate session termination:
- Invalid frame magic or version in StreamBind
- Frame size exceeding maximum
- Malformed message encoding
- Version mismatch during negotiation

### Application Errors

Application-level errors are communicated through OpenResponse rejection or StreamClose with an error code. These do not terminate the session.

## Security Considerations

The quic-reverse protocol relies on QUIC for transport security. Authentication and authorization are the responsibility of the application layer. The protocol itself does not provide:
- Peer authentication
- Message authentication codes
- End-to-end encryption beyond QUIC

Applications should implement appropriate authentication before allowing stream operations.

## Glossary

**Control Stream**: The dedicated bidirectional QUIC stream used for exchanging protocol control messages.

**Header-Bound Stream**: A data stream that begins with a StreamBind frame, correlating it to a logical stream ID from the control plane.

**Logical Stream ID**: A library-assigned identifier for streams, independent of QUIC stream IDs. Assigned by the peer accepting an OpenRequest.

**Reverse Stream**: A stream opened by the peer that accepted the QUIC connection, inverting the typical initiator/responder relationship.

**Service ID**: A string identifier for logical services, enabling multiplexing of multiple service types over a single session.

**Session**: The stateful context managing a QUIC connection with the quic-reverse protocol, including negotiation state and active streams.
