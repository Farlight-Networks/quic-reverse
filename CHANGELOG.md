# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-XX-XX

### Added

- Initial release of quic-reverse
- `Session` and `SessionHandle` for managing reverse-stream sessions over QUIC
- `SessionClient` for concurrent access to sessions from multiple tasks
- Control protocol with Hello/HelloAck handshake for version and feature negotiation
- `OpenRequest`/`OpenResponse` for stream lifecycle management
- `StreamBind` framing for correlating data streams to control plane requests
- Ping/Pong keep-alive mechanism
- Graceful session close with `StreamClose` messages
- Transport abstraction layer (`quic-reverse-transport` crate)
  - Quinn adapter for production use
  - Mock transport for testing
- Protocol implementation (`quic-reverse-control` crate)
  - Length-prefixed framing (4-byte big-endian length + bincode payload)
  - All protocol message types with serde serialization
- Configuration options for timeouts, concurrency limits, and feature flags
- Working examples: basic, relay, and edge

[Unreleased]: https://github.com/Farlight-Networks/quic-reverse/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Farlight-Networks/quic-reverse/releases/tag/v0.1.0

