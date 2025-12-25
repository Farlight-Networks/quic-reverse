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

//! Transport trait definitions.
//!
//! These traits abstract over QUIC connection and stream types,
//! enabling quic-reverse to work with different QUIC implementations.

use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

/// Abstraction over a QUIC connection.
///
/// This trait provides the minimal interface needed by quic-reverse
/// to open and accept bidirectional streams.
pub trait Connection: Send + Sync + 'static {
    /// The send stream type produced by this connection.
    type SendStream: SendStream;
    /// The receive stream type produced by this connection.
    type RecvStream: RecvStream;
    /// Error type for opening streams.
    type OpenError: std::error::Error + Send + Sync + 'static;
    /// Error type for accepting streams.
    type AcceptError: std::error::Error + Send + Sync + 'static;

    /// Opens a new bidirectional stream.
    ///
    /// Returns a future that resolves to a send/receive stream pair.
    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::SendStream, Self::RecvStream), Self::OpenError>> + Send;

    /// Accepts an incoming bidirectional stream.
    ///
    /// Returns a future that resolves to a send/receive stream pair,
    /// or `None` if the connection is closing.
    #[allow(clippy::type_complexity)]
    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<Option<(Self::SendStream, Self::RecvStream)>, Self::AcceptError>>
           + Send;

    /// Closes the connection with an error code and reason.
    fn close(&self, code: u32, reason: &[u8]);

    /// Returns true if the connection is still open.
    fn is_open(&self) -> bool;
}

/// Abstraction over a QUIC send stream.
///
/// Implementations must support async writing and graceful/abrupt shutdown.
pub trait SendStream: AsyncWrite + Send + Unpin + 'static {
    /// Error type for finishing the stream.
    type FinishError: std::error::Error + Send + Sync + 'static;

    /// Gracefully finishes the stream, signaling no more data will be sent.
    fn finish(&mut self) -> impl Future<Output = Result<(), Self::FinishError>> + Send;

    /// Abruptly resets the stream with an error code.
    fn reset(&mut self, code: u32);
}

/// Abstraction over a QUIC receive stream.
///
/// Implementations must support async reading and early termination.
pub trait RecvStream: AsyncRead + Send + Unpin + 'static {
    /// Stops reading from the stream, signaling to the peer that
    /// no more data will be read.
    fn stop(&mut self, code: u32);
}
