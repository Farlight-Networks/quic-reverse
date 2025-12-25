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

//! Quinn adapter implementation.
//!
//! This module provides implementations of the transport traits
//! for Quinn's connection and stream types.

use crate::{Connection, RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wrapper around a Quinn connection implementing the `Connection` trait.
#[derive(Clone)]
pub struct QuinnConnection {
    inner: quinn::Connection,
}

impl QuinnConnection {
    /// Creates a new `QuinnConnection` from a Quinn connection.
    #[must_use]
    pub const fn new(connection: quinn::Connection) -> Self {
        Self { inner: connection }
    }

    /// Returns a reference to the underlying Quinn connection.
    #[must_use]
    pub const fn inner(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Consumes this wrapper and returns the underlying Quinn connection.
    #[must_use]
    pub fn into_inner(self) -> quinn::Connection {
        self.inner
    }
}

impl From<quinn::Connection> for QuinnConnection {
    fn from(connection: quinn::Connection) -> Self {
        Self::new(connection)
    }
}

impl Connection for QuinnConnection {
    type SendStream = QuinnSendStream;
    type RecvStream = QuinnRecvStream;
    type OpenError = quinn::ConnectionError;
    type AcceptError = quinn::ConnectionError;

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::OpenError> {
        let (send, recv) = self.inner.open_bi().await?;
        Ok((QuinnSendStream::new(send), QuinnRecvStream::new(recv)))
    }

    async fn accept_bi(
        &self,
    ) -> Result<Option<(Self::SendStream, Self::RecvStream)>, Self::AcceptError> {
        match self.inner.accept_bi().await {
            Ok((send, recv)) => Ok(Some((
                QuinnSendStream::new(send),
                QuinnRecvStream::new(recv),
            ))),
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(quinn::VarInt::from_u32(code), reason);
    }

    fn is_open(&self) -> bool {
        self.inner.close_reason().is_none()
    }
}

/// Wrapper around a Quinn send stream implementing the `SendStream` trait.
pub struct QuinnSendStream {
    inner: quinn::SendStream,
}

impl QuinnSendStream {
    /// Creates a new `QuinnSendStream` from a Quinn send stream.
    #[must_use]
    pub const fn new(stream: quinn::SendStream) -> Self {
        Self { inner: stream }
    }

    /// Returns a reference to the underlying Quinn send stream.
    #[must_use]
    pub const fn inner(&self) -> &quinn::SendStream {
        &self.inner
    }

    /// Returns a mutable reference to the underlying Quinn send stream.
    pub fn inner_mut(&mut self) -> &mut quinn::SendStream {
        &mut self.inner
    }
}

impl AsyncWrite for QuinnSendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Use the AsyncWrite trait implementation from quinn::SendStream
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

impl SendStream for QuinnSendStream {
    type FinishError = quinn::ClosedStream;

    async fn finish(&mut self) -> Result<(), Self::FinishError> {
        self.inner.finish()
    }

    fn reset(&mut self, code: u32) {
        let _ = self.inner.reset(quinn::VarInt::from_u32(code));
    }
}

/// Wrapper around a Quinn receive stream implementing the `RecvStream` trait.
pub struct QuinnRecvStream {
    inner: quinn::RecvStream,
}

impl QuinnRecvStream {
    /// Creates a new `QuinnRecvStream` from a Quinn receive stream.
    #[must_use]
    pub const fn new(stream: quinn::RecvStream) -> Self {
        Self { inner: stream }
    }

    /// Returns a reference to the underlying Quinn receive stream.
    #[must_use]
    pub const fn inner(&self) -> &quinn::RecvStream {
        &self.inner
    }

    /// Returns a mutable reference to the underlying Quinn receive stream.
    pub fn inner_mut(&mut self) -> &mut quinn::RecvStream {
        &mut self.inner
    }
}

impl AsyncRead for QuinnRecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        <quinn::RecvStream as AsyncRead>::poll_read(Pin::new(&mut self.inner), cx, buf)
    }
}

impl RecvStream for QuinnRecvStream {
    fn stop(&mut self, code: u32) {
        let _ = self.inner.stop(quinn::VarInt::from_u32(code));
    }
}

/// Shared connection wrapper for use cases requiring `Arc`.
///
/// This is useful when the connection needs to be shared across
/// multiple async tasks.
#[derive(Clone)]
pub struct SharedQuinnConnection {
    inner: Arc<QuinnConnection>,
}

impl SharedQuinnConnection {
    /// Creates a new shared connection wrapper.
    #[must_use]
    pub fn new(connection: quinn::Connection) -> Self {
        Self {
            inner: Arc::new(QuinnConnection::new(connection)),
        }
    }
}

impl Connection for SharedQuinnConnection {
    type SendStream = QuinnSendStream;
    type RecvStream = QuinnRecvStream;
    type OpenError = quinn::ConnectionError;
    type AcceptError = quinn::ConnectionError;

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::OpenError> {
        self.inner.open_bi().await
    }

    async fn accept_bi(
        &self,
    ) -> Result<Option<(Self::SendStream, Self::RecvStream)>, Self::AcceptError> {
        self.inner.accept_bi().await
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code, reason);
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quinn_connection_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<QuinnConnection>();
        assert_send_sync::<SharedQuinnConnection>();
    }

    #[test]
    fn quinn_streams_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<QuinnSendStream>();
        assert_send::<QuinnRecvStream>();
    }
}
