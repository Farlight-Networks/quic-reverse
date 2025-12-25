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

//! Stream registry for tracking pending and active streams.
//!
//! The registry maintains state for:
//! - Pending open requests awaiting responses
//! - Active streams mapped by logical stream ID
//! - Request ID generation

use quic_reverse_control::{Metadata, OpenRequest, ServiceId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::oneshot;

/// Information about a pending open request.
#[derive(Debug)]
pub struct PendingOpen {
    /// The service being requested.
    #[allow(dead_code)] // Part of public API for future use
    pub service: ServiceId,
    /// Metadata sent with the request.
    #[allow(dead_code)] // Part of public API for future use
    pub metadata: Metadata,
    /// Channel to send the result when the response arrives.
    pub response_tx: oneshot::Sender<OpenResult>,
}

/// Result of an open request.
#[derive(Debug)]
pub enum OpenResult {
    /// Request accepted with the assigned logical stream ID.
    Accepted { logical_stream_id: u64 },
    /// Request rejected with code and optional reason.
    Rejected {
        code: quic_reverse_control::RejectCode,
        reason: Option<String>,
    },
}

/// Information about an active stream.
#[derive(Debug)]
pub struct ActiveStream {
    /// The service this stream belongs to.
    #[allow(dead_code)] // Part of public API for future use
    pub service: ServiceId,
    /// Metadata associated with the stream.
    #[allow(dead_code)] // Part of public API for future use
    pub metadata: Metadata,
    /// Request ID that created this stream.
    #[allow(dead_code)] // Part of public API for future use
    pub request_id: u64,
}

/// Registry for tracking stream state.
#[derive(Debug)]
pub struct StreamRegistry {
    /// Counter for generating unique request IDs.
    next_request_id: AtomicU64,
    /// Counter for generating unique logical stream IDs.
    #[allow(dead_code)] // Used by next_logical_stream_id() for future use
    next_logical_stream_id: AtomicU64,
    /// Pending open requests, keyed by request ID.
    pending_opens: HashMap<u64, PendingOpen>,
    /// Active streams, keyed by logical stream ID.
    active_streams: HashMap<u64, ActiveStream>,
    /// Maximum allowed pending opens.
    max_pending: usize,
    /// Maximum allowed concurrent streams.
    max_concurrent: usize,
}

impl StreamRegistry {
    /// Creates a new stream registry with the specified limits.
    #[must_use]
    pub fn new(max_pending: usize, max_concurrent: usize) -> Self {
        Self {
            next_request_id: AtomicU64::new(1),
            next_logical_stream_id: AtomicU64::new(1),
            pending_opens: HashMap::new(),
            active_streams: HashMap::new(),
            max_pending,
            max_concurrent,
        }
    }

    /// Generates a new unique request ID.
    pub fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Generates a new unique logical stream ID.
    #[allow(dead_code)] // Public API for future use
    pub fn next_logical_stream_id(&self) -> u64 {
        self.next_logical_stream_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns the number of pending open requests.
    #[must_use]
    #[allow(dead_code)] // Public API for future use
    pub fn pending_count(&self) -> usize {
        self.pending_opens.len()
    }

    /// Returns the number of active streams.
    #[must_use]
    #[allow(dead_code)] // Public API for future use
    pub fn active_count(&self) -> usize {
        self.active_streams.len()
    }

    /// Returns true if we can accept more pending opens.
    #[must_use]
    pub fn can_open(&self) -> bool {
        self.pending_opens.len() < self.max_pending
            && self.active_streams.len() < self.max_concurrent
    }

    /// Returns true if we can accept more streams.
    #[must_use]
    pub fn can_accept_stream(&self) -> bool {
        self.active_streams.len() < self.max_concurrent
    }

    /// Registers a new pending open request.
    ///
    /// Returns `None` if the limit has been reached.
    pub fn register_pending(
        &mut self,
        request: &OpenRequest,
        response_tx: oneshot::Sender<OpenResult>,
    ) -> Option<()> {
        if !self.can_open() {
            return None;
        }

        self.pending_opens.insert(
            request.request_id,
            PendingOpen {
                service: request.service.clone(),
                metadata: request.metadata.clone(),
                response_tx,
            },
        );

        Some(())
    }

    /// Removes and returns a pending open by request ID.
    pub fn take_pending(&mut self, request_id: u64) -> Option<PendingOpen> {
        self.pending_opens.remove(&request_id)
    }

    /// Registers an active stream.
    ///
    /// Returns `None` if the limit has been reached.
    pub fn register_active(
        &mut self,
        logical_stream_id: u64,
        service: ServiceId,
        metadata: Metadata,
        request_id: u64,
    ) -> Option<()> {
        if !self.can_accept_stream() {
            return None;
        }

        self.active_streams.insert(
            logical_stream_id,
            ActiveStream {
                service,
                metadata,
                request_id,
            },
        );

        Some(())
    }

    /// Removes and returns an active stream by logical stream ID.
    pub fn remove_active(&mut self, logical_stream_id: u64) -> Option<ActiveStream> {
        self.active_streams.remove(&logical_stream_id)
    }

    /// Returns a reference to an active stream by logical stream ID.
    #[must_use]
    #[allow(dead_code)] // Public API for future use
    pub fn get_active(&self, logical_stream_id: u64) -> Option<&ActiveStream> {
        self.active_streams.get(&logical_stream_id)
    }

    /// Clears all pending opens, returning the senders for notification.
    #[allow(dead_code)] // Public API for future use
    pub fn clear_pending(&mut self) -> Vec<oneshot::Sender<OpenResult>> {
        self.pending_opens
            .drain()
            .map(|(_, pending)| pending.response_tx)
            .collect()
    }

    /// Clears all state.
    #[allow(dead_code)] // Public API for future use
    pub fn clear(&mut self) {
        self.pending_opens.clear();
        self.active_streams.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(id: u64, service: &str) -> OpenRequest {
        OpenRequest::new(id, service)
    }

    #[test]
    fn request_id_generation() {
        let registry = StreamRegistry::new(10, 100);
        let id1 = registry.next_request_id();
        let id2 = registry.next_request_id();
        let id3 = registry.next_request_id();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn logical_stream_id_generation() {
        let registry = StreamRegistry::new(10, 100);
        let id1 = registry.next_logical_stream_id();
        let id2 = registry.next_logical_stream_id();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn register_pending_respects_limit() {
        let mut registry = StreamRegistry::new(2, 100);
        let (tx1, _rx1) = oneshot::channel();
        let (tx2, _rx2) = oneshot::channel();
        let (tx3, _rx3) = oneshot::channel();

        let req1 = make_request(1, "ssh");
        let req2 = make_request(2, "http");
        let req3 = make_request(3, "tcp");

        assert!(registry.register_pending(&req1, tx1).is_some());
        assert!(registry.register_pending(&req2, tx2).is_some());
        assert!(registry.register_pending(&req3, tx3).is_none()); // Limit reached

        assert_eq!(registry.pending_count(), 2);
    }

    #[test]
    fn take_pending() {
        let mut registry = StreamRegistry::new(10, 100);
        let (tx, _rx) = oneshot::channel();

        let req = make_request(42, "ssh");
        registry.register_pending(&req, tx);

        let pending = registry.take_pending(42);
        assert!(pending.is_some());
        assert_eq!(pending.unwrap().service.as_str(), "ssh");

        // Should be gone now
        assert!(registry.take_pending(42).is_none());
    }

    #[test]
    fn register_active_respects_limit() {
        let mut registry = StreamRegistry::new(10, 2);

        assert!(registry
            .register_active(1, "a".into(), Metadata::Empty, 1)
            .is_some());
        assert!(registry
            .register_active(2, "b".into(), Metadata::Empty, 2)
            .is_some());
        assert!(registry
            .register_active(3, "c".into(), Metadata::Empty, 3)
            .is_none()); // Limit reached

        assert_eq!(registry.active_count(), 2);
    }

    #[test]
    fn remove_active_frees_slot() {
        let mut registry = StreamRegistry::new(10, 2);

        registry.register_active(1, "a".into(), Metadata::Empty, 1);
        registry.register_active(2, "b".into(), Metadata::Empty, 2);

        assert!(!registry.can_accept_stream());

        registry.remove_active(1);

        assert!(registry.can_accept_stream());
        assert!(registry
            .register_active(3, "c".into(), Metadata::Empty, 3)
            .is_some());
    }

    #[test]
    fn clear_pending_returns_senders() {
        let mut registry = StreamRegistry::new(10, 100);
        let (tx1, _rx1) = oneshot::channel();
        let (tx2, _rx2) = oneshot::channel();

        let req1 = make_request(1, "a");
        let req2 = make_request(2, "b");

        registry.register_pending(&req1, tx1);
        registry.register_pending(&req2, tx2);

        let senders = registry.clear_pending();
        assert_eq!(senders.len(), 2);
        assert_eq!(registry.pending_count(), 0);
    }

    #[test]
    fn can_open_considers_both_limits() {
        let mut registry = StreamRegistry::new(2, 3);

        // Fill up active streams
        registry.register_active(1, "a".into(), Metadata::Empty, 1);
        registry.register_active(2, "b".into(), Metadata::Empty, 2);
        registry.register_active(3, "c".into(), Metadata::Empty, 3);

        // Can't open because active limit is reached
        assert!(!registry.can_open());

        // Free one active
        registry.remove_active(1);

        // Now we can open
        assert!(registry.can_open());

        // Fill pending
        let (tx1, _) = oneshot::channel();
        let (tx2, _) = oneshot::channel();
        registry.register_pending(&make_request(10, "x"), tx1);
        registry.register_pending(&make_request(11, "y"), tx2);

        // Can't open because pending limit is reached
        assert!(!registry.can_open());
    }
}
