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

//! Reverse-initiated, multiplexed services over QUIC.
//!
//! `quic-reverse` is a library that enables servers to initiate streams back to clients
//! over an existing QUIC connection. This is useful for scenarios where:
//!
//! - Clients are behind NAT and cannot accept incoming connections
//! - Edge devices need to expose services to a central server
//! - Reverse tunneling is required without opening inbound ports
//!
//! # Architecture
//!
//! The library sits atop an existing QUIC connection and adds:
//!
//! - An explicit control plane for stream lifecycle management
//! - Reverse-initiated stream semantics
//! - Service multiplexing via service identifiers
//! - Well-defined negotiation, backpressure, and error handling
//!
//! # Example
//!
//! ```ignore
//! use quic_reverse::{Session, Config, Role};
//!
//! // Wrap an existing QUIC connection
//! let session = Session::new(connection, Role::Client, Config::default());
//!
//! // Start the session (performs negotiation)
//! let mut handle = session.start().await?;
//!
//! // Open a reverse stream to a service
//! let (send, recv) = handle.open("ssh", Metadata::Empty).await?;
//! ```

pub use quic_reverse_control::{
    CloseCode, Features, Metadata, OpenFlags, RejectCode, ServiceId, StreamBind,
};
pub use quic_reverse_transport::{Connection, RecvStream, SendStream};

#[cfg(feature = "quinn")]
pub use quic_reverse_transport::{QuinnConnection, QuinnRecvStream, QuinnSendStream};

mod client;
mod config;
mod control;
mod error;
mod negotiation;
mod registry;
mod session;
mod state;

pub use client::{ClientEvent, SessionClient};
pub use config::Config;
pub use error::Error;
pub use negotiation::NegotiatedParams;
pub use session::{ControlEvent, Session, SessionHandle};
pub use state::State;

/// Role in a quic-reverse session.
///
/// The role primarily affects example code and documentation.
/// The protocol itself is largely symmetrical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The client role (typically the QUIC connection initiator).
    Client,
    /// The server role (typically the QUIC connection acceptor).
    Server,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
        }
    }
}
