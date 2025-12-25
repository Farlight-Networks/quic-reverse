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

//! Relay server example demonstrating reverse-initiated streams.
//!
//! This example simulates a public relay that accepts connections from edge
//! devices and then opens streams to access services on those devices.
//!
//! # Architecture
//!
//! ```text
//! Edge Device (behind NAT)          Relay (public)
//! ────────────────────────         ──────────────
//!      │                                  │
//!      │──── QUIC connect ───────────────>│  Edge initiates connection
//!      │                                  │
//!      │<─── open("echo") ───────────────│  Relay requests stream
//!      │                                  │
//!      │──── accept, send data stream ──>│  Edge opens data stream back
//!      │                                  │
//!      │<════ bidirectional data ════════>│
//! ```
//!
//! # Usage
//!
//! Start the relay:
//!
//!     cargo run --example relay
//!
//! Then, in another terminal, start an edge device:
//!
//!     cargo run --example edge
//!
//! When an edge connects, the relay will:
//! 1. Open a stream to the "time" service and display the result
//! 2. Open a stream to the "echo" service and exchange messages
//! 3. Attempt to open an unknown service (demonstrating rejection)

mod common;

use common::{make_server_endpoint, parse_addr, DEFAULT_SERVER_ADDR};
use quic_reverse::{CloseCode, Config, Metadata, Role, SendStream, Session, SessionClient};
use quic_reverse_transport::QuinnConnection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .init();

    let bind_addr = parse_addr(std::env::args().nth(1).as_deref(), DEFAULT_SERVER_ADDR)?;

    info!("Relay server starting on {}", bind_addr);

    let (endpoint, certs) = make_server_endpoint(bind_addr)?;

    // Write certificate to temp file so edge devices can trust us
    let cert_path = std::env::temp_dir().join("quic-reverse-relay.der");
    std::fs::write(&cert_path, certs[0].as_ref())?;
    info!("Certificate written to: {}", cert_path.display());

    info!("Waiting for edge devices to connect...");

    while let Some(incoming) = endpoint.accept().await {
        let connection = incoming.await?;
        info!("Edge device connected from {}", connection.remote_address());

        tokio::spawn(async move {
            if let Err(e) = handle_edge(connection).await {
                error!("Edge connection error: {}", e);
            }
        });
    }

    Ok(())
}

/// Handle a connected edge device.
async fn handle_edge(
    connection: quinn::Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let quinn_conn = QuinnConnection::new(connection);

    // Create session as Server (we accepted the QUIC connection)
    let config = Config::new().with_agent("relay/1.0");
    let session = Session::new(quinn_conn, Role::Server, config);

    // Start the session (performs Hello/HelloAck negotiation)
    let handle = session.start().await?;

    info!(
        "Session established with edge (agent: {:?})",
        session.negotiated_params().and_then(|p| p.remote_agent)
    );

    // Convert to SessionClient for convenient concurrent operations
    let client = SessionClient::new(handle);

    // Call the "time" service
    info!("Opening stream to 'time' service...");
    match client.open("time", Metadata::Empty).await {
        Ok((mut send, mut recv)) => {
            send.finish().await?;
            let mut response = Vec::new();
            recv.read_to_end(&mut response).await?;
            let timestamp = String::from_utf8_lossy(&response);
            info!("Received timestamp from edge: {}", timestamp);
        }
        Err(e) => {
            warn!("Failed to open 'time' service: {}", e);
        }
    }

    // Call the "echo" service
    info!("Opening stream to 'echo' service...");
    match client.open("echo", Metadata::Empty).await {
        Ok((mut send, mut recv)) => {
            let message = b"Hello from the relay!";
            info!("Sending to echo: {:?}", String::from_utf8_lossy(message));
            send.write_all(message).await?;
            send.finish().await?;
            let mut response = Vec::new();
            recv.read_to_end(&mut response).await?;
            info!("Echo response: {:?}", String::from_utf8_lossy(&response));
        }
        Err(e) => {
            warn!("Failed to open 'echo' service: {}", e);
        }
    }

    // Try an unknown service to demonstrate rejection
    info!("Opening stream to unknown 'foobar' service...");
    match client.open("foobar", Metadata::Empty).await {
        Ok(_) => {
            warn!("Unexpectedly succeeded opening 'foobar'");
        }
        Err(e) => {
            info!("Service 'foobar' rejected as expected: {}", e);
        }
    }

    // Close the session gracefully
    client
        .close(CloseCode::Normal, Some("Demo complete".into()))
        .await?;

    info!("Edge session complete");
    Ok(())
}
