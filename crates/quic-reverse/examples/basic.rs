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

//! Basic example demonstrating quic-reverse session establishment.
//!
//! This example shows:
//! - Creating client and server sessions
//! - Negotiation handshake
//! - Session close
//!
//! For a full example with stream operations, see the integration tests.
//!
//! Run with: cargo run --example basic -p quic-reverse

use quic_reverse::{CloseCode, Config, ControlEvent, Role, Session};
use quic_reverse_transport::mock_connection_pair;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for observability
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("=== quic-reverse Basic Example ===\n");

    // Create a mock connection pair (in production, use quinn::Connection)
    let (conn_client, conn_server) = mock_connection_pair();

    // Configure both sides
    let client_config = Config::new()
        .with_agent("example-client/1.0")
        .with_ping_timeout(Duration::from_secs(5));

    let server_config = Config::new().with_agent("example-server/1.0");

    // Create sessions
    println!("Creating sessions...");
    let client_session = Session::new(conn_client, Role::Client, client_config);
    let server_session = Session::new(conn_server, Role::Server, server_config);

    println!("  Client state: {:?}", client_session.state());
    println!("  Server state: {:?}", server_session.state());

    // Start both sessions concurrently (performs negotiation)
    println!("\nStarting negotiation...");
    let client_start = tokio::spawn({
        let session = client_session.clone();
        async move { session.start().await }
    });

    let server_start = tokio::spawn({
        let session = server_session.clone();
        async move { session.start().await }
    });

    let mut client_handle = client_start.await??;
    let mut server_handle = server_start.await??;

    println!("Negotiation complete!");
    println!("  Client state: {:?}", client_session.state());
    println!("  Server state: {:?}", server_session.state());

    if let Some(params) = client_session.negotiated_params() {
        println!("\nNegotiated parameters:");
        println!("  Protocol version: {}", params.version);
        println!("  Features: {:?}", params.features);
        println!("  Remote agent: {:?}", params.remote_agent);
    }

    // Graceful shutdown
    println!("\n--- Graceful Shutdown ---");
    client_handle
        .close(CloseCode::Normal, Some("Example complete".into()))
        .await?;
    println!("  Client: Sent close");

    // Server receives close
    match server_handle.process_message().await? {
        Some(ControlEvent::CloseReceived { code, reason }) => {
            println!("  Server: Received close: {:?} ({:?})", code, reason);
        }
        other => println!("  Server: Unexpected: {:?}", other),
    }

    println!("\n=== Example Complete ===");
    Ok(())
}
