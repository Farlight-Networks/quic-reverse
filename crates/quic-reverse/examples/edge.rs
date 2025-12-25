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

//! Edge device example demonstrating reverse-initiated streams.
//!
//! This example simulates a device behind NAT that connects outbound to a relay
//! and exposes local services. The relay can then open streams to access these
//! services without the edge device needing to accept inbound connections.
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
//! # Available Services
//!
//! - `echo` - Echoes data back as-is
//! - `time` - Returns the current timestamp
//!
//! # Usage
//!
//! First, start the relay:
//!
//!     cargo run --example relay
//!
//! Then, in another terminal, start the edge:
//!
//!     cargo run --example edge
//!
//! The edge will connect to the relay. The relay will then open streams to the
//! edge's services and display the results.

mod common;

use common::{make_client_endpoint, parse_addr, DEFAULT_SERVER_ADDR};
use quic_reverse::{ClientEvent, CloseCode, Config, RejectCode, Role, Session, SessionClient};
use quic_reverse_transport::{Connection, QuinnConnection};
use std::time::SystemTime;
use tracing::{info, warn};

/// Services exposed by this edge device.
const SERVICES: &[&str] = &["echo", "time"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let relay_addr = parse_addr(std::env::args().nth(1).as_deref(), DEFAULT_SERVER_ADDR)?;

    info!("Edge device starting");
    info!("Exposing services: {:?}", SERVICES);

    // Read the relay's certificate from the temp file (written by relay)
    let cert_path = std::env::temp_dir().join("quic-reverse-relay.der");
    let cert_der = std::fs::read(&cert_path).map_err(|e| {
        format!(
            "Failed to read relay certificate from {}: {}. Is the relay running?",
            cert_path.display(),
            e
        )
    })?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);

    info!("Connecting to relay at {} ...", relay_addr);

    let endpoint = make_client_endpoint(vec![cert])?;
    let connection = endpoint.connect(relay_addr, "localhost")?.await?;

    info!("Connected to relay");

    // Wrap the QUIC connection for quic-reverse
    let quinn_conn = QuinnConnection::new(connection.clone());

    // Create session as Client (we initiated the QUIC connection)
    let config = Config::new().with_agent("edge/1.0");
    let session = Session::new(quinn_conn.clone(), Role::Client, config);

    // Start the session (performs Hello/HelloAck negotiation)
    let handle = session.start().await?;

    info!(
        "Session established with relay (agent: {:?})",
        session.negotiated_params().and_then(|p| p.remote_agent)
    );

    // Convert to SessionClient with event channel for handling incoming requests
    let (client, mut events) = SessionClient::with_events(handle);

    // Track logical stream IDs
    let mut next_stream_id: u64 = 1;

    // Process incoming events from the relay
    while let Some(event) = events.recv().await {
        match event {
            ClientEvent::OpenRequest {
                request_id,
                service,
                ..
            } => {
                let service_name = service.as_str();
                info!("Relay requested service: {}", service_name);

                if SERVICES.contains(&service_name) {
                    // Accept the request and assign a logical stream ID
                    let stream_id = next_stream_id;
                    next_stream_id += 1;
                    client.accept_open(request_id, stream_id).await?;

                    // Open a bidirectional data stream and bind it to the logical stream ID
                    let (mut send, recv) = quinn_conn.open_bi().await?;
                    client.bind_stream(&mut send, stream_id).await?;

                    info!("Opened stream {} for service '{}'", stream_id, service_name);

                    // Spawn a task to handle this service
                    let svc = service_name.to_string();
                    tokio::spawn(async move {
                        if let Err(e) = handle_service(&svc, send, recv).await {
                            warn!("Service '{}' error: {}", svc, e);
                        }
                    });
                } else {
                    warn!("Unknown service requested: {}", service_name);
                    client
                        .reject_open(
                            request_id,
                            RejectCode::UnsupportedService,
                            Some(format!("unknown service: {}", service_name)),
                        )
                        .await?;
                }
            }

            ClientEvent::StreamClosed {
                logical_stream_id,
                code,
            } => {
                info!(
                    "Stream {} closed by relay (code: {:?})",
                    logical_stream_id, code
                );
            }

            ClientEvent::Closing { code, reason } => {
                info!(
                    "Relay closed session: {:?} ({})",
                    code,
                    reason.as_deref().unwrap_or("no reason")
                );
                break;
            }

            ClientEvent::PingReceived { sequence } => {
                info!("Received ping {}", sequence);
            }
        }
    }

    // Graceful shutdown
    let _ = client.close(CloseCode::Normal, None).await;
    endpoint.wait_idle().await;

    info!("Edge device disconnected");
    Ok(())
}

/// Handle a service request on the given stream.
async fn handle_service(
    service: &str,
    mut send: quic_reverse::QuinnSendStream,
    mut recv: quic_reverse::QuinnRecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use quic_reverse::SendStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    match service {
        "echo" => {
            // Echo: read data and send it back
            let mut buf = vec![0u8; 4096];
            loop {
                match recv.read(&mut buf).await? {
                    0 => break,
                    n => {
                        let data = &buf[..n];
                        info!("[echo] Received {} bytes, echoing back", n);
                        send.write_all(data).await?;
                    }
                }
            }
        }

        "time" => {
            // Time: send current timestamp and close
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            let timestamp = format!("{}", now.as_secs());
            info!("[time] Sending timestamp: {}", timestamp);
            send.write_all(timestamp.as_bytes()).await?;
        }

        _ => {
            warn!("[{}] Unknown service", service);
        }
    }

    send.finish().await?;
    info!("[{}] Stream finished", service);
    Ok(())
}
