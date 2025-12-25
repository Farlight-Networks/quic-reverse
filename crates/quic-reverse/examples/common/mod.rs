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

//! Shared utilities for quic-reverse examples.
//!
//! Provides TLS configuration and QUIC connection setup helpers.

#![allow(dead_code)]

use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::{error::Error, net::SocketAddr, sync::Arc};

/// Default bind address for the server.
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:4433";

/// Generate a self-signed certificate for testing.
///
/// Returns (certificate chain, private key) suitable for rustls.
pub fn generate_self_signed_cert() -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn Error>,
> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())?;
    Ok((vec![cert_der], key_der))
}

/// Create a server endpoint with self-signed TLS.
pub fn make_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<(Endpoint, Vec<rustls::pki_types::CertificateDer<'static>>), Box<dyn Error>> {
    let (certs, key) = generate_self_signed_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)?;
    server_crypto.alpn_protocols = vec![b"quic-reverse-example".to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, certs))
}

/// Create a client endpoint that trusts the given server certificate.
pub fn make_client_endpoint(
    server_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> Result<Endpoint, Box<dyn Error>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in server_certs {
        roots.add(cert)?;
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"quic-reverse-example".to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Parse a socket address from string, with a default fallback.
pub fn parse_addr(addr: Option<&str>, default: &str) -> Result<SocketAddr, Box<dyn Error>> {
    let addr_str = addr.unwrap_or(default);
    Ok(addr_str.parse()?)
}
