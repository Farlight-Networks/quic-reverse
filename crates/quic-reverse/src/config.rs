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

//! Session configuration.

use quic_reverse_control::Features;
use std::time::Duration;

/// Configuration for a quic-reverse session.
#[derive(Debug, Clone)]
pub struct Config {
    /// Protocol versions supported by this session, in preference order.
    ///
    /// The highest mutually supported version will be selected during negotiation.
    pub supported_versions: Vec<u16>,

    /// Feature flags to advertise during negotiation.
    ///
    /// The intersection of both peers' features will be used.
    pub features: Features,

    /// Timeout for open requests awaiting a response.
    ///
    /// If no `OpenResponse` is received within this duration, the request fails.
    pub open_timeout: Duration,

    /// Timeout for binding a stream after receiving an accepted `OpenResponse`.
    ///
    /// If no stream with the matching logical stream ID arrives within this
    /// duration, the request fails.
    pub stream_bind_timeout: Duration,

    /// Timeout for the entire negotiation handshake.
    ///
    /// If negotiation doesn't complete within this duration, the session fails.
    pub negotiation_timeout: Duration,

    /// Maximum number of pending open requests.
    ///
    /// Attempts to open more streams than this limit will block until
    /// existing requests complete.
    pub max_inflight_opens: usize,

    /// Maximum number of concurrent active streams.
    ///
    /// New open requests will be rejected if this limit is reached.
    pub max_concurrent_streams: usize,

    /// Optional ping interval for keep-alive.
    ///
    /// If set, `Ping` messages will be sent at this interval when no
    /// other traffic is occurring. Requires the `PING_PONG` feature.
    pub ping_interval: Option<Duration>,

    /// Timeout for ping responses.
    ///
    /// If a `Pong` is not received within this duration after sending a `Ping`,
    /// the ping is considered failed. Defaults to 10 seconds.
    pub ping_timeout: Duration,

    /// Agent identifier sent in `Hello` messages.
    ///
    /// This is optional and used for debugging and diagnostics.
    pub agent: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            supported_versions: vec![1],
            features: Features::empty(),
            open_timeout: Duration::from_secs(30),
            stream_bind_timeout: Duration::from_secs(10),
            negotiation_timeout: Duration::from_secs(30),
            max_inflight_opens: 100,
            max_concurrent_streams: 1000,
            ping_interval: None,
            ping_timeout: Duration::from_secs(10),
            agent: None,
        }
    }
}

impl Config {
    /// Creates a new configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the supported protocol versions.
    #[must_use]
    pub fn with_versions(mut self, versions: Vec<u16>) -> Self {
        self.supported_versions = versions;
        self
    }

    /// Sets the feature flags.
    #[must_use]
    pub const fn with_features(mut self, features: Features) -> Self {
        self.features = features;
        self
    }

    /// Sets the open request timeout.
    #[must_use]
    pub const fn with_open_timeout(mut self, timeout: Duration) -> Self {
        self.open_timeout = timeout;
        self
    }

    /// Sets the stream binding timeout.
    #[must_use]
    pub const fn with_stream_bind_timeout(mut self, timeout: Duration) -> Self {
        self.stream_bind_timeout = timeout;
        self
    }

    /// Sets the negotiation timeout.
    #[must_use]
    pub const fn with_negotiation_timeout(mut self, timeout: Duration) -> Self {
        self.negotiation_timeout = timeout;
        self
    }

    /// Sets the maximum number of inflight open requests.
    #[must_use]
    pub const fn with_max_inflight_opens(mut self, max: usize) -> Self {
        self.max_inflight_opens = max;
        self
    }

    /// Sets the maximum number of concurrent streams.
    #[must_use]
    pub const fn with_max_concurrent_streams(mut self, max: usize) -> Self {
        self.max_concurrent_streams = max;
        self
    }

    /// Sets the ping interval for keep-alive.
    #[must_use]
    pub fn with_ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = Some(interval);
        self.features |= Features::PING_PONG;
        self
    }

    /// Sets the ping timeout.
    #[must_use]
    pub const fn with_ping_timeout(mut self, timeout: Duration) -> Self {
        self.ping_timeout = timeout;
        self
    }

    /// Sets the agent identifier.
    #[must_use]
    pub fn with_agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = Some(agent.into());
        self
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.supported_versions.is_empty() {
            return Err(ConfigError::NoSupportedVersions);
        }

        if self.max_inflight_opens == 0 {
            return Err(ConfigError::InvalidLimit("max_inflight_opens must be > 0"));
        }

        if self.max_concurrent_streams == 0 {
            return Err(ConfigError::InvalidLimit(
                "max_concurrent_streams must be > 0",
            ));
        }

        Ok(())
    }
}

/// Configuration validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// No supported protocol versions specified.
    #[error("at least one protocol version must be supported")]
    NoSupportedVersions,

    /// Invalid limit value.
    #[error("invalid limit: {0}")]
    InvalidLimit(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_builder() {
        let config = Config::new()
            .with_versions(vec![1, 2])
            .with_features(Features::STRUCTURED_METADATA)
            .with_open_timeout(Duration::from_secs(60))
            .with_max_concurrent_streams(500)
            .with_agent("test/1.0");

        assert_eq!(config.supported_versions, vec![1, 2]);
        assert!(config.features.contains(Features::STRUCTURED_METADATA));
        assert_eq!(config.open_timeout, Duration::from_secs(60));
        assert_eq!(config.max_concurrent_streams, 500);
        assert_eq!(config.agent.as_deref(), Some("test/1.0"));
    }

    #[test]
    fn ping_interval_enables_feature() {
        let config = Config::new().with_ping_interval(Duration::from_secs(30));
        assert!(config.features.contains(Features::PING_PONG));
    }

    #[test]
    fn empty_versions_is_invalid() {
        let config = Config::new().with_versions(vec![]);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::NoSupportedVersions)
        ));
    }

    #[test]
    fn zero_limits_are_invalid() {
        let config = Config::new().with_max_inflight_opens(0);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit(_))
        ));

        let config = Config::new().with_max_concurrent_streams(0);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidLimit(_))
        ));
    }
}
