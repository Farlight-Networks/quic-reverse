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

//! Session state machine.
//!
//! Defines the lifecycle states of a quic-reverse session and valid transitions.

/// Session lifecycle state.
///
/// The session progresses through these states:
/// ```text
/// Init ──► Negotiating ──► Ready ──► Closing ──► Closed
///              │             │          │
///              │             ▼          │
///              │       Disconnected ────┴──► Closed
///              │             │
///              └─────────────┴──────────────► Closed (on error)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum State {
    /// Initial state before negotiation begins.
    #[default]
    Init,
    /// Handshake in progress (Hello/HelloAck exchange).
    Negotiating,
    /// Session is ready for stream operations.
    Ready,
    /// Connection lost but session not yet closed.
    ///
    /// The application may attempt to reconnect from this state.
    Disconnected,
    /// Graceful shutdown in progress.
    Closing,
    /// Session has terminated.
    Closed,
}

impl State {
    /// Converts from u8 representation used in atomic storage.
    #[must_use]
    pub(crate) const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Init,
            1 => Self::Negotiating,
            2 => Self::Ready,
            3 => Self::Disconnected,
            4 => Self::Closing,
            _ => Self::Closed,
        }
    }

    /// Returns true if the session can accept new stream operations.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Returns true if the session has terminated.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns true if the connection was lost.
    #[must_use]
    pub const fn is_disconnected(&self) -> bool {
        matches!(self, Self::Disconnected)
    }

    /// Returns true if a transition to the target state is valid.
    #[must_use]
    #[allow(clippy::match_same_arms)] // Keep separate for documentation clarity
    pub const fn can_transition_to(&self, target: Self) -> bool {
        use State::{Closed, Closing, Disconnected, Init, Negotiating, Ready};

        match (*self, target) {
            // Normal progression
            (Init, Negotiating) => true,
            (Negotiating, Ready) => true,
            (Ready, Closing) => true,
            (Closing, Closed) => true,

            // Disconnection from Ready state
            (Ready, Disconnected) => true,

            // Disconnected can transition to Closed
            (Disconnected, Closed) => true,

            // Any state can transition to Closed (error/abort/normal)
            // Note: (Closing, Closed) is already handled above
            (Init | Negotiating | Ready | Closed, Closed) => true,

            // Everything else is invalid
            _ => false,
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init => write!(f, "init"),
            Self::Negotiating => write!(f, "negotiating"),
            Self::Ready => write!(f, "ready"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Closing => write!(f, "closing"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_forward_transitions() {
        assert!(State::Init.can_transition_to(State::Negotiating));
        assert!(State::Negotiating.can_transition_to(State::Ready));
        assert!(State::Ready.can_transition_to(State::Closing));
        assert!(State::Closing.can_transition_to(State::Closed));
    }

    #[test]
    fn error_transitions_to_closed() {
        assert!(State::Init.can_transition_to(State::Closed));
        assert!(State::Negotiating.can_transition_to(State::Closed));
        assert!(State::Ready.can_transition_to(State::Closed));
        assert!(State::Closing.can_transition_to(State::Closed));
    }

    #[test]
    fn invalid_transitions() {
        // Can't go backwards
        assert!(!State::Ready.can_transition_to(State::Negotiating));
        assert!(!State::Ready.can_transition_to(State::Init));
        assert!(!State::Closed.can_transition_to(State::Ready));

        // Can't skip states
        assert!(!State::Init.can_transition_to(State::Ready));
        assert!(!State::Negotiating.can_transition_to(State::Closing));
    }

    #[test]
    fn state_display() {
        assert_eq!(State::Init.to_string(), "init");
        assert_eq!(State::Ready.to_string(), "ready");
        assert_eq!(State::Closed.to_string(), "closed");
    }

    #[test]
    fn is_ready() {
        assert!(!State::Init.is_ready());
        assert!(!State::Negotiating.is_ready());
        assert!(State::Ready.is_ready());
        assert!(!State::Closing.is_ready());
        assert!(!State::Closed.is_ready());
    }

    #[test]
    fn is_closed() {
        assert!(!State::Init.is_closed());
        assert!(!State::Ready.is_closed());
        assert!(State::Closed.is_closed());
    }

    #[test]
    fn disconnected_transitions() {
        assert!(State::Ready.can_transition_to(State::Disconnected));
        assert!(State::Disconnected.can_transition_to(State::Closed));
        assert!(!State::Init.can_transition_to(State::Disconnected));
        assert!(!State::Disconnected.can_transition_to(State::Ready));
    }

    #[test]
    fn is_disconnected() {
        assert!(!State::Ready.is_disconnected());
        assert!(State::Disconnected.is_disconnected());
        assert!(!State::Closed.is_disconnected());
    }
}
