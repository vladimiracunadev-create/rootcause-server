//! Shared, platform-neutral contracts and detection logic for RootCause Server.
//!
//! The crate is deliberately free of I/O: it has no network, no filesystem and
//! no clock beyond what the caller hands it. Everything a server operator ends
//! up reading in the console — the exposed surface, the brute-force burst, the
//! posture score — is produced here by pure functions over reported evidence,
//! which is what makes a finding reproducible instead of merely plausible.

pub mod detect;
pub mod models;
pub mod policy;
pub mod posture;
pub mod runbook;
pub mod security;

pub use detect::{DetectionEngine, DetectionInput, RULES, RuleInfo, agent_silence, rule};
pub use models::*;
pub use policy::DetectionPolicy;
pub use posture::compute_now as compute_posture;
pub use runbook::{RunbookStep, StepKind};
pub use security::{
    AuthEvent, AuthOutcome, BindScope, CollectionGap, FirewallState, ListeningSocket, PortClass,
    Protocol, RemotePeer, SecuritySignals, WatchedFile,
};

/// Protocol version implemented by the server and the native agents.
///
/// Bumped only when the wire contract stops being backwards compatible; adding
/// an optional field does not qualify.
pub const PROTOCOL_VERSION: &str = "1.1";

/// Protocol versions this build still accepts from an agent.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["1.0", "1.1"];

/// Whether a reported protocol version can still be ingested.
pub fn protocol_is_supported(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_protocol_is_supported() {
        assert!(protocol_is_supported(PROTOCOL_VERSION));
    }

    #[test]
    fn older_agents_keep_working() {
        assert!(protocol_is_supported("1.0"));
    }

    #[test]
    fn unknown_protocols_are_rejected() {
        assert!(!protocol_is_supported("2.0"));
        assert!(!protocol_is_supported(""));
    }
}
