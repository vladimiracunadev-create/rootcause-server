//! Shared, platform-neutral contracts for RootCause Server.

pub mod models;
pub mod rca;

pub use models::*;
pub use rca::{RcaEngine, RcaPolicy};

/// Protocol version implemented by the server and native agents.
pub const PROTOCOL_VERSION: &str = "1.0";
