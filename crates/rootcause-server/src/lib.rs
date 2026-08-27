//! RootCause Server as a library, so the HTTP surface can be tested end to end.
//!
//! The binary is a thin wrapper over these modules: everything that decides
//! whether a request is accepted, what is detected and what is stored lives
//! here, where an integration test can drive it without opening a socket.

/// HTTP routes, ingestion and the reports the console renders.
pub mod api;
/// Perimeter and credential checks applied to every protected route.
pub mod auth;
/// Command line and environment contract of the control plane.
pub mod config;
/// The control plane's own perimeter: rate limit and lockout.
pub mod defense;
/// API errors with stable machine-readable codes.
pub mod error;
/// Security headers and the policy that keeps the console inert.
pub mod headers;
/// Shared state handed to every route.
pub mod state;
/// SQLite persistence for assets, telemetry, incidents and audit.
pub mod storage;
/// The console, embedded in the binary and served from memory.
pub mod ui;
/// Background work: agent silence, perimeter pruning and retention.
pub mod watchdog;
