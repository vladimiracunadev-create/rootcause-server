//! RootCause Server as a library, so the HTTP surface can be tested end to end.
//!
//! The binary is a thin wrapper over these modules: everything that decides
//! whether a request is accepted, what is detected and what is stored lives
//! here, where an integration test can drive it without opening a socket.

pub mod api;
pub mod auth;
pub mod config;
pub mod defense;
pub mod error;
pub mod headers;
pub mod state;
pub mod storage;
pub mod ui;
pub mod watchdog;
