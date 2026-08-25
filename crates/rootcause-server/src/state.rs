use std::{sync::Arc, time::Instant};

use rootcause_core::RcaEngine;

use crate::storage::Database;

#[derive(Clone)]
pub struct AppState {
    pub database: Database,
    pub rca: RcaEngine,
    pub started_at: Instant,
    pub api_token: Option<Arc<str>>,
}

impl AppState {
    pub fn new(database: Database, api_token: Option<String>) -> Self {
        Self {
            database,
            rca: RcaEngine::default(),
            started_at: Instant::now(),
            api_token: api_token.map(Arc::from),
        }
    }
}
