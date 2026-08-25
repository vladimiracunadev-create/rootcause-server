//! Shared state handed to every route.

use std::{net::IpAddr, sync::Arc, time::Instant};

use rootcause_core::{DetectionEngine, models::HardeningStatus};
use tracing::warn;

use crate::{config::ServeSettings, defense::Perimeter, storage::Database};

/// Immutable facts about how this instance was started.
#[derive(Debug, Clone, Copy)]
pub struct Runtime {
    pub bind_is_loopback: bool,
    pub rate_limit_per_minute: u32,
    pub lockout_threshold: u32,
    pub retention_days: u32,
    pub agent_interval_seconds: u64,
    pub max_body_bytes: usize,
}

#[derive(Clone)]
pub struct AppState {
    pub database: Database,
    pub engine: Arc<DetectionEngine>,
    pub perimeter: Arc<Perimeter>,
    pub started_at: Instant,
    pub api_token: Option<Arc<str>>,
    pub trust_forwarded_for: bool,
    pub runtime: Runtime,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("authenticated", &self.api_token.is_some())
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl AppState {
    pub fn new(database: Database, engine: DetectionEngine, settings: &ServeSettings) -> Self {
        Self {
            database,
            engine: Arc::new(engine),
            perimeter: Arc::new(Perimeter::new(
                settings.rate_limit_per_minute,
                settings.lockout_threshold,
                settings.lockout_seconds,
            )),
            started_at: Instant::now(),
            api_token: settings.api_token.clone().map(Arc::from),
            trust_forwarded_for: settings.trust_forwarded_for,
            runtime: Runtime {
                bind_is_loopback: settings.bind.ip().is_loopback(),
                rate_limit_per_minute: settings.rate_limit_per_minute,
                lockout_threshold: settings.lockout_threshold,
                retention_days: settings.retention_days,
                agent_interval_seconds: settings.agent_interval_seconds,
                max_body_bytes: settings.max_body_bytes(),
            },
        }
    }

    /// How this instance is configured, so the console can warn honestly.
    pub fn hardening(&self) -> HardeningStatus {
        HardeningStatus {
            authentication: self.api_token.is_some(),
            bind_is_loopback: self.runtime.bind_is_loopback,
            rate_limit_per_minute: self.runtime.rate_limit_per_minute,
            lockout_threshold: self.runtime.lockout_threshold,
            retention_days: self.runtime.retention_days,
        }
    }

    /// Persist a perimeter decision. Never fails the request it describes.
    pub async fn record_defense(&self, reason: &str, source: IpAddr, detail: String) {
        if let Err(error) =
            self.database.record_defense_event(reason, &source.to_string(), &detail).await
        {
            warn!(?error, "no se pudo registrar el evento de defensa");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> ServeSettings {
        ServeSettings {
            bind: "127.0.0.1:8080".parse().unwrap(),
            database_url: "sqlite::memory:".to_owned(),
            api_token: Some("a".repeat(32)),
            insecure_dev_mode: false,
            json_logs: false,
            rate_limit_per_minute: 600,
            lockout_threshold: 10,
            lockout_seconds: 300,
            retention_days: 30,
            agent_interval_seconds: 30,
            trust_forwarded_for: false,
            policy_file: None,
            max_body_kib: 1024,
        }
    }

    #[tokio::test]
    async fn the_hardening_report_reflects_the_running_configuration() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let state = AppState::new(database, DetectionEngine::default(), &settings());
        let hardening = state.hardening();
        assert!(hardening.authentication);
        assert!(hardening.bind_is_loopback);
        assert_eq!(hardening.rate_limit_per_minute, 600);
        assert_eq!(hardening.retention_days, 30);
    }

    #[tokio::test]
    async fn a_tokenless_instance_reports_that_it_has_no_authentication() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let settings = ServeSettings { api_token: None, insecure_dev_mode: true, ..settings() };
        let state = AppState::new(database, DetectionEngine::default(), &settings);
        assert!(!state.hardening().authentication);
    }

    #[tokio::test]
    async fn a_defense_event_is_persisted_and_counted() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let state = AppState::new(database, DetectionEngine::default(), &settings());
        state
            .record_defense("auth.lockout", "203.0.113.9".parse().unwrap(), "prueba".to_owned())
            .await;
        let counters = state.database.defense_counters().await.unwrap();
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].0, "auth.lockout");
    }
}
