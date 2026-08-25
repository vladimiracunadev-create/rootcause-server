//! Background work that must happen even when nothing is being reported.
//!
//! Two of the three jobs here exist because an attacker benefits from silence:
//! an agent that stops talking is a finding, and evidence that grows without
//! bound is evidence nobody can search. The third simply keeps the perimeter
//! table from growing forever.

use std::{collections::BTreeSet, time::Duration};

use chrono::Utc;
use rootcause_core::{
    detect::{agent_silence, silence_fingerprint},
    models::Category,
};
use tracing::{debug, info, warn};

use crate::state::AppState;

/// How often the watchdog wakes up.
const TICK: Duration = Duration::from_secs(30);
/// How often retention runs, expressed in ticks.
const PURGE_EVERY_TICKS: u64 = 120;
/// Idle window after which a perimeter entry is forgotten.
const PERIMETER_IDLE: Duration = Duration::from_secs(900);

/// Run the watchdog until the process shuts down.
pub async fn run(state: AppState) {
    let mut ticks: u64 = 0;
    loop {
        tokio::time::sleep(TICK).await;
        ticks = ticks.wrapping_add(1);

        if let Err(error) = sweep_silence(&state).await {
            warn!(?error, "no se pudo evaluar el silencio de los agentes");
        }
        state.perimeter.prune(std::time::Instant::now(), PERIMETER_IDLE);

        if ticks.is_multiple_of(PURGE_EVERY_TICKS) {
            match state.database.purge(state.runtime.retention_days).await {
                Ok(removed) if removed > 0 => {
                    info!(removed, days = state.runtime.retention_days, "retención aplicada");
                }
                Ok(_) => debug!("retención aplicada sin filas que eliminar"),
                Err(error) => warn!(?error, "no se pudo aplicar la retención"),
            }
        }
    }
}

/// Raise a finding for every asset that stopped reporting, and close the ones
/// that came back.
pub async fn sweep_silence(state: &AppState) -> anyhow::Result<usize> {
    let heartbeats = state.database.asset_heartbeats().await?;
    let now = Utc::now();
    let mut raised = 0;

    for (registration, last_seen) in heartbeats {
        let candidate = agent_silence(
            state.engine.policy(),
            &registration,
            last_seen,
            now,
            state.runtime.agent_interval_seconds,
        );
        match candidate {
            Some(candidate) => {
                state.database.upsert_incident(candidate, now).await?;
                raised += 1;
            }
            None => {
                // The asset is reporting again, so nothing in the availability
                // category is still happening: close whatever was open there.
                debug_assert_eq!(
                    silence_fingerprint(registration.agent_id),
                    format!("{}:availability.agent.silence", registration.agent_id),
                    "the silence fingerprint must stay stable across versions"
                );
                state
                    .database
                    .auto_resolve(
                        registration.agent_id,
                        &[Category::Availability],
                        &BTreeSet::new(),
                    )
                    .await?;
            }
        }
    }
    Ok(raised)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration as ChronoDuration;
    use rootcause_core::{
        DetectionEngine,
        models::{AssetRegistration, IncidentStatus, MetricSample, Platform},
    };
    use uuid::Uuid;

    use super::*;
    use crate::{
        config::ServeSettings,
        storage::{Database, IncidentFilter},
    };

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

    fn registration(id: Uuid) -> AssetRegistration {
        AssetRegistration {
            agent_id: id,
            hostname: "srv-quiet".to_owned(),
            platform: Platform::Linux,
            os_version: None,
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            agent_version: "0.2.0".to_owned(),
            labels: BTreeMap::new(),
        }
    }

    fn sample(id: Uuid, minutes_ago: i64) -> MetricSample {
        MetricSample {
            agent_id: id,
            observed_at: Utc::now() - ChronoDuration::minutes(minutes_ago),
            cpu_percent: 5.0,
            memory_percent: 20.0,
            disk_percent: 30.0,
            uptime_seconds: 10,
            load_average: None,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
            disk_free_bytes: None,
            process_count: None,
        }
    }

    async fn state() -> AppState {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        AppState::new(database, DetectionEngine::default(), &settings())
    }

    #[tokio::test]
    async fn an_agent_reporting_on_time_produces_no_finding() {
        let state = state().await;
        let id = Uuid::new_v4();
        state.database.upsert_asset(&registration(id)).await.unwrap();
        state.database.store_sample(&sample(id, 0)).await.unwrap();

        assert_eq!(sweep_silence(&state).await.unwrap(), 0);
        assert_eq!(state.database.counts().await.unwrap().open_incidents, 0);
    }

    #[tokio::test]
    async fn an_agent_that_went_quiet_is_reported_once() {
        let state = state().await;
        let id = Uuid::new_v4();
        state.database.upsert_asset(&registration(id)).await.unwrap();
        // Rewrite the heartbeat as if the last sample arrived an hour ago.
        sqlx_set_last_seen(&state, id, 60).await;

        assert_eq!(sweep_silence(&state).await.unwrap(), 1);
        assert_eq!(sweep_silence(&state).await.unwrap(), 1);
        let incidents = state.database.list_incidents(&IncidentFilter::default()).await.unwrap();
        assert_eq!(incidents.len(), 1, "silence must deduplicate like any other finding");
        assert_eq!(incidents[0].category, Category::Availability);
        assert_eq!(incidents[0].occurrences, 2);
    }

    #[tokio::test]
    async fn an_agent_that_comes_back_closes_its_own_finding() {
        let state = state().await;
        let id = Uuid::new_v4();
        state.database.upsert_asset(&registration(id)).await.unwrap();
        sqlx_set_last_seen(&state, id, 60).await;
        sweep_silence(&state).await.unwrap();
        assert_eq!(state.database.counts().await.unwrap().open_incidents, 1);

        state.database.store_sample(&sample(id, 0)).await.unwrap();
        sweep_silence(&state).await.unwrap();
        let incidents = state.database.list_incidents(&IncidentFilter::default()).await.unwrap();
        assert_eq!(incidents[0].status, IncidentStatus::Resolved);
    }

    /// Move an asset's heartbeat back in time, the way a real outage would.
    async fn sqlx_set_last_seen(state: &AppState, id: Uuid, minutes_ago: i64) {
        let stamp = (Utc::now() - ChronoDuration::minutes(minutes_ago)).to_rfc3339();
        state
            .database
            .set_last_seen(id, &stamp)
            .await
            .expect("the heartbeat must be adjustable in tests");
    }
}
