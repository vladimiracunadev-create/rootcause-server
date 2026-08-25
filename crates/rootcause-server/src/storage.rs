use std::str::FromStr;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Duration, Utc};
use rootcause_core::{
    AssetRegistration, AssetStatus, AssetView, Incident, IncidentCandidate, IncidentStatus,
    MetricSample, Severity,
};
use serde_json::json;
use sqlx::{
    FromRow, SqlitePool,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    },
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct DatabaseCounts {
    pub assets_total: i64,
    pub assets_online: i64,
    pub open_incidents: i64,
    pub critical_incidents: i64,
}

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

#[derive(Debug, FromRow)]
struct AssetRow {
    registration_json: String,
    first_seen: String,
    last_seen: String,
    latest_metrics_json: Option<String>,
}

#[derive(Debug, FromRow)]
struct IncidentRow {
    incident_json: String,
}

impl Database {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let is_memory = database_url.contains(":memory:");
        let mut options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .synchronous(SqliteSynchronous::Normal);
        if !is_memory {
            options = options.journal_mode(SqliteJournalMode::Wal);
        }
        let pool = SqlitePoolOptions::new()
            .max_connections(if is_memory { 1 } else { 5 })
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options)
            .await?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("database migration failed")?;
        Ok(Self { pool })
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn upsert_asset(&self, asset: &AssetRegistration) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        let registration_json = serde_json::to_string(asset)?;
        sqlx::query(
            r#"
            INSERT INTO assets (
                agent_id, hostname, platform, registration_json, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname = excluded.hostname,
                platform = excluded.platform,
                registration_json = excluded.registration_json,
                last_seen = excluded.last_seen
            "#,
        )
        .bind(asset.agent_id.to_string())
        .bind(&asset.hostname)
        .bind(asset.platform.as_str())
        .bind(registration_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn asset_hostname(&self, agent_id: Uuid) -> anyhow::Result<Option<String>> {
        let hostname = sqlx::query_scalar::<_, String>(
            "SELECT hostname FROM assets WHERE agent_id = ?",
        )
        .bind(agent_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(hostname)
    }

    pub async fn store_sample(&self, sample: &MetricSample) -> anyhow::Result<()> {
        let sample_json = serde_json::to_string(sample)?;
        let received_at = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO telemetry (agent_id, observed_at, sample_json) VALUES (?, ?, ?)",
        )
        .bind(sample.agent_id.to_string())
        .bind(sample.observed_at.to_rfc3339())
        .bind(&sample_json)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "UPDATE assets SET last_seen = ?, latest_metrics_json = ? WHERE agent_id = ?",
        )
        .bind(received_at)
        .bind(sample_json)
        .bind(sample.agent_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_assets(&self) -> anyhow::Result<Vec<AssetView>> {
        let rows = sqlx::query_as::<_, AssetRow>(
            r#"
            SELECT registration_json, first_seen, last_seen, latest_metrics_json
            FROM assets
            ORDER BY last_seen DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(asset_from_row).collect()
    }

    pub async fn upsert_incident(
        &self,
        candidate: IncidentCandidate,
        observed_at: DateTime<Utc>,
    ) -> anyhow::Result<Incident> {
        let existing = sqlx::query_as::<_, IncidentRow>(
            "SELECT incident_json FROM incidents WHERE fingerprint = ?",
        )
        .bind(&candidate.fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        let incident = if let Some(row) = existing {
            let mut incident: Incident = serde_json::from_str(&row.incident_json)?;
            incident.last_seen = observed_at;
            incident.occurrences = incident.occurrences.saturating_add(1);
            incident.status = IncidentStatus::Open;
            if candidate.severity.rank() > incident.severity.rank() {
                incident.severity = candidate.severity;
            }
            incident.summary = candidate.summary;
            incident.root_cause = candidate.root_cause;
            incident.confidence = candidate.confidence;
            incident.evidence = candidate.evidence;
            incident.recommended_actions = candidate.recommended_actions;
            incident
        } else {
            candidate.into_incident(observed_at)
        };

        let incident_json = serde_json::to_string(&incident)?;
        sqlx::query(
            r#"
            INSERT INTO incidents (
                id, fingerprint, asset_id, severity, status,
                first_seen, last_seen, incident_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                severity = excluded.severity,
                status = excluded.status,
                last_seen = excluded.last_seen,
                incident_json = excluded.incident_json
            "#,
        )
        .bind(incident.id.to_string())
        .bind(&incident.fingerprint)
        .bind(incident.asset_id.to_string())
        .bind(incident.severity.as_str())
        .bind(incident.status.as_str())
        .bind(incident.first_seen.to_rfc3339())
        .bind(incident.last_seen.to_rfc3339())
        .bind(incident_json)
        .execute(&self.pool)
        .await?;
        Ok(incident)
    }

    pub async fn list_incidents(&self) -> anyhow::Result<Vec<Incident>> {
        let rows = sqlx::query_as::<_, IncidentRow>(
            r#"
            SELECT incident_json
            FROM incidents
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END DESC,
                last_seen DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| serde_json::from_str(&row.incident_json).map_err(Into::into))
            .collect()
    }

    pub async fn update_incident_status(
        &self,
        id: Uuid,
        status: IncidentStatus,
        actor: &str,
    ) -> anyhow::Result<Option<Incident>> {
        let row = sqlx::query_as::<_, IncidentRow>(
            "SELECT incident_json FROM incidents WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let mut incident: Incident = serde_json::from_str(&row.incident_json)?;
        incident.status = status;
        let incident_json = serde_json::to_string(&incident)?;
        sqlx::query("UPDATE incidents SET status = ?, incident_json = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(incident_json)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        self.audit(
            actor,
            "incident.status.changed",
            &id.to_string(),
            json!({ "status": status.as_str() }),
        )
        .await?;
        Ok(Some(incident))
    }

    pub async fn counts(&self) -> anyhow::Result<DatabaseCounts> {
        let cutoff = (Utc::now() - Duration::seconds(120)).to_rfc3339();
        let assets_total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM assets")
            .fetch_one(&self.pool)
            .await?;
        let assets_online =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM assets WHERE last_seen >= ?")
                .bind(cutoff)
                .fetch_one(&self.pool)
                .await?;
        let open_incidents = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM incidents WHERE status != 'resolved'",
        )
        .fetch_one(&self.pool)
        .await?;
        let critical_incidents = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM incidents WHERE status != 'resolved' AND severity = 'critical'",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(DatabaseCounts {
            assets_total,
            assets_online,
            open_incidents,
            critical_incidents,
        })
    }

    async fn audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        detail: serde_json::Value,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (observed_at, actor, action, target, detail_json) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(serde_json::to_string(&detail)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn asset_from_row(row: AssetRow) -> anyhow::Result<AssetView> {
    let registration: AssetRegistration = serde_json::from_str(&row.registration_json)?;
    let first_seen = parse_time(&row.first_seen)?;
    let last_seen = parse_time(&row.last_seen)?;
    let age_seconds = Utc::now().timestamp().saturating_sub(last_seen.timestamp());
    let status = if age_seconds <= 120 {
        AssetStatus::Online
    } else if age_seconds <= 600 {
        AssetStatus::Stale
    } else {
        AssetStatus::Offline
    };
    let latest_metrics = row
        .latest_metrics_json
        .map(|value| serde_json::from_str(&value))
        .transpose()?;

    Ok(AssetView {
        registration,
        first_seen,
        last_seen,
        status,
        latest_metrics,
    })
}

fn parse_time(value: &str) -> anyhow::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| anyhow!("invalid stored timestamp: {error}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rootcause_core::{Platform, RcaEngine};

    use super::*;

    fn asset(id: Uuid) -> AssetRegistration {
        AssetRegistration {
            agent_id: id,
            hostname: "test-host".to_owned(),
            platform: Platform::Linux,
            os_version: Some("Test Linux".to_owned()),
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            agent_version: "0.1.0".to_owned(),
            labels: BTreeMap::new(),
        }
    }

    fn sample(id: Uuid, disk_percent: f32) -> MetricSample {
        MetricSample {
            agent_id: id,
            observed_at: Utc::now(),
            cpu_percent: 20.0,
            memory_percent: 40.0,
            disk_percent,
            uptime_seconds: 100,
            load_average: None,
            network_rx_bytes: 10,
            network_tx_bytes: 20,
        }
    }

    #[tokio::test]
    async fn asset_and_telemetry_round_trip() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id)).await.unwrap();
        database.store_sample(&sample(id, 50.0)).await.unwrap();

        let assets = database.list_assets().await.unwrap();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].registration.agent_id, id);
        assert_eq!(assets[0].latest_metrics.as_ref().unwrap().disk_percent, 50.0);
    }

    #[tokio::test]
    async fn repeated_findings_are_deduplicated() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id)).await.unwrap();
        let sample = sample(id, 97.0);
        let candidate = RcaEngine::default()
            .analyze(&sample, "test-host")
            .into_iter()
            .next()
            .unwrap();
        database
            .upsert_incident(candidate.clone(), sample.observed_at)
            .await
            .unwrap();
        database
            .upsert_incident(candidate, sample.observed_at)
            .await
            .unwrap();

        let incidents = database.list_incidents().await.unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].occurrences, 2);
    }
}
