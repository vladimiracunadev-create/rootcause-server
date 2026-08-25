//! SQLite persistence for assets, telemetry, security surface and incidents.
//!
//! Evidence is stored as the JSON the agent sent, next to the columns the
//! console needs to filter on. Keeping the original payload means a finding can
//! be re-evaluated against a newer rule without asking the fleet to report the
//! same thing twice.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use anyhow::{Context, anyhow};
use chrono::{DateTime, Duration, Utc};
use rootcause_core::{
    models::{
        AssetRegistration, AssetStatus, AssetView, AuditEntry, Category, Incident,
        IncidentCandidate, IncidentStatus, MetricSample, Severity, ThreatSource,
    },
    security::{AuthEvent, AuthOutcome, SecuritySignals, WatchedFile},
};
use serde_json::json;
use sqlx::{
    FromRow, Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use uuid::Uuid;

/// Headline numbers rendered by the console.
#[derive(Debug, Clone, Copy, Default)]
pub struct DatabaseCounts {
    pub assets_total: i64,
    pub assets_online: i64,
    pub open_incidents: i64,
    pub critical_incidents: i64,
    pub exposed_services: i64,
    pub blocked_sources: i64,
}

/// Filters accepted by the incident listing.
#[derive(Debug, Clone, Default)]
pub struct IncidentFilter {
    pub status: Option<IncidentStatus>,
    pub severity: Option<Severity>,
    pub category: Option<Category>,
    pub asset_id: Option<Uuid>,
    pub limit: Option<i64>,
}

/// Seconds after which an asset is considered stale, then offline.
const STALE_AFTER_SECONDS: i64 = 120;
const OFFLINE_AFTER_SECONDS: i64 = 600;

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Database").finish_non_exhaustive()
    }
}

#[derive(Debug, FromRow)]
struct AssetRow {
    registration_json: String,
    first_seen: String,
    last_seen: String,
    latest_metrics_json: Option<String>,
    security_json: Option<String>,
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
            .busy_timeout(std::time::Duration::from_secs(10))
            .synchronous(SqliteSynchronous::Normal);
        if !is_memory {
            options = options.journal_mode(SqliteJournalMode::Wal);
        }
        let pool = SqlitePoolOptions::new()
            .max_connections(if is_memory { 1 } else { 8 })
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await.context("database migration failed")?;
        Ok(Self { pool })
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    // ---------------------------------------------------------------- assets

    pub async fn upsert_asset(&self, asset: &AssetRegistration) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        let registration_json = serde_json::to_string(asset)?;
        sqlx::query(
            r#"
            INSERT INTO assets (
                agent_id, hostname, platform, registration_json, first_seen, last_seen, role
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname = excluded.hostname,
                platform = excluded.platform,
                registration_json = excluded.registration_json,
                role = excluded.role,
                last_seen = excluded.last_seen
            "#,
        )
        .bind(asset.agent_id.to_string())
        .bind(&asset.hostname)
        .bind(asset.platform.as_str())
        .bind(registration_json)
        .bind(&now)
        .bind(&now)
        .bind(asset.role().as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn asset_registration(
        &self,
        agent_id: Uuid,
    ) -> anyhow::Result<Option<AssetRegistration>> {
        let json = sqlx::query_scalar::<_, String>(
            "SELECT registration_json FROM assets WHERE agent_id = ?",
        )
        .bind(agent_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        json.map(|value| serde_json::from_str(&value).map_err(Into::into)).transpose()
    }

    pub async fn list_assets(&self) -> anyhow::Result<Vec<AssetView>> {
        let rows = sqlx::query_as::<_, AssetRow>(
            r#"
            SELECT registration_json, first_seen, last_seen, latest_metrics_json, security_json
            FROM assets
            ORDER BY last_seen DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(asset_from_row).collect()
    }

    /// Registrations plus the moment each was last heard from.
    pub async fn asset_heartbeats(
        &self,
    ) -> anyhow::Result<Vec<(AssetRegistration, DateTime<Utc>)>> {
        let rows = sqlx::query("SELECT registration_json, last_seen FROM assets")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let registration: AssetRegistration =
                    serde_json::from_str(row.try_get::<String, _>("registration_json")?.as_str())?;
                let last_seen = parse_time(row.try_get::<String, _>("last_seen")?.as_str())?;
                Ok((registration, last_seen))
            })
            .collect()
    }

    // ------------------------------------------------------------- telemetry

    pub async fn store_sample(&self, sample: &MetricSample) -> anyhow::Result<()> {
        let sample_json = serde_json::to_string(sample)?;
        sqlx::query("INSERT INTO telemetry (agent_id, observed_at, sample_json) VALUES (?, ?, ?)")
            .bind(sample.agent_id.to_string())
            .bind(sample.observed_at.to_rfc3339())
            .bind(&sample_json)
            .execute(&self.pool)
            .await?;

        sqlx::query("UPDATE assets SET last_seen = ?, latest_metrics_json = ? WHERE agent_id = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(sample_json)
            .bind(sample.agent_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The `limit` samples before `before`, oldest first, for baseline maths.
    pub async fn recent_samples(
        &self,
        agent_id: Uuid,
        before: DateTime<Utc>,
        limit: i64,
    ) -> anyhow::Result<Vec<MetricSample>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"
            SELECT sample_json FROM telemetry
            WHERE agent_id = ? AND observed_at < ?
            ORDER BY observed_at DESC
            LIMIT ?
            "#,
        )
        .bind(agent_id.to_string())
        .bind(before.to_rfc3339())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut samples: Vec<MetricSample> =
            rows.iter().map(|value| serde_json::from_str(value)).collect::<Result<_, _>>()?;
        samples.reverse();
        Ok(samples)
    }

    pub async fn store_security(
        &self,
        agent_id: Uuid,
        signals: &SecuritySignals,
    ) -> anyhow::Result<()> {
        let exposed = signals.exposed_listeners().count() as i64;
        sqlx::query("UPDATE assets SET security_json = ?, exposed_services = ? WHERE agent_id = ?")
            .bind(serde_json::to_string(signals)?)
            .bind(exposed)
            .bind(agent_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn store_posture(&self, agent_id: Uuid, score: u8) -> anyhow::Result<()> {
        sqlx::query("UPDATE assets SET posture_score = ? WHERE agent_id = ?")
            .bind(i64::from(score))
            .bind(agent_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ------------------------------------------------------- file baselines

    pub async fn file_baseline(&self, agent_id: Uuid) -> anyhow::Result<BTreeMap<String, String>> {
        let rows = sqlx::query("SELECT path, digest FROM file_baselines WHERE agent_id = ?")
            .bind(agent_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| Ok((row.try_get::<String, _>("path")?, row.try_get::<String, _>("digest")?)))
            .collect()
    }

    pub async fn update_file_baseline(
        &self,
        agent_id: Uuid,
        files: &[WatchedFile],
    ) -> anyhow::Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let observed_at = Utc::now().to_rfc3339();
        let mut transaction = self.pool.begin().await?;
        for file in files {
            sqlx::query(
                r#"
                INSERT INTO file_baselines (agent_id, path, digest, observed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(agent_id, path) DO UPDATE SET
                    digest = excluded.digest,
                    observed_at = excluded.observed_at
                "#,
            )
            .bind(agent_id.to_string())
            .bind(&file.path)
            .bind(&file.digest)
            .bind(&observed_at)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    // ------------------------------------------------------- auth pressure

    pub async fn record_auth_pressure(
        &self,
        agent_id: Uuid,
        events: &[AuthEvent],
    ) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut transaction = self.pool.begin().await?;
        for event in events {
            let (failures, successes) = match event.outcome {
                AuthOutcome::Failure => (i64::from(event.count), 0),
                AuthOutcome::Success => (0, i64::from(event.count)),
            };
            let timestamp = event.last_seen.to_rfc3339();
            sqlx::query(
                r#"
                INSERT INTO auth_pressure (
                    agent_id, source_address, service, username,
                    failures, successes, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id, source_address, service, username) DO UPDATE SET
                    failures = MAX(auth_pressure.failures, excluded.failures),
                    successes = MAX(auth_pressure.successes, excluded.successes),
                    last_seen = MAX(auth_pressure.last_seen, excluded.last_seen)
                "#,
            )
            .bind(agent_id.to_string())
            .bind(&event.source_address)
            .bind(&event.service)
            .bind(event.username.clone().unwrap_or_default())
            .bind(failures)
            .bind(successes)
            .bind(&timestamp)
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Addresses pressing on the fleet's authentication, worst first.
    pub async fn threat_sources(&self, limit: i64) -> anyhow::Result<Vec<ThreatSource>> {
        let rows = sqlx::query(
            r#"
            SELECT
                p.source_address AS source_address,
                SUM(p.failures) AS failures,
                SUM(p.successes) AS successes,
                GROUP_CONCAT(DISTINCT p.service) AS services,
                GROUP_CONCAT(DISTINCT p.username) AS usernames,
                GROUP_CONCAT(DISTINCT a.hostname) AS assets,
                MIN(p.first_seen) AS first_seen,
                MAX(p.last_seen) AS last_seen
            FROM auth_pressure p
            LEFT JOIN assets a ON a.agent_id = p.agent_id
            GROUP BY p.source_address
            ORDER BY failures DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let failures = row.try_get::<i64, _>("failures").unwrap_or_default().max(0) as u32;
                let successes =
                    row.try_get::<i64, _>("successes").unwrap_or_default().max(0) as u32;
                let severity = threat_severity(failures, successes);
                Ok(ThreatSource {
                    source_address: row.try_get("source_address")?,
                    failures,
                    successes,
                    services: split_group(row.try_get::<Option<String>, _>("services")?),
                    usernames: split_group(row.try_get::<Option<String>, _>("usernames")?),
                    assets: split_group(row.try_get::<Option<String>, _>("assets")?),
                    first_seen: parse_time(row.try_get::<String, _>("first_seen")?.as_str())?,
                    last_seen: parse_time(row.try_get::<String, _>("last_seen")?.as_str())?,
                    severity,
                })
            })
            .collect()
    }

    pub async fn total_auth_failures(&self) -> anyhow::Result<u32> {
        let total = sqlx::query_scalar::<_, Option<i64>>("SELECT SUM(failures) FROM auth_pressure")
            .fetch_one(&self.pool)
            .await?
            .unwrap_or_default();
        Ok(total.max(0) as u32)
    }

    // ------------------------------------------------------------ incidents

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
            // A finding that keeps happening is open again, even if it had been
            // acknowledged: acknowledging is not fixing.
            incident.status = IncidentStatus::Open;
            incident.severity = incident.severity.max(candidate.severity);
            incident.title = candidate.title;
            incident.summary = candidate.summary;
            incident.category = candidate.category;
            incident.root_cause = candidate.root_cause;
            incident.confidence = candidate.confidence;
            incident.evidence = candidate.evidence;
            incident.recommended_actions = candidate.recommended_actions;
            incident.runbook = candidate.runbook;
            incident.techniques = candidate.techniques;
            incident
        } else {
            candidate.into_incident(observed_at)
        };

        sqlx::query(
            r#"
            INSERT INTO incidents (
                id, fingerprint, asset_id, severity, status,
                first_seen, last_seen, incident_json, category
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                severity = excluded.severity,
                status = excluded.status,
                category = excluded.category,
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
        .bind(serde_json::to_string(&incident)?)
        .bind(incident.category.as_str())
        .execute(&self.pool)
        .await?;
        Ok(incident)
    }

    /// Close findings of a category that the latest cycle no longer reports.
    ///
    /// This is what makes the console trustworthy over time: an exposed port
    /// that was closed stops shouting on its own, and the closure is audited.
    pub async fn auto_resolve(
        &self,
        agent_id: Uuid,
        categories: &[Category],
        still_present: &BTreeSet<String>,
    ) -> anyhow::Result<usize> {
        let rows = sqlx::query(
            r#"
            SELECT fingerprint, incident_json FROM incidents
            WHERE asset_id = ? AND status != 'resolved'
            "#,
        )
        .bind(agent_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut resolved = 0;
        for row in rows {
            let fingerprint: String = row.try_get("fingerprint")?;
            if still_present.contains(&fingerprint) {
                continue;
            }
            let mut incident: Incident =
                serde_json::from_str(row.try_get::<String, _>("incident_json")?.as_str())?;
            if !categories.contains(&incident.category) {
                continue;
            }
            incident.status = IncidentStatus::Resolved;
            sqlx::query(
                "UPDATE incidents SET status = 'resolved', incident_json = ? WHERE fingerprint = ?",
            )
            .bind(serde_json::to_string(&incident)?)
            .bind(&fingerprint)
            .execute(&self.pool)
            .await?;
            self.audit(
                "rootcause-engine",
                "incident.auto_resolved",
                &incident.id.to_string(),
                json!({ "fingerprint": fingerprint, "reason": "la condición dejó de observarse" }),
            )
            .await?;
            resolved += 1;
        }
        Ok(resolved)
    }

    pub async fn list_incidents(&self, filter: &IncidentFilter) -> anyhow::Result<Vec<Incident>> {
        let mut sql = String::from("SELECT incident_json FROM incidents WHERE 1 = 1");
        if filter.status.is_some() {
            sql.push_str(" AND status = ?");
        }
        if filter.severity.is_some() {
            sql.push_str(" AND severity = ?");
        }
        if filter.category.is_some() {
            sql.push_str(" AND category = ?");
        }
        if filter.asset_id.is_some() {
            sql.push_str(" AND asset_id = ?");
        }
        sql.push_str(
            r#"
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 4
                    WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END DESC,
                last_seen DESC
            LIMIT ?
            "#,
        );

        let mut query = sqlx::query_as::<_, IncidentRow>(&sql);
        if let Some(status) = filter.status {
            query = query.bind(status.as_str());
        }
        if let Some(severity) = filter.severity {
            query = query.bind(severity.as_str());
        }
        if let Some(category) = filter.category {
            query = query.bind(category.as_str());
        }
        if let Some(asset_id) = filter.asset_id {
            query = query.bind(asset_id.to_string());
        }
        query = query.bind(filter.limit.unwrap_or(500).clamp(1, 5_000));

        let rows = query.fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| serde_json::from_str(&row.incident_json).map_err(Into::into))
            .collect()
    }

    pub async fn incident(&self, id: Uuid) -> anyhow::Result<Option<Incident>> {
        let row =
            sqlx::query_as::<_, IncidentRow>("SELECT incident_json FROM incidents WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        row.map(|row| serde_json::from_str(&row.incident_json).map_err(Into::into)).transpose()
    }

    pub async fn update_incident_status(
        &self,
        id: Uuid,
        status: IncidentStatus,
        actor: &str,
    ) -> anyhow::Result<Option<Incident>> {
        let Some(mut incident) = self.incident(id).await? else {
            return Ok(None);
        };
        let previous = incident.status;
        incident.status = status;
        sqlx::query("UPDATE incidents SET status = ?, incident_json = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(serde_json::to_string(&incident)?)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        self.audit(
            actor,
            "incident.status.changed",
            &id.to_string(),
            json!({ "from": previous.as_str(), "to": status.as_str() }),
        )
        .await?;
        Ok(Some(incident))
    }

    // ---------------------------------------------------------------- counts

    pub async fn counts(&self) -> anyhow::Result<DatabaseCounts> {
        let cutoff = (Utc::now() - Duration::seconds(STALE_AFTER_SECONDS)).to_rfc3339();
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
        let exposed_services =
            sqlx::query_scalar::<_, Option<i64>>("SELECT SUM(exposed_services) FROM assets")
                .fetch_one(&self.pool)
                .await?
                .unwrap_or_default();
        let blocked_sources = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT source) FROM defense_events WHERE reason = 'auth.lockout'",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(DatabaseCounts {
            assets_total,
            assets_online,
            open_incidents,
            critical_incidents,
            exposed_services,
            blocked_sources,
        })
    }

    // ------------------------------------------------------------- defence

    pub async fn record_defense_event(
        &self,
        reason: &str,
        source: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO defense_events (observed_at, reason, source, detail) VALUES (?, ?, ?, ?)",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(reason)
        .bind(source)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// How many requests the control plane rejected, grouped by reason.
    pub async fn defense_counters(&self) -> anyhow::Result<Vec<(String, u64, DateTime<Utc>)>> {
        let rows = sqlx::query(
            r#"
            SELECT reason, COUNT(*) AS total, MAX(observed_at) AS last_seen
            FROM defense_events
            GROUP BY reason
            ORDER BY total DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("reason")?,
                    row.try_get::<i64, _>("total")?.max(0) as u64,
                    parse_time(row.try_get::<String, _>("last_seen")?.as_str())?,
                ))
            })
            .collect()
    }

    // ---------------------------------------------------------------- audit

    pub async fn audit(
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

    pub async fn list_audit(&self, limit: i64) -> anyhow::Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT observed_at, actor, action, target, detail_json FROM audit_log ORDER BY observed_at DESC LIMIT ?",
        )
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(AuditEntry {
                    observed_at: parse_time(row.try_get::<String, _>("observed_at")?.as_str())?,
                    actor: row.try_get("actor")?,
                    action: row.try_get("action")?,
                    target: row.try_get("target")?,
                    detail: serde_json::from_str(row.try_get::<String, _>("detail_json")?.as_str())
                        .unwrap_or(serde_json::Value::Null),
                })
            })
            .collect()
    }

    /// Move an asset's heartbeat, so tests can reproduce an outage without waiting.
    #[cfg(test)]
    pub(crate) async fn set_last_seen(&self, agent_id: Uuid, stamp: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE assets SET last_seen = ? WHERE agent_id = ?")
            .bind(stamp)
            .bind(agent_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------ retention

    /// Drop telemetry, resolved incidents and audit entries past the retention
    /// window. Returns the number of telemetry rows removed.
    pub async fn purge(&self, retention_days: u32) -> anyhow::Result<u64> {
        let cutoff = (Utc::now() - Duration::days(i64::from(retention_days.max(1)))).to_rfc3339();
        let telemetry = sqlx::query("DELETE FROM telemetry WHERE observed_at < ?")
            .bind(&cutoff)
            .execute(&self.pool)
            .await?
            .rows_affected();
        sqlx::query("DELETE FROM auth_pressure WHERE last_seen < ?")
            .bind(&cutoff)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM defense_events WHERE observed_at < ?")
            .bind(&cutoff)
            .execute(&self.pool)
            .await?;
        Ok(telemetry)
    }
}

fn threat_severity(failures: u32, successes: u32) -> Severity {
    if successes > 0 && failures >= 20 {
        return Severity::Critical;
    }
    match failures {
        0..=4 => Severity::Info,
        5..=19 => Severity::Low,
        20..=99 => Severity::High,
        _ => Severity::Critical,
    }
}

fn split_group(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn asset_from_row(row: AssetRow) -> anyhow::Result<AssetView> {
    let registration: AssetRegistration = serde_json::from_str(&row.registration_json)?;
    let first_seen = parse_time(&row.first_seen)?;
    let last_seen = parse_time(&row.last_seen)?;
    let age_seconds = Utc::now().timestamp().saturating_sub(last_seen.timestamp());
    let status = if age_seconds <= STALE_AFTER_SECONDS {
        AssetStatus::Online
    } else if age_seconds <= OFFLINE_AFTER_SECONDS {
        AssetStatus::Stale
    } else {
        AssetStatus::Offline
    };
    let role = registration.role();

    Ok(AssetView {
        registration,
        first_seen,
        last_seen,
        status,
        latest_metrics: row
            .latest_metrics_json
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
        security: row.security_json.map(|value| serde_json::from_str(&value)).transpose()?,
        posture: None,
        role,
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

    use rootcause_core::{
        DetectionEngine, DetectionInput,
        models::{AssetRole, Platform},
        security::{ListeningSocket, Protocol},
    };

    use super::*;

    async fn database() -> Database {
        Database::connect("sqlite::memory:").await.expect("in-memory database")
    }

    fn asset(id: Uuid, role: &str) -> AssetRegistration {
        let mut labels = BTreeMap::new();
        labels.insert("role".to_owned(), role.to_owned());
        AssetRegistration {
            agent_id: id,
            hostname: "srv-test".to_owned(),
            platform: Platform::Linux,
            os_version: Some("Debian 13".to_owned()),
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            agent_version: "0.2.0".to_owned(),
            labels,
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
            disk_free_bytes: Some(1_000),
            process_count: Some(120),
        }
    }

    #[tokio::test]
    async fn assets_and_telemetry_round_trip() {
        let database = database().await;
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id, "database")).await.unwrap();
        database.store_sample(&sample(id, 50.0)).await.unwrap();

        let assets = database.list_assets().await.unwrap();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].role, AssetRole::DatabaseServer);
        assert_eq!(assets[0].latest_metrics.as_ref().unwrap().disk_percent, 50.0);
        assert_eq!(assets[0].status, AssetStatus::Online);
    }

    #[tokio::test]
    async fn the_security_surface_is_stored_with_its_exposed_count() {
        let database = database().await;
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id, "internal")).await.unwrap();
        let signals = SecuritySignals {
            listeners: vec![
                ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 22),
                ListeningSocket::new(Protocol::Tcp, "127.0.0.1", 5432),
            ],
            ..SecuritySignals::default()
        };
        database.store_security(id, &signals).await.unwrap();

        assert_eq!(database.counts().await.unwrap().exposed_services, 1);
        let assets = database.list_assets().await.unwrap();
        assert_eq!(assets[0].security.as_ref().unwrap().listeners.len(), 2);
    }

    #[tokio::test]
    async fn repeated_findings_are_deduplicated_and_counted() {
        let database = database().await;
        let id = Uuid::new_v4();
        let registration = asset(id, "internal");
        database.upsert_asset(&registration).await.unwrap();
        let sample = sample(id, 97.0);
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline);
        let candidate =
            DetectionEngine::default().analyze(&input).into_iter().next().expect("a finding");

        database.upsert_incident(candidate.clone(), sample.observed_at).await.unwrap();
        database.upsert_incident(candidate, sample.observed_at).await.unwrap();

        let incidents = database.list_incidents(&IncidentFilter::default()).await.unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].occurrences, 2);
        assert_eq!(incidents[0].category, Category::Resource);
    }

    #[tokio::test]
    async fn incidents_can_be_filtered_by_category_and_status() {
        let database = database().await;
        let id = Uuid::new_v4();
        let registration = asset(id, "internal");
        database.upsert_asset(&registration).await.unwrap();
        let sample = sample(id, 97.0);
        let signals = SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432)],
            ..SecuritySignals::default()
        };
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline)
            .with_security(Some(&signals));
        for candidate in DetectionEngine::default().analyze(&input) {
            database.upsert_incident(candidate, sample.observed_at).await.unwrap();
        }

        let exposure = database
            .list_incidents(&IncidentFilter {
                category: Some(Category::Exposure),
                ..IncidentFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(exposure.len(), 1);
        assert_eq!(exposure[0].category, Category::Exposure);

        let critical = database
            .list_incidents(&IncidentFilter {
                severity: Some(Severity::Critical),
                ..IncidentFilter::default()
            })
            .await
            .unwrap();
        assert!(critical.iter().all(|incident| incident.severity == Severity::Critical));
    }

    #[tokio::test]
    async fn a_condition_that_stops_being_observed_is_auto_resolved() {
        let database = database().await;
        let id = Uuid::new_v4();
        let registration = asset(id, "internal");
        database.upsert_asset(&registration).await.unwrap();
        let sample = sample(id, 20.0);
        let signals = SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432)],
            ..SecuritySignals::default()
        };
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline)
            .with_security(Some(&signals));
        for candidate in DetectionEngine::default().analyze(&input) {
            database.upsert_incident(candidate, sample.observed_at).await.unwrap();
        }
        assert_eq!(database.counts().await.unwrap().open_incidents, 1);

        // Next cycle: the port is closed, so nothing is still present.
        let resolved =
            database.auto_resolve(id, &[Category::Exposure], &BTreeSet::new()).await.unwrap();
        assert_eq!(resolved, 1);
        assert_eq!(database.counts().await.unwrap().open_incidents, 0);
        assert!(
            database
                .list_audit(10)
                .await
                .unwrap()
                .iter()
                .any(|entry| entry.action == "incident.auto_resolved")
        );
    }

    #[tokio::test]
    async fn auto_resolve_never_touches_another_category() {
        let database = database().await;
        let id = Uuid::new_v4();
        let registration = asset(id, "internal");
        database.upsert_asset(&registration).await.unwrap();
        let sample = sample(id, 97.0);
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline);
        for candidate in DetectionEngine::default().analyze(&input) {
            database.upsert_incident(candidate, sample.observed_at).await.unwrap();
        }
        let resolved =
            database.auto_resolve(id, &[Category::Exposure], &BTreeSet::new()).await.unwrap();
        assert_eq!(resolved, 0);
        assert_eq!(database.counts().await.unwrap().open_incidents, 1);
    }

    #[tokio::test]
    async fn a_status_change_is_audited_with_both_ends() {
        let database = database().await;
        let id = Uuid::new_v4();
        let registration = asset(id, "internal");
        database.upsert_asset(&registration).await.unwrap();
        let sample = sample(id, 97.0);
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline);
        let candidate = DetectionEngine::default().analyze(&input).into_iter().next().unwrap();
        let incident = database.upsert_incident(candidate, sample.observed_at).await.unwrap();

        let updated = database
            .update_incident_status(incident.id, IncidentStatus::Acknowledged, "vladimir")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, IncidentStatus::Acknowledged);

        let audit = database.list_audit(10).await.unwrap();
        let entry = audit.iter().find(|entry| entry.action == "incident.status.changed").unwrap();
        assert_eq!(entry.actor, "vladimir");
        assert_eq!(entry.detail["from"], "open");
        assert_eq!(entry.detail["to"], "acknowledged");
    }

    #[tokio::test]
    async fn file_baselines_are_remembered_between_cycles() {
        let database = database().await;
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id, "internal")).await.unwrap();
        let file = WatchedFile {
            path: "/etc/ssh/sshd_config".to_owned(),
            digest: "aaaa".to_owned(),
            size_bytes: 10,
            modified_at: None,
            mode: Some(0o600),
        };
        database.update_file_baseline(id, std::slice::from_ref(&file)).await.unwrap();
        assert_eq!(
            database.file_baseline(id).await.unwrap().get("/etc/ssh/sshd_config"),
            Some(&"aaaa".to_owned())
        );

        let changed = WatchedFile { digest: "bbbb".to_owned(), ..file };
        database.update_file_baseline(id, &[changed]).await.unwrap();
        assert_eq!(
            database.file_baseline(id).await.unwrap().get("/etc/ssh/sshd_config"),
            Some(&"bbbb".to_owned())
        );
    }

    #[tokio::test]
    async fn auth_pressure_is_aggregated_across_assets() {
        let database = database().await;
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        database.upsert_asset(&asset(first, "edge")).await.unwrap();
        database.upsert_asset(&asset(second, "internal")).await.unwrap();

        let event = |count: u32, outcome: AuthOutcome| AuthEvent {
            service: "sshd".to_owned(),
            source_address: "203.0.113.10".to_owned(),
            username: Some("root".to_owned()),
            outcome,
            count,
            last_seen: Utc::now(),
        };
        database.record_auth_pressure(first, &[event(30, AuthOutcome::Failure)]).await.unwrap();
        database.record_auth_pressure(second, &[event(80, AuthOutcome::Failure)]).await.unwrap();

        let sources = database.threat_sources(10).await.unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_address, "203.0.113.10");
        assert_eq!(sources[0].failures, 110);
        assert_eq!(sources[0].severity, Severity::Critical);
        assert_eq!(database.total_auth_failures().await.unwrap(), 110);
    }

    #[tokio::test]
    async fn a_successful_login_after_a_burst_raises_the_source_severity() {
        let database = database().await;
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id, "edge")).await.unwrap();
        let base = AuthEvent {
            service: "sshd".to_owned(),
            source_address: "198.51.100.4".to_owned(),
            username: Some("deploy".to_owned()),
            outcome: AuthOutcome::Failure,
            count: 25,
            last_seen: Utc::now(),
        };
        database.record_auth_pressure(id, std::slice::from_ref(&base)).await.unwrap();
        database
            .record_auth_pressure(
                id,
                &[AuthEvent { outcome: AuthOutcome::Success, count: 1, ..base }],
            )
            .await
            .unwrap();
        let sources = database.threat_sources(10).await.unwrap();
        assert_eq!(sources[0].severity, Severity::Critical);
        assert_eq!(sources[0].successes, 1);
    }

    #[tokio::test]
    async fn recent_samples_come_back_oldest_first() {
        let database = database().await;
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id, "internal")).await.unwrap();
        let now = Utc::now();
        for step in 0..5_i64 {
            let mut entry = sample(id, 10.0 + step as f32);
            entry.observed_at = now - Duration::seconds(60 * (5 - step));
            database.store_sample(&entry).await.unwrap();
        }
        let history = database.recent_samples(id, now, 3).await.unwrap();
        assert_eq!(history.len(), 3);
        assert!(history[0].observed_at < history[2].observed_at);
    }

    #[tokio::test]
    async fn defence_events_are_counted_by_reason() {
        let database = database().await;
        database.record_defense_event("auth.lockout", "203.0.113.9", "5 fallos").await.unwrap();
        database.record_defense_event("auth.lockout", "203.0.113.9", "6 fallos").await.unwrap();
        database.record_defense_event("rate.limit", "198.51.100.1", "").await.unwrap();

        let counters = database.defense_counters().await.unwrap();
        assert_eq!(counters[0].0, "auth.lockout");
        assert_eq!(counters[0].1, 2);
        assert_eq!(database.counts().await.unwrap().blocked_sources, 1);
    }

    #[tokio::test]
    async fn retention_removes_old_telemetry_and_keeps_the_asset() {
        let database = database().await;
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id, "internal")).await.unwrap();
        let mut old = sample(id, 30.0);
        old.observed_at = Utc::now() - Duration::days(90);
        database.store_sample(&old).await.unwrap();
        database.store_sample(&sample(id, 31.0)).await.unwrap();

        let removed = database.purge(30).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(database.list_assets().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_zero_day_retention_never_deletes_everything() {
        let database = database().await;
        let id = Uuid::new_v4();
        database.upsert_asset(&asset(id, "internal")).await.unwrap();
        database.store_sample(&sample(id, 30.0)).await.unwrap();
        assert_eq!(database.purge(0).await.unwrap(), 0);
    }
}
