use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
    Unknown,
}

impl Platform {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "windows" => Self::Windows,
            "linux" => Self::Linux,
            "macos" => Self::Macos,
            _ => Self::Unknown,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRegistration {
    pub agent_id: Uuid,
    pub hostname: String,
    pub platform: Platform,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub agent_version: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    pub agent_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub disk_percent: f32,
    pub uptime_seconds: u64,
    pub load_average: Option<[f64; 3]>,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
}

impl MetricSample {
    pub fn validate(&self) -> Result<(), &'static str> {
        for value in [self.cpu_percent, self.memory_percent, self.disk_percent] {
            if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                return Err("percent metrics must be finite values from 0 through 100");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEnvelope {
    pub protocol_version: String,
    pub asset: Option<AssetRegistration>,
    pub sample: MetricSample,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Acknowledged,
    Resolved,
}

impl IncidentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub summary: String,
    pub observed_value: f64,
    pub threshold: f64,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub fingerprint: String,
    pub asset_id: Uuid,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub root_cause: String,
    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrences: u64,
    pub evidence: Vec<Evidence>,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentCandidate {
    pub fingerprint: String,
    pub asset_id: Uuid,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    pub root_cause: String,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
    pub recommended_actions: Vec<String>,
}

impl IncidentCandidate {
    pub fn into_incident(self, observed_at: DateTime<Utc>) -> Incident {
        Incident {
            id: Uuid::new_v4(),
            fingerprint: self.fingerprint,
            asset_id: self.asset_id,
            title: self.title,
            summary: self.summary,
            severity: self.severity,
            status: IncidentStatus::Open,
            root_cause: self.root_cause,
            confidence: self.confidence,
            first_seen: observed_at,
            last_seen: observed_at,
            occurrences: 1,
            evidence: self.evidence,
            recommended_actions: self.recommended_actions,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetStatus {
    Online,
    Stale,
    Offline,
}

impl AssetStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Stale => "stale",
            Self::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetView {
    pub registration: AssetRegistration,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: AssetStatus,
    pub latest_metrics: Option<MetricSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub status: String,
    pub platform: Option<Platform>,
    pub risk: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub generated_at: DateTime<Utc>,
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub service: String,
    pub version: String,
    pub protocol_version: String,
    pub uptime_seconds: u64,
    pub assets_total: i64,
    pub assets_online: i64,
    pub open_incidents: i64,
    pub critical_incidents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub accepted: bool,
    pub incidents_touched: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}
