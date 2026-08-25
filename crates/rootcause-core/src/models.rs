//! Platform-neutral contracts shared by the server, the agent and the console.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{runbook::RunbookStep, security::SecuritySignals};

/// Operating-system family of a managed asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

    pub const fn label(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::Macos => "macOS",
            Self::Unknown => "Otro",
        }
    }
}

/// Operational role declared for an asset.
///
/// The role changes what "normal" means: a public web server is *expected* to
/// listen on 443, a database server is never expected to answer the Internet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetRole {
    /// Reachable from the Internet on purpose.
    EdgeServer,
    /// Server that must only be reachable from the internal network.
    #[default]
    InternalServer,
    /// Data store; never expected to be publicly reachable.
    DatabaseServer,
    /// Operator workstation.
    Workstation,
}

impl AssetRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeServer => "edge-server",
            Self::InternalServer => "internal-server",
            Self::DatabaseServer => "database-server",
            Self::Workstation => "workstation",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::EdgeServer => "Servidor de borde",
            Self::InternalServer => "Servidor interno",
            Self::DatabaseServer => "Servidor de base de datos",
            Self::Workstation => "Estación de trabajo",
        }
    }

    /// Parse the `role` label supplied by an agent.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "edge" | "edge-server" | "borde" => Some(Self::EdgeServer),
            "internal" | "internal-server" | "interno" => Some(Self::InternalServer),
            "database" | "database-server" | "db" | "base-de-datos" => Some(Self::DatabaseServer),
            "workstation" | "estacion" | "estación" => Some(Self::Workstation),
            _ => None,
        }
    }
}

/// Identity an agent declares when it registers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRegistration {
    pub agent_id: Uuid,
    pub hostname: String,
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub agent_version: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl AssetRegistration {
    /// Role declared through the `role=` label, defaulting to an internal server.
    pub fn role(&self) -> AssetRole {
        self.labels.get("role").and_then(|value| AssetRole::parse(value)).unwrap_or_default()
    }

    /// Deployment environment declared through the `environment=` label.
    pub fn environment(&self) -> Option<&str> {
        self.labels.get("environment").map(String::as_str)
    }
}

/// One resource measurement cycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    pub agent_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub disk_percent: f32,
    pub uptime_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_average: Option<[f64; 3]>,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    /// Free bytes across the inspected mount points, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_free_bytes: Option<u64>,
    /// Number of processes seen during this cycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_count: Option<u32>,
}

impl MetricSample {
    /// Reject impossible measurements before they reach storage or detection.
    pub fn validate(&self) -> Result<(), &'static str> {
        for value in [self.cpu_percent, self.memory_percent, self.disk_percent] {
            if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                return Err("percent metrics must be finite values from 0 through 100");
            }
        }
        Ok(())
    }
}

/// Payload an agent posts on every cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEnvelope {
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<AssetRegistration>,
    pub sample: MetricSample,
    /// Security surface observed in the same cycle.
    ///
    /// Optional so that a `0.1` agent keeps working against a `0.2` server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecuritySignals>,
}

/// Impact ranking shared by incidents and posture findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Informativo",
            Self::Low => "Bajo",
            Self::Medium => "Medio",
            Self::High => "Alto",
            Self::Critical => "Crítico",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Family a finding belongs to, used for filtering and for the posture score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Compute, memory and storage saturation.
    Resource,
    /// Services reachable from outside the machine.
    Exposure,
    /// Active attempts against the machine or its network.
    Intrusion,
    /// Unexpected change on a security-critical file.
    Integrity,
    /// Missing baseline controls: firewall, updates, clock.
    Hygiene,
    /// The sensor or the asset stopped answering.
    Availability,
}

impl Category {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Exposure => "exposure",
            Self::Intrusion => "intrusion",
            Self::Integrity => "integrity",
            Self::Hygiene => "hygiene",
            Self::Availability => "availability",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Resource => "Recursos",
            Self::Exposure => "Superficie expuesta",
            Self::Intrusion => "Intrusión",
            Self::Integrity => "Integridad",
            Self::Hygiene => "Higiene",
            Self::Availability => "Disponibilidad",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "resource" => Some(Self::Resource),
            "exposure" => Some(Self::Exposure),
            "intrusion" => Some(Self::Intrusion),
            "integrity" => Some(Self::Integrity),
            "hygiene" => Some(Self::Hygiene),
            "availability" => Some(Self::Availability),
            _ => None,
        }
    }

    /// Every category, in the order the console renders them.
    pub const ALL: [Self; 6] = [
        Self::Intrusion,
        Self::Exposure,
        Self::Integrity,
        Self::Availability,
        Self::Hygiene,
        Self::Resource,
    ];
}

/// Lifecycle of an incident.
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

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "open" => Some(Self::Open),
            "acknowledged" => Some(Self::Acknowledged),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// A single observation that supports a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub observed_at: DateTime<Utc>,
}

impl Evidence {
    /// Evidence for a numeric threshold breach.
    pub fn metric(
        kind: impl Into<String>,
        summary: impl Into<String>,
        observed_value: f64,
        threshold: f64,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            kind: kind.into(),
            summary: summary.into(),
            observed_value: Some(observed_value),
            threshold: Some(threshold),
            detail: None,
            observed_at,
        }
    }

    /// Evidence for a categorical observation, such as an exposed socket.
    pub fn fact(
        kind: impl Into<String>,
        summary: impl Into<String>,
        detail: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            kind: kind.into(),
            summary: summary.into(),
            observed_value: None,
            threshold: None,
            detail: Some(detail.into()),
            observed_at,
        }
    }
}

/// A deduplicated finding with its evidence, cause and guided response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub fingerprint: String,
    pub asset_id: Uuid,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    #[serde(default = "default_category")]
    pub category: Category,
    pub status: IncidentStatus,
    pub root_cause: String,
    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrences: u64,
    pub evidence: Vec<Evidence>,
    pub recommended_actions: Vec<String>,
    /// Non-destructive commands an operator may run after reviewing them.
    #[serde(default)]
    pub runbook: Vec<RunbookStep>,
    /// MITRE ATT&CK technique identifiers relevant to the finding.
    #[serde(default)]
    pub techniques: Vec<String>,
}

const fn default_category() -> Category {
    Category::Resource
}

/// A finding produced by a detector before deduplication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentCandidate {
    pub fingerprint: String,
    pub asset_id: Uuid,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    pub category: Category,
    pub root_cause: String,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
    pub recommended_actions: Vec<String>,
    #[serde(default)]
    pub runbook: Vec<RunbookStep>,
    #[serde(default)]
    pub techniques: Vec<String>,
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
            category: self.category,
            status: IncidentStatus::Open,
            root_cause: self.root_cause,
            confidence: self.confidence,
            first_seen: observed_at,
            last_seen: observed_at,
            occurrences: 1,
            evidence: self.evidence,
            recommended_actions: self.recommended_actions,
            runbook: self.runbook,
            techniques: self.techniques,
        }
    }
}

/// Liveness of an asset derived from the age of its last telemetry.
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

/// An asset as the console sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetView {
    pub registration: AssetRegistration,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: AssetStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_metrics: Option<MetricSample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecuritySignals>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureScore>,
    #[serde(default)]
    pub role: AssetRole,
}

/// A node in the defence topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<Severity>,
    /// Network zone the node belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Publicly reachable ports counted for this node.
    #[serde(default)]
    pub exposed_ports: u32,
    #[serde(default)]
    pub open_incidents: u32,
}

/// A relation between two topology nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
    /// Highest severity carried by this relation, when it represents exposure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<Severity>,
}

/// The full defence map at one point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub generated_at: DateTime<Utc>,
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

/// One axis of the posture score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureDimension {
    pub category: Category,
    pub score: u8,
    pub findings: u32,
    pub summary: String,
}

/// Aggregated defensive posture, from 0 (worst) to 100 (best).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureScore {
    pub score: u8,
    pub grade: String,
    pub dimensions: Vec<PostureDimension>,
    /// Surfaces that could not be inspected, so the score is not read as proof.
    #[serde(default)]
    pub uninspected_surfaces: Vec<String>,
    pub computed_at: DateTime<Utc>,
}

/// One publicly reachable service across the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureEntry {
    pub asset_id: Uuid,
    pub hostname: String,
    pub platform: Platform,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub scope: String,
    pub service: String,
    pub class: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    pub observed_at: DateTime<Utc>,
}

/// The attack surface of the whole fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureReport {
    pub generated_at: DateTime<Utc>,
    pub public_services: u32,
    pub private_services: u32,
    pub entries: Vec<ExposureEntry>,
    #[serde(default)]
    pub uninspected_assets: Vec<String>,
}

/// An address that repeatedly failed to authenticate against the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSource {
    pub source_address: String,
    pub failures: u32,
    pub successes: u32,
    pub services: Vec<String>,
    pub usernames: Vec<String>,
    pub assets: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub severity: Severity,
}

/// Aggregated pressure against the fleet's authentication surfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub generated_at: DateTime<Utc>,
    pub total_failures: u32,
    pub distinct_sources: u32,
    pub sources: Vec<ThreatSource>,
    /// Requests the control plane itself rejected, by reason.
    #[serde(default)]
    pub control_plane_defense: Vec<DefenseCounter>,
}

/// A defensive action the control plane took on its own perimeter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseCounter {
    pub reason: String,
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
}

/// Service status and fleet headline numbers.
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
    pub exposed_services: i64,
    pub blocked_sources: i64,
    pub detectors: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureScore>,
    pub hardening: HardeningStatus,
}

/// How the running instance is configured, so the console can warn honestly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningStatus {
    pub authentication: bool,
    pub bind_is_loopback: bool,
    pub rate_limit_per_minute: u32,
    pub lockout_threshold: u32,
    pub retention_days: u32,
}

/// Result of accepting one telemetry envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub accepted: bool,
    pub incidents_touched: usize,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Liveness and readiness payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

/// One entry of the immutable audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub observed_at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_by_impact() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Critical));
        assert_eq!(Severity::parse("nope"), None);
    }

    #[test]
    fn role_defaults_to_internal_server() {
        let mut labels = BTreeMap::new();
        labels.insert("environment".to_owned(), "production".to_owned());
        let registration = AssetRegistration {
            agent_id: Uuid::nil(),
            hostname: "srv".to_owned(),
            platform: Platform::Linux,
            os_version: None,
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            agent_version: "0.2.0".to_owned(),
            labels,
        };
        assert_eq!(registration.role(), AssetRole::InternalServer);
        assert_eq!(registration.environment(), Some("production"));
    }

    #[test]
    fn role_label_is_parsed() {
        let mut labels = BTreeMap::new();
        labels.insert("role".to_owned(), "Database".to_owned());
        let registration = AssetRegistration {
            agent_id: Uuid::nil(),
            hostname: "db".to_owned(),
            platform: Platform::Linux,
            os_version: None,
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            agent_version: "0.2.0".to_owned(),
            labels,
        };
        assert_eq!(registration.role(), AssetRole::DatabaseServer);
    }

    #[test]
    fn metric_validation_rejects_impossible_values() {
        let mut sample = MetricSample {
            agent_id: Uuid::nil(),
            observed_at: Utc::now(),
            cpu_percent: 10.0,
            memory_percent: 10.0,
            disk_percent: 10.0,
            uptime_seconds: 1,
            load_average: None,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
            disk_free_bytes: None,
            process_count: None,
        };
        assert!(sample.validate().is_ok());
        sample.cpu_percent = 140.0;
        assert!(sample.validate().is_err());
        sample.cpu_percent = f32::NAN;
        assert!(sample.validate().is_err());
    }

    #[test]
    fn every_category_round_trips() {
        for category in Category::ALL {
            assert_eq!(Category::parse(category.as_str()), Some(category));
        }
    }
}
