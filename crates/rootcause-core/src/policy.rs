//! Detection thresholds.
//!
//! Every number a detector uses lives here, is serialisable, and is validated
//! before it takes effect. An operator can therefore see — and version — the
//! exact policy that produced an incident.

use serde::{Deserialize, Serialize};

use crate::{
    models::{AssetRole, Severity},
    security::{BindScope, PortClass},
};

/// Thresholds for resource saturation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourcePolicy {
    pub cpu_high: f32,
    pub cpu_critical: f32,
    /// Consecutive samples above `cpu_high` before a spike counts as saturation.
    pub cpu_sustained_samples: usize,
    pub memory_high: f32,
    pub memory_critical: f32,
    pub disk_high: f32,
    pub disk_critical: f32,
    /// Hours of projected runway below which a filling disk becomes urgent.
    pub disk_runway_hours: f64,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            cpu_high: 90.0,
            cpu_critical: 98.0,
            cpu_sustained_samples: 3,
            memory_high: 88.0,
            memory_critical: 96.0,
            disk_high: 85.0,
            disk_critical: 95.0,
            disk_runway_hours: 48.0,
        }
    }
}

/// Thresholds for authentication pressure and network reconnaissance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntrusionPolicy {
    /// Failed attempts from one source before it counts as a brute-force burst.
    pub failures_per_source_high: u32,
    pub failures_per_source_critical: u32,
    /// Distinct usernames tried by one source before it counts as spraying.
    pub sprayed_usernames: usize,
    /// Distinct sources failing against one asset before it counts as distributed.
    pub distributed_sources: usize,
    /// Distinct remote peers in one cycle before it looks like a scan.
    pub peer_fanin_high: usize,
    pub peer_fanin_critical: usize,
    /// Outbound bytes per second over baseline before egress looks anomalous.
    pub egress_multiplier: f64,
    /// Minimum outbound rate, in bytes per second, before egress is evaluated.
    pub egress_floor_bytes_per_second: f64,
}

impl Default for IntrusionPolicy {
    fn default() -> Self {
        Self {
            failures_per_source_high: 20,
            failures_per_source_critical: 100,
            sprayed_usernames: 5,
            distributed_sources: 10,
            peer_fanin_high: 50,
            peer_fanin_critical: 200,
            egress_multiplier: 8.0,
            egress_floor_bytes_per_second: 1_000_000.0,
        }
    }
}

/// Thresholds for baseline controls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HygienePolicy {
    /// Pending security updates before the finding is raised to `High`.
    pub pending_updates_high: u32,
    /// Seconds of clock difference tolerated between agent and server.
    pub clock_skew_seconds: i64,
    /// Multiples of the agent interval without telemetry before silence is a finding.
    pub silence_intervals: u32,
}

impl Default for HygienePolicy {
    fn default() -> Self {
        Self { pending_updates_high: 15, clock_skew_seconds: 120, silence_intervals: 4 }
    }
}

/// The complete, versionable detection policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionPolicy {
    pub resource: ResourcePolicy,
    pub intrusion: IntrusionPolicy,
    pub hygiene: HygienePolicy,
    /// Ports allowed to be publicly reachable without raising a finding.
    ///
    /// A public web server is *supposed* to answer on 80 and 443; treating that
    /// as a finding would train operators to ignore the exposure view.
    pub public_allowlist: Vec<u16>,
}

impl DetectionPolicy {
    /// Reject a policy whose numbers contradict each other.
    ///
    /// A policy that cannot fire is worse than no policy: it looks like defence
    /// and provides none.
    pub fn validate(&self) -> Result<(), String> {
        let r = &self.resource;
        for (name, high, critical) in [
            ("cpu", r.cpu_high, r.cpu_critical),
            ("memory", r.memory_high, r.memory_critical),
            ("disk", r.disk_high, r.disk_critical),
        ] {
            if !(0.0..=100.0).contains(&high) || !(0.0..=100.0).contains(&critical) {
                return Err(format!("{name} thresholds must be percentages from 0 through 100"));
            }
            if high > critical {
                return Err(format!("{name}_high must not exceed {name}_critical"));
            }
        }
        if r.cpu_sustained_samples == 0 {
            return Err("cpu_sustained_samples must be at least 1".to_owned());
        }
        if r.disk_runway_hours <= 0.0 {
            return Err("disk_runway_hours must be positive".to_owned());
        }

        let i = &self.intrusion;
        if i.failures_per_source_high == 0 {
            return Err("failures_per_source_high must be at least 1".to_owned());
        }
        if i.failures_per_source_high > i.failures_per_source_critical {
            return Err(
                "failures_per_source_high must not exceed failures_per_source_critical".to_owned()
            );
        }
        if i.peer_fanin_high > i.peer_fanin_critical {
            return Err("peer_fanin_high must not exceed peer_fanin_critical".to_owned());
        }
        if i.egress_multiplier <= 1.0 {
            return Err("egress_multiplier must be greater than 1".to_owned());
        }

        if self.hygiene.silence_intervals == 0 {
            return Err("silence_intervals must be at least 1".to_owned());
        }
        if self.hygiene.clock_skew_seconds <= 0 {
            return Err("clock_skew_seconds must be positive".to_owned());
        }
        Ok(())
    }

    /// Whether a publicly reachable port is expected for this asset.
    pub fn is_allowed_public(&self, port: u16, role: AssetRole) -> bool {
        if self.public_allowlist.contains(&port) {
            return true;
        }
        matches!(role, AssetRole::EdgeServer) && matches!(port, 80 | 443)
    }

    /// Severity of one exposed service, given how far it reaches and its role.
    ///
    /// The rule the whole exposure view rests on: reachability multiplies the
    /// intrinsic risk of the service behind the port.
    pub fn exposure_severity(
        &self,
        class: PortClass,
        scope: BindScope,
        role: AssetRole,
    ) -> Severity {
        let base = match class {
            PortClass::Database | PortClass::Infrastructure => Severity::Critical,
            PortClass::RemoteAdmin | PortClass::Cleartext => Severity::High,
            PortClass::FileShare => Severity::High,
            PortClass::Mail | PortClass::Web => Severity::Medium,
            PortClass::Other => Severity::Low,
        };
        let severity = match scope {
            BindScope::Loopback => return Severity::Info,
            BindScope::Public => base,
            BindScope::Private => downgrade(base),
        };
        // A database server answering anything from outside is always critical.
        if role == AssetRole::DatabaseServer
            && scope == BindScope::Public
            && class != PortClass::Other
        {
            return Severity::Critical;
        }
        severity
    }
}

const fn downgrade(severity: Severity) -> Severity {
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_valid() {
        assert!(DetectionPolicy::default().validate().is_ok());
    }

    #[test]
    fn inverted_thresholds_are_rejected() {
        let mut policy = DetectionPolicy::default();
        policy.resource.cpu_high = 99.0;
        policy.resource.cpu_critical = 90.0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn out_of_range_thresholds_are_rejected() {
        let mut policy = DetectionPolicy::default();
        policy.resource.disk_high = 180.0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn zero_sustained_samples_is_rejected() {
        let mut policy = DetectionPolicy::default();
        policy.resource.cpu_sustained_samples = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn loopback_never_produces_exposure_risk() {
        let policy = DetectionPolicy::default();
        assert_eq!(
            policy.exposure_severity(
                PortClass::Database,
                BindScope::Loopback,
                AssetRole::DatabaseServer
            ),
            Severity::Info
        );
    }

    #[test]
    fn public_database_is_critical_and_private_one_is_lower() {
        let policy = DetectionPolicy::default();
        assert_eq!(
            policy.exposure_severity(
                PortClass::Database,
                BindScope::Public,
                AssetRole::InternalServer
            ),
            Severity::Critical
        );
        assert_eq!(
            policy.exposure_severity(
                PortClass::Database,
                BindScope::Private,
                AssetRole::InternalServer
            ),
            Severity::High
        );
    }

    #[test]
    fn edge_servers_may_publish_http() {
        let policy = DetectionPolicy::default();
        assert!(policy.is_allowed_public(443, AssetRole::EdgeServer));
        assert!(!policy.is_allowed_public(443, AssetRole::DatabaseServer));
        assert!(!policy.is_allowed_public(22, AssetRole::EdgeServer));
    }

    #[test]
    fn allowlist_is_honoured_for_every_role() {
        let policy = DetectionPolicy { public_allowlist: vec![8443], ..DetectionPolicy::default() };
        assert!(policy.is_allowed_public(8443, AssetRole::DatabaseServer));
    }

    #[test]
    fn policy_round_trips_through_json() {
        let policy = DetectionPolicy::default();
        let encoded = serde_json::to_string(&policy).unwrap();
        let decoded: DetectionPolicy = serde_json::from_str(&encoded).unwrap();
        assert_eq!(policy, decoded);
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        let error = serde_json::from_str::<DetectionPolicy>(r#"{"resourc": {}}"#).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
