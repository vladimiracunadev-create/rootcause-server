use crate::{Evidence, IncidentCandidate, MetricSample, Severity};

#[derive(Debug, Clone)]
pub struct RcaPolicy {
    pub cpu_high: f32,
    pub cpu_critical: f32,
    pub memory_high: f32,
    pub memory_critical: f32,
    pub disk_high: f32,
    pub disk_critical: f32,
}

impl Default for RcaPolicy {
    fn default() -> Self {
        Self {
            cpu_high: 90.0,
            cpu_critical: 98.0,
            memory_high: 88.0,
            memory_critical: 96.0,
            disk_high: 85.0,
            disk_critical: 95.0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RcaEngine {
    policy: RcaPolicy,
}

impl RcaEngine {
    pub fn new(policy: RcaPolicy) -> Self {
        Self { policy }
    }

    pub fn analyze(&self, sample: &MetricSample, hostname: &str) -> Vec<IncidentCandidate> {
        let mut findings = Vec::new();

        if sample.disk_percent >= self.policy.disk_high {
            let severity = if sample.disk_percent >= self.policy.disk_critical {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(IncidentCandidate {
                fingerprint: format!("{}:disk-capacity", sample.agent_id),
                asset_id: sample.agent_id,
                title: format!("Disk capacity pressure on {hostname}"),
                summary: format!(
                    "Disk usage reached {:.1}%, reducing the operating margin for services and updates.",
                    sample.disk_percent
                ),
                severity,
                root_cause: "Available disk capacity crossed the configured safety threshold."
                    .to_owned(),
                confidence: 0.96,
                evidence: vec![Evidence {
                    kind: "metric.disk.used_percent".to_owned(),
                    summary: "Disk usage threshold exceeded".to_owned(),
                    observed_value: f64::from(sample.disk_percent),
                    threshold: f64::from(self.policy.disk_high),
                    observed_at: sample.observed_at,
                }],
                recommended_actions: vec![
                    "Identify the directories or applications consuming space.".to_owned(),
                    "Verify log rotation and temporary-file retention before deleting data."
                        .to_owned(),
                    "Increase capacity if usage represents expected growth.".to_owned(),
                ],
            });
        }

        if sample.memory_percent >= self.policy.memory_high {
            let severity = if sample.memory_percent >= self.policy.memory_critical {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(IncidentCandidate {
                fingerprint: format!("{}:memory-pressure", sample.agent_id),
                asset_id: sample.agent_id,
                title: format!("Memory pressure on {hostname}"),
                summary: format!(
                    "Memory usage reached {:.1}%, which can trigger paging and application latency.",
                    sample.memory_percent
                ),
                severity,
                root_cause: "Sustained memory demand crossed the configured capacity threshold."
                    .to_owned(),
                confidence: 0.84,
                evidence: vec![Evidence {
                    kind: "metric.memory.used_percent".to_owned(),
                    summary: "Memory usage threshold exceeded".to_owned(),
                    observed_value: f64::from(sample.memory_percent),
                    threshold: f64::from(self.policy.memory_high),
                    observed_at: sample.observed_at,
                }],
                recommended_actions: vec![
                    "Inspect the highest-memory processes and recent workload changes.".to_owned(),
                    "Confirm whether paging or out-of-memory events occurred.".to_owned(),
                    "Restart a service only after preserving diagnostic evidence.".to_owned(),
                ],
            });
        }

        if sample.cpu_percent >= self.policy.cpu_high {
            let severity = if sample.cpu_percent >= self.policy.cpu_critical {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(IncidentCandidate {
                fingerprint: format!("{}:cpu-saturation", sample.agent_id),
                asset_id: sample.agent_id,
                title: format!("CPU saturation on {hostname}"),
                summary: format!(
                    "CPU usage reached {:.1}%. Correlation over subsequent samples is required to distinguish a spike from sustained saturation.",
                    sample.cpu_percent
                ),
                severity,
                root_cause: "Compute demand crossed the configured saturation threshold."
                    .to_owned(),
                confidence: 0.70,
                evidence: vec![Evidence {
                    kind: "metric.cpu.used_percent".to_owned(),
                    summary: "CPU usage threshold exceeded".to_owned(),
                    observed_value: f64::from(sample.cpu_percent),
                    threshold: f64::from(self.policy.cpu_high),
                    observed_at: sample.observed_at,
                }],
                recommended_actions: vec![
                    "Correlate the spike with processes, deployments and scheduled jobs."
                        .to_owned(),
                    "Review multiple samples before terminating a process.".to_owned(),
                ],
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    fn sample(cpu: f32, memory: f32, disk: f32) -> MetricSample {
        MetricSample {
            agent_id: Uuid::nil(),
            observed_at: Utc::now(),
            cpu_percent: cpu,
            memory_percent: memory,
            disk_percent: disk,
            uptime_seconds: 60,
            load_average: None,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
        }
    }

    #[test]
    fn healthy_sample_has_no_findings() {
        let findings = RcaEngine::default().analyze(&sample(25.0, 50.0, 40.0), "test");
        assert!(findings.is_empty());
    }

    #[test]
    fn critical_disk_pressure_is_detected() {
        let findings = RcaEngine::default().analyze(&sample(25.0, 50.0, 97.0), "test");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].fingerprint.ends_with("disk-capacity"));
    }

    #[test]
    fn multiple_resource_pressures_are_preserved() {
        let findings = RcaEngine::default().analyze(&sample(99.0, 97.0, 96.0), "test");
        assert_eq!(findings.len(), 3);
    }
}
