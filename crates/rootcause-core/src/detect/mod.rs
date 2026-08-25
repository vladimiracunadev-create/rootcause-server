//! Deterministic detection over the evidence an agent reported.
//!
//! Every rule in this module answers one question about a server, and every
//! finding it produces carries the observation that triggered it. Nothing here
//! reaches the network, reads a file or executes a command: given the same
//! input and the same policy, the output is always identical, which is what
//! makes an incident auditable months later.

mod availability;
mod exposure;
mod hygiene;
mod integrity;
mod intrusion;
mod resource;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

pub use availability::{agent_silence, silence_fingerprint};

use crate::{
    models::{AssetRegistration, Category, IncidentCandidate, MetricSample, Severity},
    policy::DetectionPolicy,
    security::SecuritySignals,
};

/// A published detection rule.
///
/// The catalog is part of the product surface: the console and the docs render
/// it so that "what RootCause detects today" is never a marketing claim that
/// drifts away from the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: &'static str,
    pub category: Category,
    pub title: &'static str,
    /// The operational question the rule answers.
    pub question: &'static str,
    /// Highest severity the rule can reach.
    pub ceiling: Severity,
    /// MITRE ATT&CK techniques the rule relates to.
    pub techniques: &'static [&'static str],
}

/// Every rule this build implements.
pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "exposure.service.public",
        category: Category::Exposure,
        title: "Servicio alcanzable fuera del host",
        question: "¿Hay un servicio escuchando en una dirección que no es loopback?",
        ceiling: Severity::Critical,
        techniques: &["T1190"],
    },
    RuleInfo {
        id: "exposure.cleartext.protocol",
        category: Category::Exposure,
        title: "Protocolo sin cifrar publicado",
        question: "¿Se publican credenciales en claro por Telnet, FTP, LDAP o POP3?",
        ceiling: Severity::High,
        techniques: &["T1040", "T1190"],
    },
    RuleInfo {
        id: "intrusion.auth.bruteforce",
        category: Category::Intrusion,
        title: "Ráfaga de autenticación fallida",
        question: "¿Un mismo origen acumula intentos fallidos sobre este servidor?",
        ceiling: Severity::Critical,
        techniques: &["T1110.001"],
    },
    RuleInfo {
        id: "intrusion.auth.spray",
        category: Category::Intrusion,
        title: "Barrido de usuarios",
        question: "¿Un origen prueba muchos nombres de usuario distintos?",
        ceiling: Severity::High,
        techniques: &["T1110.003"],
    },
    RuleInfo {
        id: "intrusion.auth.distributed",
        category: Category::Intrusion,
        title: "Presión distribuida sobre la autenticación",
        question: "¿Muchos orígenes distintos fallan contra el mismo servidor?",
        ceiling: Severity::High,
        techniques: &["T1110"],
    },
    RuleInfo {
        id: "intrusion.auth.success_after_burst",
        category: Category::Intrusion,
        title: "Acceso concedido tras una ráfaga fallida",
        question: "¿Un origen que fallaba repetidamente consiguió entrar?",
        ceiling: Severity::Critical,
        techniques: &["T1110", "T1078"],
    },
    RuleInfo {
        id: "intrusion.network.fanin",
        category: Category::Intrusion,
        title: "Concentración anómala de orígenes",
        question: "¿Demasiadas direcciones distintas tocan el host a la vez?",
        ceiling: Severity::High,
        techniques: &["T1046", "T1595"],
    },
    RuleInfo {
        id: "intrusion.egress.anomaly",
        category: Category::Intrusion,
        title: "Salida de datos fuera de lo habitual",
        question: "¿El tráfico de salida se disparó respecto de su propia línea base?",
        ceiling: Severity::High,
        techniques: &["T1041"],
    },
    RuleInfo {
        id: "integrity.file.changed",
        category: Category::Integrity,
        title: "Archivo crítico modificado",
        question: "¿Cambió un archivo de configuración que sostiene la seguridad del host?",
        ceiling: Severity::High,
        techniques: &["T1543", "T1098"],
    },
    RuleInfo {
        id: "integrity.file.permissions",
        category: Category::Integrity,
        title: "Permisos debilitados en archivo crítico",
        question: "¿Un archivo sensible quedó escribible por cualquier usuario?",
        ceiling: Severity::High,
        techniques: &["T1222"],
    },
    RuleInfo {
        id: "hygiene.firewall.disabled",
        category: Category::Hygiene,
        title: "Firewall del host inactivo",
        question: "¿El servidor depende solo del perímetro para filtrar tráfico?",
        ceiling: Severity::High,
        techniques: &["T1562.004"],
    },
    RuleInfo {
        id: "hygiene.updates.pending",
        category: Category::Hygiene,
        title: "Actualizaciones de seguridad pendientes",
        question: "¿Hay parches de seguridad publicados y no aplicados?",
        ceiling: Severity::High,
        techniques: &["T1190"],
    },
    RuleInfo {
        id: "hygiene.clock.skew",
        category: Category::Hygiene,
        title: "Reloj del host desincronizado",
        question: "¿La hora del servidor permite correlacionar sus registros?",
        ceiling: Severity::Medium,
        techniques: &["T1070.006"],
    },
    RuleInfo {
        id: "availability.agent.silence",
        category: Category::Availability,
        title: "El sensor dejó de reportar",
        question: "¿El agente calló sin que nadie lo detuviera de forma planificada?",
        ceiling: Severity::High,
        techniques: &["T1562.001"],
    },
    RuleInfo {
        id: "resource.cpu.saturation",
        category: Category::Resource,
        title: "Saturación sostenida de CPU",
        question: "¿La CPU lleva varias muestras seguidas al límite?",
        ceiling: Severity::Critical,
        techniques: &["T1496"],
    },
    RuleInfo {
        id: "resource.memory.pressure",
        category: Category::Resource,
        title: "Presión de memoria",
        question: "¿La memoria comprometida puede provocar paginación o OOM?",
        ceiling: Severity::Critical,
        techniques: &["T1499"],
    },
    RuleInfo {
        id: "resource.disk.capacity",
        category: Category::Resource,
        title: "Capacidad de disco al límite",
        question: "¿Queda margen de disco para operar y registrar?",
        ceiling: Severity::Critical,
        techniques: &["T1499"],
    },
    RuleInfo {
        id: "resource.disk.runway",
        category: Category::Resource,
        title: "Disco llenándose a ritmo insostenible",
        question: "¿Cuántas horas faltan para quedarse sin disco al ritmo actual?",
        ceiling: Severity::High,
        techniques: &["T1499"],
    },
];

/// Look up a published rule by identifier.
pub fn rule(id: &str) -> Option<RuleInfo> {
    RULES.iter().copied().find(|entry| entry.id == id)
}

/// Everything one detection pass may look at.
#[derive(Debug, Clone, Copy)]
pub struct DetectionInput<'a> {
    pub registration: &'a AssetRegistration,
    pub sample: &'a MetricSample,
    pub security: Option<&'a SecuritySignals>,
    /// Previous samples for this asset, oldest first, excluding `sample`.
    pub history: &'a [MetricSample],
    /// Last known digest for every watched file, by path.
    pub file_baseline: &'a BTreeMap<String, String>,
    /// When the server received the envelope.
    pub received_at: DateTime<Utc>,
}

impl<'a> DetectionInput<'a> {
    pub fn new(
        registration: &'a AssetRegistration,
        sample: &'a MetricSample,
        received_at: DateTime<Utc>,
        file_baseline: &'a BTreeMap<String, String>,
    ) -> Self {
        Self { registration, sample, security: None, history: &[], file_baseline, received_at }
    }

    #[must_use]
    pub fn with_security(mut self, security: Option<&'a SecuritySignals>) -> Self {
        self.security = security;
        self
    }

    #[must_use]
    pub fn with_history(mut self, history: &'a [MetricSample]) -> Self {
        self.history = history;
        self
    }

    pub fn hostname(&self) -> &str {
        &self.registration.hostname
    }
}

/// Runs every rule against one telemetry envelope.
#[derive(Debug, Clone, Default)]
pub struct DetectionEngine {
    policy: DetectionPolicy,
}

impl DetectionEngine {
    /// Build an engine, rejecting a policy that could never fire.
    pub fn new(policy: DetectionPolicy) -> Result<Self, String> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub const fn policy(&self) -> &DetectionPolicy {
        &self.policy
    }

    /// Number of published rules; surfaced by `/api/v1/status`.
    pub const fn rule_count() -> usize {
        RULES.len()
    }

    /// Evaluate every rule, highest severity first.
    pub fn analyze(&self, input: &DetectionInput<'_>) -> Vec<IncidentCandidate> {
        let mut findings = Vec::new();
        exposure::detect(&self.policy, input, &mut findings);
        intrusion::detect(&self.policy, input, &mut findings);
        integrity::detect(&self.policy, input, &mut findings);
        hygiene::detect(&self.policy, input, &mut findings);
        resource::detect(&self.policy, input, &mut findings);

        let mut findings = merge_by_fingerprint(findings);
        findings.sort_by(|left, right| {
            right
                .severity
                .rank()
                .cmp(&left.severity.rank())
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });
        findings
    }
}

/// Collapse candidates that describe the same condition in one cycle.
///
/// A service bound to both `0.0.0.0` and `::` is one finding, not two: without
/// this the occurrence counter would advance twice per cycle and an operator
/// would read a stable condition as an escalating one.
fn merge_by_fingerprint(findings: Vec<IncidentCandidate>) -> Vec<IncidentCandidate> {
    let mut merged: BTreeMap<String, IncidentCandidate> = BTreeMap::new();
    for candidate in findings {
        match merged.get_mut(&candidate.fingerprint) {
            None => {
                merged.insert(candidate.fingerprint.clone(), candidate);
            }
            Some(existing) => {
                if candidate.severity > existing.severity {
                    let mut evidence = std::mem::take(&mut existing.evidence);
                    *existing = candidate;
                    evidence.append(&mut existing.evidence);
                    existing.evidence = evidence;
                } else {
                    for evidence in candidate.evidence {
                        if !existing.evidence.contains(&evidence) {
                            existing.evidence.push(evidence);
                        }
                    }
                }
            }
        }
    }
    merged.into_values().collect()
}

/// Build the fingerprint that deduplicates a finding across cycles.
pub(crate) fn fingerprint(input: &DetectionInput<'_>, rule_id: &str, key: &str) -> String {
    let agent = input.sample.agent_id;
    if key.is_empty() { format!("{agent}:{rule_id}") } else { format!("{agent}:{rule_id}:{key}") }
}

/// Techniques published for a rule, as owned strings for the incident payload.
pub(crate) fn techniques(rule_id: &str) -> Vec<String> {
    rule(rule_id)
        .map(|entry| entry.techniques.iter().map(|value| (*value).to_owned()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use crate::models::{AssetRegistration, MetricSample, Platform};

    pub fn agent_id() -> Uuid {
        Uuid::from_u128(0x5eed_0000_0000_0000_0000_0000_0000_0001)
    }

    pub fn registration(role: &str) -> AssetRegistration {
        let mut labels = BTreeMap::new();
        if !role.is_empty() {
            labels.insert("role".to_owned(), role.to_owned());
        }
        AssetRegistration {
            agent_id: agent_id(),
            hostname: "srv-app-01".to_owned(),
            platform: Platform::Linux,
            os_version: Some("Debian 13".to_owned()),
            kernel_version: Some("6.12.0".to_owned()),
            architecture: "x86_64".to_owned(),
            agent_version: "0.2.0".to_owned(),
            labels,
        }
    }

    pub fn sample_at(observed_at: DateTime<Utc>) -> MetricSample {
        MetricSample {
            agent_id: agent_id(),
            observed_at,
            cpu_percent: 12.0,
            memory_percent: 34.0,
            disk_percent: 40.0,
            uptime_seconds: 86_400,
            load_average: Some([0.4, 0.3, 0.2]),
            network_rx_bytes: 1_000,
            network_tx_bytes: 1_000,
            disk_free_bytes: Some(50_000_000_000),
            process_count: Some(180),
        }
    }

    pub fn sample() -> MetricSample {
        sample_at(Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::fixtures::{registration, sample};

    #[test]
    fn rule_ids_are_unique_and_namespaced() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in RULES {
            assert!(seen.insert(entry.id), "duplicated rule id {}", entry.id);
            assert!(
                entry.id.starts_with(entry.category.as_str()),
                "rule {} must be namespaced by its category",
                entry.id
            );
        }
    }

    #[test]
    fn every_rule_declares_a_question_and_a_technique() {
        for entry in RULES {
            assert!(!entry.question.is_empty(), "{} has no question", entry.id);
            assert!(!entry.techniques.is_empty(), "{} has no ATT&CK mapping", entry.id);
        }
    }

    #[test]
    fn a_healthy_server_produces_no_findings() {
        let registration = registration("internal");
        let sample = sample();
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline);
        assert!(DetectionEngine::default().analyze(&input).is_empty());
    }

    #[test]
    fn invalid_policies_are_rejected_at_construction() {
        let mut policy = DetectionPolicy::default();
        policy.intrusion.egress_multiplier = 0.5;
        assert!(DetectionEngine::new(policy).is_err());
    }

    #[test]
    fn rule_count_matches_the_catalog() {
        assert_eq!(DetectionEngine::rule_count(), RULES.len());
        assert!(rule("exposure.service.public").is_some());
        assert!(rule("does.not.exist").is_none());
    }
}
