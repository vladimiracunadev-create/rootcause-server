//! Baseline controls that should already be in place before anything happens.

use crate::{
    detect::{DetectionInput, fingerprint, techniques},
    models::{Category, Evidence, IncidentCandidate, Severity},
    policy::DetectionPolicy,
    runbook,
};

const RULE_FIREWALL: &str = "hygiene.firewall.disabled";
const RULE_UPDATES: &str = "hygiene.updates.pending";
const RULE_CLOCK: &str = "hygiene.clock.skew";

pub(super) fn detect(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    clock(policy, input, findings);
    let Some(security) = input.security else { return };
    let hostname = input.hostname();
    let platform = input.registration.platform;
    let observed_at = input.sample.observed_at;

    if let Some(firewall) = &security.firewall
        && (!firewall.enabled || !firewall.default_inbound_deny)
    {
        let severity = if firewall.enabled { Severity::Medium } else { Severity::High };
        let state = if firewall.enabled {
            "está activo pero acepta tráfico entrante por omisión"
        } else {
            "está desactivado"
        };
        findings.push(IncidentCandidate {
            fingerprint: fingerprint(input, RULE_FIREWALL, &firewall.engine),
            asset_id: input.sample.agent_id,
            title: format!("El firewall de {hostname} no filtra el tráfico entrante"),
            summary: format!(
                "El motor {} {state}. Sin filtro en el host, cualquier servicio que se publique por error queda alcanzable en el mismo instante en que arranca.",
                firewall.engine
            ),
            severity,
            category: Category::Hygiene,
            root_cause: format!(
                "El firewall del host no aplica una política de denegación entrante ({}, {} reglas).",
                if firewall.enabled { "activo" } else { "inactivo" },
                firewall.rule_count
            ),
            confidence: 0.98,
            evidence: vec![Evidence::fact(
                "host.firewall",
                format!("Estado de {}", firewall.engine),
                format!(
                    "activo={} · reglas={} · denegación entrante por omisión={}",
                    firewall.enabled, firewall.rule_count, firewall.default_inbound_deny
                ),
                observed_at,
            )],
            recommended_actions: vec![
                "Define una política de denegación entrante y abre solo los puertos que el servicio necesita.".to_owned(),
                "Antes de activarlo, asegura la regla de tu propio acceso remoto para no quedar fuera del servidor.".to_owned(),
                "No sustituyas el firewall del host por el perimetral: el tráfico interno también necesita filtro.".to_owned(),
            ],
            runbook: runbook::enable_firewall(platform),
            techniques: techniques(RULE_FIREWALL),
        });
    }

    if let Some(pending) = security.pending_security_updates
        && pending > 0
    {
        let severity = if pending >= policy.hygiene.pending_updates_high {
            Severity::High
        } else {
            Severity::Medium
        };
        findings.push(IncidentCandidate {
            fingerprint: fingerprint(input, RULE_UPDATES, ""),
            asset_id: input.sample.agent_id,
            title: format!("{pending} actualizaciones de seguridad pendientes en {hostname}"),
            summary: format!(
                "El sistema declara {pending} paquete(s) con parche de seguridad publicado y sin aplicar. Cada uno es una vulnerabilidad ya conocida por quien quiera usarla."
            ),
            severity,
            category: Category::Hygiene,
            root_cause: "El servidor opera con parches de seguridad disponibles y no instalados."
                .to_owned(),
            confidence: 0.95,
            evidence: vec![Evidence::metric(
                "host.updates.pending_security",
                "Actualizaciones de seguridad pendientes",
                f64::from(pending),
                f64::from(policy.hygiene.pending_updates_high),
                observed_at,
            )],
            recommended_actions: vec![
                "Programa una ventana de actualización y aplica primero los paquetes expuestos a la red.".to_owned(),
                "Verifica que el reinicio de servicios quede incluido: un paquete actualizado sin reinicio sigue ejecutando el código viejo.".to_owned(),
            ],
            runbook: vec![],
            techniques: techniques(RULE_UPDATES),
        });
    }
}

fn clock(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    let skew = (input.received_at - input.sample.observed_at).num_seconds();
    let tolerance = policy.hygiene.clock_skew_seconds;
    if skew.abs() <= tolerance {
        return;
    }
    let direction = if skew > 0 { "atrasado" } else { "adelantado" };
    findings.push(IncidentCandidate {
        fingerprint: fingerprint(input, RULE_CLOCK, ""),
        asset_id: input.sample.agent_id,
        title: format!("El reloj de {} está {direction}", input.hostname()),
        summary: format!(
            "La diferencia entre la hora del host y la del servidor es de {} segundos. Con esa deriva, correlacionar sus registros con los de otro equipo deja de ser fiable justo cuando más se necesita.",
            skew.abs()
        ),
        severity: Severity::Medium,
        category: Category::Hygiene,
        root_cause: "El host no mantiene su reloj sincronizado con una fuente de tiempo confiable."
            .to_owned(),
        confidence: 0.99,
        evidence: vec![Evidence::metric(
            "host.clock.skew_seconds",
            "Diferencia de reloj frente al servidor",
            skew.abs() as f64,
            tolerance as f64,
            input.sample.observed_at,
        )],
        recommended_actions: vec![
            "Habilita y verifica la sincronización horaria del host (NTP o el servicio equivalente).".to_owned(),
            "Revisa si la deriva apareció de golpe: un salto de reloj también se usa para dificultar el análisis de registros.".to_owned(),
        ],
        runbook: vec![],
        techniques: techniques(RULE_CLOCK),
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration;

    use super::*;
    use crate::{
        detect::{DetectionEngine, fixtures},
        security::{FirewallState, SecuritySignals},
    };

    fn analyze(signals: SecuritySignals, skew_seconds: i64) -> Vec<IncidentCandidate> {
        let registration = fixtures::registration("internal");
        let sample = fixtures::sample();
        let received_at = sample.observed_at + Duration::seconds(skew_seconds);
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, received_at, &baseline)
            .with_security(Some(&signals));
        DetectionEngine::default().analyze(&input)
    }

    fn firewall(enabled: bool, default_inbound_deny: bool) -> SecuritySignals {
        SecuritySignals {
            firewall: Some(FirewallState {
                engine: "ufw".to_owned(),
                enabled,
                rule_count: 12,
                default_inbound_deny,
            }),
            ..SecuritySignals::default()
        }
    }

    #[test]
    fn a_firewall_denying_inbound_traffic_is_silent() {
        assert!(analyze(firewall(true, true), 0).is_empty());
    }

    #[test]
    fn a_disabled_firewall_is_high() {
        let findings = analyze(firewall(false, false), 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(!findings[0].runbook.is_empty());
    }

    #[test]
    fn an_enabled_firewall_that_allows_everything_is_medium() {
        let findings = analyze(firewall(true, false), 0);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn pending_updates_scale_with_their_number() {
        let few =
            SecuritySignals { pending_security_updates: Some(2), ..SecuritySignals::default() };
        assert_eq!(analyze(few, 0)[0].severity, Severity::Medium);
        let many =
            SecuritySignals { pending_security_updates: Some(40), ..SecuritySignals::default() };
        assert_eq!(analyze(many, 0)[0].severity, Severity::High);
    }

    #[test]
    fn a_fully_patched_host_is_silent() {
        let signals =
            SecuritySignals { pending_security_updates: Some(0), ..SecuritySignals::default() };
        assert!(analyze(signals, 0).is_empty());
    }

    #[test]
    fn clock_skew_is_reported_in_both_directions() {
        let late = analyze(SecuritySignals::default(), 900);
        assert_eq!(late.len(), 1);
        assert!(late[0].title.contains("atrasado"));
        let early = analyze(SecuritySignals::default(), -900);
        assert!(early[0].title.contains("adelantado"));
    }

    #[test]
    fn ordinary_transport_delay_is_not_skew() {
        assert!(analyze(SecuritySignals::default(), 30).is_empty());
    }
}
