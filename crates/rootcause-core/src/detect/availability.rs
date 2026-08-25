//! The sensor stopped answering.
//!
//! This is the one rule that fires on the *absence* of evidence, so it runs on
//! the server rather than on a telemetry envelope: an agent that was silenced
//! cannot report that it was silenced.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    models::{AssetRegistration, Category, Evidence, IncidentCandidate, Severity},
    policy::DetectionPolicy,
};

const RULE_SILENCE: &str = "availability.agent.silence";

/// Raise a finding when an asset has been quiet for too many collection cycles.
///
/// Returns `None` while the asset is within its expected reporting window.
pub fn agent_silence(
    policy: &DetectionPolicy,
    registration: &AssetRegistration,
    last_seen: DateTime<Utc>,
    now: DateTime<Utc>,
    interval_seconds: u64,
) -> Option<IncidentCandidate> {
    let interval = interval_seconds.max(5);
    let tolerated = interval.saturating_mul(u64::from(policy.hygiene.silence_intervals));
    let silence = (now - last_seen).num_seconds();
    if silence <= 0 || (silence as u64) < tolerated {
        return None;
    }

    let minutes = silence / 60;
    let severity = if (silence as u64) >= tolerated.saturating_mul(4) {
        Severity::High
    } else {
        Severity::Medium
    };
    let hostname = &registration.hostname;

    Some(IncidentCandidate {
        fingerprint: format!("{}:{RULE_SILENCE}", registration.agent_id),
        asset_id: registration.agent_id,
        title: format!("{hostname} dejó de reportar"),
        summary: format!(
            "No llega telemetría desde hace {minutes} minuto(s), cuando el intervalo acordado es de {interval} segundos. Un apagado planificado, una caída de red y un agente detenido a propósito se ven exactamente igual desde aquí: hay que distinguirlos fuera de RootCause."
        ),
        severity,
        category: Category::Availability,
        root_cause:
            "El agente no entregó telemetría dentro de la ventana esperada y el servidor no puede afirmar nada sobre el estado actual del host."
                .to_owned(),
        confidence: 0.99,
        evidence: vec![Evidence::metric(
            "agent.silence_seconds",
            format!("Silencio de {hostname} frente a la ventana tolerada"),
            silence as f64,
            tolerated as f64,
            last_seen,
        )],
        recommended_actions: vec![
            "Confirma si el equipo está apagado o en mantenimiento antes de escalar.".to_owned(),
            "Si el equipo responde pero el agente no reporta, revisa el servicio y sus registros.".to_owned(),
            "Un agente detenido sin registro de cambio se investiga como manipulación, no como falla.".to_owned(),
        ],
        runbook: vec![],
        techniques: super::techniques(RULE_SILENCE),
    })
}

/// Identifier of the asset a silence finding belongs to.
pub fn silence_fingerprint(agent_id: Uuid) -> String {
    format!("{agent_id}:{RULE_SILENCE}")
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::detect::fixtures;

    #[test]
    fn a_reporting_agent_produces_no_finding() {
        let registration = fixtures::registration("internal");
        let now = Utc::now();
        assert!(
            agent_silence(
                &DetectionPolicy::default(),
                &registration,
                now - Duration::seconds(30),
                now,
                30
            )
            .is_none()
        );
    }

    #[test]
    fn silence_beyond_the_tolerated_window_is_reported() {
        let registration = fixtures::registration("internal");
        let now = Utc::now();
        let finding = agent_silence(
            &DetectionPolicy::default(),
            &registration,
            now - Duration::seconds(300),
            now,
            30,
        )
        .expect("four missed cycles must be reported");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.category, Category::Availability);
        assert_eq!(finding.fingerprint, silence_fingerprint(registration.agent_id));
    }

    #[test]
    fn prolonged_silence_escalates() {
        let registration = fixtures::registration("internal");
        let now = Utc::now();
        let finding = agent_silence(
            &DetectionPolicy::default(),
            &registration,
            now - Duration::hours(3),
            now,
            30,
        )
        .unwrap();
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn a_future_timestamp_never_produces_a_finding() {
        let registration = fixtures::registration("internal");
        let now = Utc::now();
        assert!(
            agent_silence(
                &DetectionPolicy::default(),
                &registration,
                now + Duration::hours(1),
                now,
                30
            )
            .is_none()
        );
    }
}
