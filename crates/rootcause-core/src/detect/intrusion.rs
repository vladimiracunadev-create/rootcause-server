//! Someone is actively pushing against this server.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use crate::{
    detect::{DetectionInput, fingerprint, techniques},
    models::{Category, Evidence, IncidentCandidate, MetricSample, Severity},
    policy::DetectionPolicy,
    runbook,
    security::{AuthOutcome, SecuritySignals},
};

const RULE_BRUTEFORCE: &str = "intrusion.auth.bruteforce";
const RULE_SPRAY: &str = "intrusion.auth.spray";
const RULE_DISTRIBUTED: &str = "intrusion.auth.distributed";
const RULE_SUCCESS: &str = "intrusion.auth.success_after_burst";
const RULE_FANIN: &str = "intrusion.network.fanin";
const RULE_EGRESS: &str = "intrusion.egress.anomaly";

/// Authentication pressure coming from one address.
#[derive(Debug, Default)]
struct SourcePressure {
    failures: u32,
    successes: u32,
    usernames: BTreeSet<String>,
    services: BTreeSet<String>,
    last_seen: Option<DateTime<Utc>>,
}

pub(super) fn detect(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    if let Some(security) = input.security {
        authentication(policy, input, security, findings);
        fanin(policy, input, security, findings);
    }
    egress(policy, input, findings);
}

fn authentication(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    security: &SecuritySignals,
    findings: &mut Vec<IncidentCandidate>,
) {
    let mut by_source: BTreeMap<&str, SourcePressure> = BTreeMap::new();
    for event in &security.auth_events {
        let entry = by_source.entry(event.source_address.as_str()).or_default();
        match event.outcome {
            AuthOutcome::Failure => entry.failures = entry.failures.saturating_add(event.count),
            AuthOutcome::Success => entry.successes = entry.successes.saturating_add(event.count),
        }
        if let Some(username) = &event.username {
            entry.usernames.insert(username.clone());
        }
        entry.services.insert(event.service.clone());
        entry.last_seen =
            Some(entry.last_seen.map_or(event.last_seen, |seen| seen.max(event.last_seen)));
    }

    let hostname = input.hostname();
    let platform = input.registration.platform;
    let policy_intrusion = &policy.intrusion;
    let mut pressured_sources = 0_usize;
    let mut total_failures = 0_u32;

    for (address, pressure) in &by_source {
        total_failures = total_failures.saturating_add(pressure.failures);
        if pressure.failures == 0 {
            continue;
        }
        pressured_sources += 1;
        let observed_at = pressure.last_seen.unwrap_or(input.sample.observed_at);
        let services = pressure.services.iter().cloned().collect::<Vec<_>>().join(", ");

        if pressure.failures >= policy_intrusion.failures_per_source_high {
            let severity = if pressure.failures >= policy_intrusion.failures_per_source_critical {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(IncidentCandidate {
                fingerprint: fingerprint(input, RULE_BRUTEFORCE, address),
                asset_id: input.sample.agent_id,
                title: format!("Ráfaga de autenticación fallida desde {address} contra {hostname}"),
                summary: format!(
                    "{address} acumuló {} intentos fallidos contra {services}. Un servicio de autenticación expuesto recibe intentos automatizados de forma permanente; lo que convierte esto en un incidente es el volumen y su persistencia.",
                    pressure.failures
                ),
                severity,
                category: Category::Intrusion,
                root_cause: format!(
                    "El servicio de autenticación acepta intentos ilimitados desde {address} sin retardo, bloqueo ni segunda credencial."
                ),
                confidence: 0.93,
                evidence: vec![
                    Evidence::metric(
                        "auth.failures.by_source",
                        format!("Intentos fallidos desde {address}"),
                        f64::from(pressure.failures),
                        f64::from(policy_intrusion.failures_per_source_high),
                        observed_at,
                    ),
                    Evidence::fact(
                        "auth.services",
                        "Servicios afectados",
                        services.clone(),
                        observed_at,
                    ),
                ],
                recommended_actions: vec![
                    format!("Verifica si {address} pertenece a tu operación antes de bloquearla."),
                    "Limita la exposición del servicio de autenticación a orígenes conocidos o a la VPN.".to_owned(),
                    "Exige llaves o segundo factor y desactiva la autenticación por contraseña donde sea posible.".to_owned(),
                ],
                runbook: runbook::block_source(platform, address),
                techniques: techniques(RULE_BRUTEFORCE),
            });
        }

        if pressure.usernames.len() >= policy_intrusion.sprayed_usernames {
            let sampled = pressure.usernames.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
            findings.push(IncidentCandidate {
                fingerprint: fingerprint(input, RULE_SPRAY, address),
                asset_id: input.sample.agent_id,
                title: format!("Barrido de usuarios desde {address} contra {hostname}"),
                summary: format!(
                    "{address} probó {} nombres de usuario distintos. Esto no es alguien que olvidó su clave: es una lista.",
                    pressure.usernames.len()
                ),
                severity: Severity::High,
                category: Category::Intrusion,
                root_cause:
                    "El servicio revela que acepta intentos para cualquier usuario y no penaliza el barrido."
                        .to_owned(),
                confidence: 0.9,
                evidence: vec![
                    Evidence::metric(
                        "auth.usernames.distinct",
                        format!("Usuarios distintos probados desde {address}"),
                        pressure.usernames.len() as f64,
                        policy_intrusion.sprayed_usernames as f64,
                        observed_at,
                    ),
                    Evidence::fact(
                        "auth.usernames.sample",
                        "Muestra de los usuarios probados",
                        sampled,
                        observed_at,
                    ),
                ],
                recommended_actions: vec![
                    "Revisa si alguno de los usuarios probados existe realmente en el servidor.".to_owned(),
                    "Desactiva las cuentas genéricas heredadas (admin, test, oracle, git) que no estén en uso.".to_owned(),
                    format!("Bloquea {address} tras confirmar que no es un origen legítimo."),
                ],
                runbook: runbook::block_source(platform, address),
                techniques: techniques(RULE_SPRAY),
            });
        }

        if pressure.successes > 0 && pressure.failures >= policy_intrusion.failures_per_source_high
        {
            let users = pressure.usernames.iter().cloned().collect::<Vec<_>>().join(", ");
            findings.push(IncidentCandidate {
                fingerprint: fingerprint(input, RULE_SUCCESS, address),
                asset_id: input.sample.agent_id,
                title: format!("Acceso concedido a {address} tras {} intentos fallidos", pressure.failures),
                summary: format!(
                    "{address} falló {} veces y después autenticó correctamente contra {services}. Trata la sesión como comprometida hasta demostrar lo contrario.",
                    pressure.failures
                ),
                severity: Severity::Critical,
                category: Category::Intrusion,
                root_cause:
                    "Una credencial válida fue usada desde un origen que venía adivinando credenciales."
                        .to_owned(),
                confidence: 0.88,
                evidence: vec![
                    Evidence::metric(
                        "auth.success_after_failures",
                        format!("Accesos concedidos a {address} tras la ráfaga"),
                        f64::from(pressure.successes),
                        1.0,
                        observed_at,
                    ),
                    Evidence::fact("auth.usernames", "Usuarios involucrados", users, observed_at),
                ],
                recommended_actions: vec![
                    "Revisa las sesiones activas y ciérralas si no corresponden a una persona identificada.".to_owned(),
                    "Rota la credencial de las cuentas involucradas y revisa sus llaves autorizadas.".to_owned(),
                    "Busca persistencia creada después del acceso: tareas programadas, servicios y claves nuevas.".to_owned(),
                ],
                runbook: runbook::block_source(platform, address),
                techniques: techniques(RULE_SUCCESS),
            });
        }
    }

    if pressured_sources >= policy_intrusion.distributed_sources {
        let observed_at = input.sample.observed_at;
        findings.push(IncidentCandidate {
            fingerprint: fingerprint(input, RULE_DISTRIBUTED, ""),
            asset_id: input.sample.agent_id,
            title: format!("Presión distribuida sobre la autenticación de {hostname}"),
            summary: format!(
                "{pressured_sources} orígenes distintos acumularon {total_failures} intentos fallidos. Bloquear direcciones una por una no contendrá una campaña distribuida."
            ),
            severity: Severity::High,
            category: Category::Intrusion,
            root_cause:
                "El servicio de autenticación está publicado a Internet sin limitación de origen ni de tasa."
                    .to_owned(),
            confidence: 0.9,
            evidence: vec![Evidence::metric(
                "auth.sources.distinct",
                "Orígenes distintos con intentos fallidos",
                pressured_sources as f64,
                policy_intrusion.distributed_sources as f64,
                observed_at,
            )],
            recommended_actions: vec![
                "Publica el servicio solo tras VPN o limita el acceso a rangos conocidos.".to_owned(),
                "Activa limitación de tasa y bloqueo temporal por origen en el propio servicio.".to_owned(),
                "Exige segundo factor para las cuentas administrativas.".to_owned(),
            ],
            runbook: vec![],
            techniques: techniques(RULE_DISTRIBUTED),
        });
    }
}

fn fanin(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    security: &SecuritySignals,
    findings: &mut Vec<IncidentCandidate>,
) {
    let distinct = security.distinct_peers();
    if distinct < policy.intrusion.peer_fanin_high {
        return;
    }
    let severity = if distinct >= policy.intrusion.peer_fanin_critical {
        Severity::High
    } else {
        Severity::Medium
    };
    let ports: BTreeSet<u16> = security.peers.iter().map(|peer| peer.local_port).collect();
    let observed_at = input.sample.observed_at;

    findings.push(IncidentCandidate {
        fingerprint: fingerprint(input, RULE_FANIN, ""),
        asset_id: input.sample.agent_id,
        title: format!("Concentración anómala de orígenes sobre {}", input.hostname()),
        summary: format!(
            "{distinct} direcciones distintas mantienen conexiones contra {} puerto(s) del host. Puede ser tráfico legítimo de un balanceador o el reconocimiento previo a un intento dirigido: la diferencia está en si esos orígenes son conocidos.",
            ports.len()
        ),
        severity,
        category: Category::Intrusion,
        root_cause: "El host acepta conexiones desde un conjunto de orígenes mucho mayor que el habitual."
            .to_owned(),
        confidence: 0.62,
        evidence: vec![
            Evidence::metric(
                "network.peers.distinct",
                "Direcciones remotas distintas conectadas",
                distinct as f64,
                policy.intrusion.peer_fanin_high as f64,
                observed_at,
            ),
            Evidence::fact(
                "network.ports.touched",
                "Puertos locales alcanzados",
                ports.iter().take(12).map(u16::to_string).collect::<Vec<_>>().join(", "),
                observed_at,
            ),
        ],
        recommended_actions: vec![
            "Compara los orígenes con los rangos conocidos de tu balanceador, CDN o monitoreo.".to_owned(),
            "Si los orígenes no son conocidos, limita la exposición del puerto antes de investigar más.".to_owned(),
            "Correlaciona con los intentos de autenticación fallidos del mismo período.".to_owned(),
        ],
        runbook: vec![],
        techniques: techniques(RULE_FANIN),
    });
}

/// Outbound byte rate, in bytes per second, between two consecutive samples.
fn egress_rate(previous: &MetricSample, current: &MetricSample) -> Option<f64> {
    let seconds = (current.observed_at - previous.observed_at).num_seconds();
    if seconds <= 0 {
        return None;
    }
    // A counter that went backwards means the interface or the host restarted.
    let delta = current.network_tx_bytes.checked_sub(previous.network_tx_bytes)?;
    Some(delta as f64 / seconds as f64)
}

fn egress(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    let history = input.history;
    if history.len() < 3 {
        return;
    }
    let Some(previous) = history.last() else { return };
    let Some(current_rate) = egress_rate(previous, input.sample) else { return };
    if current_rate < policy.intrusion.egress_floor_bytes_per_second {
        return;
    }

    let baseline_rates: Vec<f64> =
        history.windows(2).filter_map(|pair| egress_rate(&pair[0], &pair[1])).collect();
    if baseline_rates.is_empty() {
        return;
    }
    let baseline = baseline_rates.iter().sum::<f64>() / baseline_rates.len() as f64;
    let threshold = (baseline * policy.intrusion.egress_multiplier)
        .max(policy.intrusion.egress_floor_bytes_per_second);
    if current_rate < threshold {
        return;
    }

    let severity = if current_rate >= threshold * 3.0 { Severity::High } else { Severity::Medium };
    let observed_at = input.sample.observed_at;
    findings.push(IncidentCandidate {
        fingerprint: fingerprint(input, RULE_EGRESS, ""),
        asset_id: input.sample.agent_id,
        title: format!("Salida de datos fuera de lo habitual en {}", input.hostname()),
        summary: format!(
            "El tráfico de salida alcanzó {:.1} MB/s frente a una línea base propia de {:.1} MB/s. Un respaldo, una réplica o una sincronización lo explican; una exfiltración también.",
            current_rate / 1_000_000.0,
            baseline / 1_000_000.0
        ),
        severity,
        category: Category::Intrusion,
        root_cause: "El volumen de salida se apartó de la línea base construida con las muestras previas del propio host."
            .to_owned(),
        confidence: 0.55,
        evidence: vec![Evidence::metric(
            "network.egress.bytes_per_second",
            "Tasa de salida frente a su línea base",
            current_rate,
            threshold,
            observed_at,
        )],
        recommended_actions: vec![
            "Identifica el proceso y el destino que concentran la salida antes de cortar nada.".to_owned(),
            "Comprueba si coincide con una ventana de respaldo o replicación programada.".to_owned(),
            "Si el destino no es conocido, contén la salida hacia ese destino y conserva la evidencia.".to_owned(),
        ],
        runbook: vec![],
        techniques: techniques(RULE_EGRESS),
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, Utc};

    use super::*;
    use crate::{
        detect::{DetectionEngine, fixtures},
        security::{AuthEvent, RemotePeer},
    };

    fn failure(address: &str, username: &str, count: u32) -> AuthEvent {
        AuthEvent {
            service: "sshd".to_owned(),
            source_address: address.to_owned(),
            username: Some(username.to_owned()),
            outcome: AuthOutcome::Failure,
            count,
            last_seen: Utc::now(),
        }
    }

    fn success(address: &str, username: &str) -> AuthEvent {
        AuthEvent { outcome: AuthOutcome::Success, count: 1, ..failure(address, username, 1) }
    }

    fn analyze(signals: SecuritySignals) -> Vec<IncidentCandidate> {
        let registration = fixtures::registration("internal");
        let sample = fixtures::sample();
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline)
            .with_security(Some(&signals));
        DetectionEngine::default().analyze(&input)
    }

    fn ids(findings: &[IncidentCandidate]) -> Vec<String> {
        findings
            .iter()
            .map(|finding| finding.fingerprint.split(':').nth(1).unwrap_or_default().to_owned())
            .collect()
    }

    #[test]
    fn a_handful_of_failures_is_not_an_incident() {
        let signals = SecuritySignals {
            auth_events: vec![failure("203.0.113.5", "deploy", 3)],
            ..SecuritySignals::default()
        };
        assert!(analyze(signals).is_empty());
    }

    #[test]
    fn a_burst_from_one_source_is_reported_with_its_address() {
        let signals = SecuritySignals {
            auth_events: vec![failure("203.0.113.5", "root", 45)],
            ..SecuritySignals::default()
        };
        let findings = analyze(signals);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("203.0.113.5"));
        assert!(!findings[0].runbook.is_empty());
    }

    #[test]
    fn a_large_burst_is_critical() {
        let signals = SecuritySignals {
            auth_events: vec![failure("203.0.113.5", "root", 400)],
            ..SecuritySignals::default()
        };
        assert_eq!(analyze(signals)[0].severity, Severity::Critical);
    }

    #[test]
    fn many_usernames_from_one_source_is_a_spray() {
        let signals = SecuritySignals {
            auth_events: (0..6).map(|n| failure("198.51.100.9", &format!("user{n}"), 2)).collect(),
            ..SecuritySignals::default()
        };
        let findings = analyze(signals);
        assert!(ids(&findings).contains(&"intrusion.auth.spray".to_owned()));
    }

    #[test]
    fn a_success_after_a_burst_is_the_worst_case() {
        let signals = SecuritySignals {
            auth_events: vec![failure("203.0.113.5", "admin", 60), success("203.0.113.5", "admin")],
            ..SecuritySignals::default()
        };
        let findings = analyze(signals);
        let success_finding = findings
            .iter()
            .find(|finding| finding.fingerprint.contains("success_after_burst"))
            .expect("the successful login must be reported");
        assert_eq!(success_finding.severity, Severity::Critical);
    }

    #[test]
    fn a_success_without_a_burst_is_not_an_incident() {
        let signals = SecuritySignals {
            auth_events: vec![success("203.0.113.5", "admin")],
            ..SecuritySignals::default()
        };
        assert!(analyze(signals).is_empty());
    }

    #[test]
    fn many_sources_are_reported_as_a_distributed_campaign() {
        let signals = SecuritySignals {
            auth_events: (0..12).map(|n| failure(&format!("203.0.113.{n}"), "root", 4)).collect(),
            ..SecuritySignals::default()
        };
        let findings = analyze(signals);
        assert!(ids(&findings).contains(&"intrusion.auth.distributed".to_owned()));
    }

    #[test]
    fn peer_fanin_is_reported_once_over_the_threshold() {
        let peers = (0..60)
            .map(|n| RemotePeer {
                remote_address: format!("198.51.100.{n}"),
                remote_port: 40000 + n,
                local_port: 22,
                connections: 1,
            })
            .collect();
        let signals = SecuritySignals { peers, ..SecuritySignals::default() };
        let findings = analyze(signals);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn egress_needs_a_baseline_before_it_fires() {
        let registration = fixtures::registration("internal");
        let now = Utc::now();
        let mut history = Vec::new();
        for step in 0..4_u32 {
            let mut previous =
                fixtures::sample_at(now - Duration::seconds(i64::from(60 * (4 - step))));
            previous.network_tx_bytes = 1_000_000 * u64::from(step);
            history.push(previous);
        }
        let mut current = fixtures::sample_at(now);
        current.network_tx_bytes = 20_000_000_000;
        let baseline = BTreeMap::new();
        let input =
            DetectionInput::new(&registration, &current, now, &baseline).with_history(&history);
        let findings = DetectionEngine::default().analyze(&input);
        assert!(findings.iter().any(|finding| finding.fingerprint.contains("egress.anomaly")));
    }

    #[test]
    fn a_counter_reset_does_not_look_like_exfiltration() {
        let previous = fixtures::sample_at(Utc::now() - Duration::seconds(30));
        let mut current = fixtures::sample_at(Utc::now());
        current.network_tx_bytes = 0;
        assert_eq!(egress_rate(&previous, &current), None);
    }

    #[test]
    fn steady_traffic_does_not_trigger_egress() {
        let registration = fixtures::registration("internal");
        let now = Utc::now();
        let history: Vec<_> = (0..4_u32)
            .map(|step| {
                let mut sample =
                    fixtures::sample_at(now - Duration::seconds(i64::from(60 * (4 - step))));
                sample.network_tx_bytes = 2_000_000_000 * u64::from(step);
                sample
            })
            .collect();
        let mut current = fixtures::sample_at(now);
        current.network_tx_bytes = 8_000_000_000;
        let baseline = BTreeMap::new();
        let input =
            DetectionInput::new(&registration, &current, now, &baseline).with_history(&history);
        assert!(DetectionEngine::default().analyze(&input).is_empty());
    }
}
