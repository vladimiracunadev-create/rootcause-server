//! What of this server can be reached from somewhere else.

use crate::{
    detect::{DetectionInput, fingerprint, techniques},
    models::{Category, Evidence, IncidentCandidate, Severity},
    policy::DetectionPolicy,
    runbook,
    security::{BindScope, ListeningSocket, PortClass, service_name},
};

const RULE_PUBLIC: &str = "exposure.service.public";
const RULE_CLEARTEXT: &str = "exposure.cleartext.protocol";

pub(super) fn detect(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    let Some(security) = input.security else { return };
    let role = input.registration.role();
    let platform = input.registration.platform;
    let hostname = input.hostname();

    for socket in security.exposed_listeners() {
        if socket.scope == BindScope::Public && policy.is_allowed_public(socket.port, role) {
            continue;
        }
        let class = socket.class();
        let severity = policy.exposure_severity(class, socket.scope, role);
        if severity == Severity::Info {
            continue;
        }
        let service = service_name(socket.port);
        let rule_id = if class == PortClass::Cleartext { RULE_CLEARTEXT } else { RULE_PUBLIC };

        findings.push(IncidentCandidate {
            fingerprint: fingerprint(
                input,
                rule_id,
                &format!("{}/{}", socket.protocol.as_str(), socket.port),
            ),
            asset_id: input.sample.agent_id,
            title: title_for(rule_id, &service, hostname),
            summary: summary_for(rule_id, &service, socket),
            severity,
            category: Category::Exposure,
            root_cause: root_cause_for(rule_id, &service, socket),
            confidence: 0.99,
            evidence: vec![evidence_for(socket, &service, input)],
            recommended_actions: actions_for(rule_id, &service, socket.port),
            runbook: runbook::restrict_listener(platform, socket.port, &service),
            techniques: techniques(rule_id),
        });
    }
}

fn title_for(rule_id: &str, service: &str, hostname: &str) -> String {
    if rule_id == RULE_CLEARTEXT {
        format!("{service} publica credenciales sin cifrar en {hostname}")
    } else {
        format!("{service} alcanzable fuera de {hostname}")
    }
}

fn summary_for(rule_id: &str, service: &str, socket: &ListeningSocket) -> String {
    let reach = match socket.scope {
        BindScope::Public => "desde cualquier interfaz, incluidas las públicas",
        BindScope::Private => "desde toda la red interna",
        BindScope::Loopback => "solo desde el propio host",
    };
    let process = socket
        .process
        .as_deref()
        .map(|name| format!(" El proceso responsable es {name}."))
        .unwrap_or_default();
    if rule_id == RULE_CLEARTEXT {
        format!(
            "{service} escucha en {} y es alcanzable {reach}. El protocolo transporta credenciales legibles: quien observe la red las obtiene sin explotar ninguna vulnerabilidad.{process}",
            socket.endpoint()
        )
    } else {
        format!(
            "{service} escucha en {} y es alcanzable {reach}. Cada servicio alcanzable es una puerta que alguien puede tocar sin autenticarse todavía.{process}",
            socket.endpoint()
        )
    }
}

fn root_cause_for(rule_id: &str, service: &str, socket: &ListeningSocket) -> String {
    if rule_id == RULE_CLEARTEXT {
        format!(
            "{service} está configurado sobre un protocolo sin cifrado y expuesto en {}.",
            socket.endpoint()
        )
    } else {
        format!(
            "El servicio está enlazado a {} en lugar de restringirse a la interfaz mínima necesaria.",
            socket.address
        )
    }
}

fn evidence_for(socket: &ListeningSocket, service: &str, input: &DetectionInput<'_>) -> Evidence {
    let detail = match (&socket.process, socket.pid) {
        (Some(process), Some(pid)) => format!("{process} (pid {pid})"),
        (Some(process), None) => process.clone(),
        _ => "proceso no identificado por el agente".to_owned(),
    };
    Evidence::fact(
        "network.listener",
        format!(
            "{}/{} · {} · alcance {}",
            socket.protocol.as_str(),
            socket.port,
            service,
            socket.scope.as_str()
        ),
        format!("{} → {detail}", socket.endpoint()),
        input.sample.observed_at,
    )
}

fn actions_for(rule_id: &str, service: &str, port: u16) -> Vec<String> {
    let mut actions = vec![
        format!(
            "Confirma si {service} debe ser alcanzable desde fuera del host o si quedó publicado por omisión."
        ),
        format!(
            "Si debe seguir publicado, restringe el origen permitido y exige autenticación antes de aceptar tráfico en el puerto {port}."
        ),
    ];
    if rule_id == RULE_CLEARTEXT {
        actions.push(format!(
            "Sustituye {service} por su equivalente cifrado y desactiva el puerto {port} cuando la migración esté verificada."
        ));
    } else {
        actions.push(
            "Vuelve a enlazar el servicio a 127.0.0.1 o a la interfaz interna y verifica desde fuera que dejó de responder."
                .to_owned(),
        );
    }
    actions
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        detect::{DetectionEngine, fixtures},
        security::{Protocol, SecuritySignals},
    };

    fn analyze(listeners: Vec<ListeningSocket>, role: &str) -> Vec<IncidentCandidate> {
        let registration = fixtures::registration(role);
        let sample = fixtures::sample();
        let signals = SecuritySignals { listeners, ..SecuritySignals::default() };
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline)
            .with_security(Some(&signals));
        DetectionEngine::default().analyze(&input)
    }

    #[test]
    fn a_loopback_database_is_not_a_finding() {
        let findings =
            analyze(vec![ListeningSocket::new(Protocol::Tcp, "127.0.0.1", 5432)], "internal");
        assert!(findings.is_empty());
    }

    #[test]
    fn a_public_database_is_critical_and_names_the_service() {
        let findings =
            analyze(vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432)], "internal");
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.category, Category::Exposure);
        assert!(finding.title.contains("PostgreSQL"));
        assert!(finding.fingerprint.ends_with("exposure.service.public:tcp/5432"));
        assert!(finding.techniques.contains(&"T1190".to_owned()));
    }

    #[test]
    fn an_edge_server_may_publish_https_but_not_ssh() {
        let findings = analyze(
            vec![
                ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 443),
                ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 22),
            ],
            "edge",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SSH"));
    }

    #[test]
    fn cleartext_protocols_get_their_own_rule() {
        let findings =
            analyze(vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 23)], "internal");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fingerprint.contains("exposure.cleartext.protocol"));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn private_scope_lowers_but_does_not_erase_the_finding() {
        let findings =
            analyze(vec![ListeningSocket::new(Protocol::Tcp, "10.0.0.5", 6379)], "internal");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn the_process_behind_the_port_reaches_the_evidence() {
        let socket = ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 27017)
            .with_process(Some("mongod".to_owned()), Some(1234));
        let findings = analyze(vec![socket], "internal");
        let detail = findings[0].evidence[0].detail.as_deref().unwrap();
        assert!(detail.contains("mongod"));
        assert!(detail.contains("1234"));
    }

    #[test]
    fn every_exposure_finding_carries_a_runbook() {
        let findings =
            analyze(vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 3389)], "internal");
        assert!(!findings[0].runbook.is_empty());
        assert!(!findings[0].recommended_actions.is_empty());
    }

    #[test]
    fn dual_stack_bindings_of_one_service_are_a_single_finding() {
        let findings = analyze(
            vec![
                ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432),
                ListeningSocket::new(Protocol::Tcp, "::", 5432),
            ],
            "internal",
        );
        assert_eq!(findings.len(), 1, "one service is one finding, not one per address family");
        assert_eq!(findings[0].evidence.len(), 2, "both bindings stay in the evidence");
    }

    #[test]
    fn a_database_server_exposing_anything_public_is_critical() {
        let findings =
            analyze(vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 8080)], "database");
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
