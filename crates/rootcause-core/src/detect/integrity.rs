//! Something changed on disk that nobody announced.

use crate::{
    detect::{DetectionInput, fingerprint, techniques},
    models::{Category, Evidence, IncidentCandidate, Severity},
    policy::DetectionPolicy,
    runbook,
    security::WatchedFile,
};

const RULE_CHANGED: &str = "integrity.file.changed";
const RULE_PERMISSIONS: &str = "integrity.file.permissions";

/// Files whose modification changes who can enter the server.
const ACCESS_CRITICAL: &[&str] = &[
    "sshd_config",
    "sudoers",
    "passwd",
    "shadow",
    "group",
    "authorized_keys",
    "pam.d",
    "crontab",
    "hosts.allow",
    "hosts.deny",
];

fn is_access_critical(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    ACCESS_CRITICAL.iter().any(|marker| lowered.contains(marker))
}

pub(super) fn detect(
    _policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    let Some(security) = input.security else { return };
    let platform = input.registration.platform;
    let hostname = input.hostname();
    let observed_at = input.sample.observed_at;

    for file in &security.watched_files {
        if let Some(previous) = input.file_baseline.get(&file.path)
            && previous != &file.digest
        {
            let severity =
                if is_access_critical(&file.path) { Severity::High } else { Severity::Medium };
            findings.push(IncidentCandidate {
                fingerprint: fingerprint(input, RULE_CHANGED, &file.path),
                asset_id: input.sample.agent_id,
                title: format!("{} cambió en {hostname}", file.path),
                summary: format!(
                    "El contenido de {} ya no coincide con la huella observada anteriormente. Un despliegue autorizado explica el cambio; una modificación no anunciada de un archivo que gobierna el acceso, no.",
                    file.path
                ),
                severity,
                category: Category::Integrity,
                root_cause: format!(
                    "La huella SHA-256 de {} pasó de {} a {}.",
                    file.path,
                    short_digest(previous),
                    short_digest(&file.digest)
                ),
                confidence: 0.97,
                evidence: vec![digest_evidence(file, previous, input)],
                recommended_actions: vec![
                    "Comprueba si el cambio corresponde a un despliegue o a una tarea de configuración registrada.".to_owned(),
                    "Si no hay cambio autorizado, conserva el archivo actual como evidencia antes de restaurar.".to_owned(),
                    "Revisa qué cuenta tuvo acceso de escritura en la ventana del cambio.".to_owned(),
                ],
                runbook: runbook::verify_file(platform, &file.path),
                techniques: techniques(RULE_CHANGED),
            });
        }

        if file.is_world_writable() {
            findings.push(IncidentCandidate {
                fingerprint: fingerprint(input, RULE_PERMISSIONS, &file.path),
                asset_id: input.sample.agent_id,
                title: format!("{} es escribible por cualquier usuario en {hostname}", file.path),
                summary: format!(
                    "Los permisos de {} permiten escritura a usuarios fuera de su propietario y grupo. Cualquier cuenta local, incluida la de un servicio comprometido, puede reescribirlo.",
                    file.path
                ),
                severity: Severity::High,
                category: Category::Integrity,
                root_cause: format!(
                    "El archivo tiene modo {:o}, con el bit de escritura para otros activo.",
                    file.mode.unwrap_or_default()
                ),
                confidence: 0.99,
                evidence: vec![Evidence::fact(
                    "file.mode",
                    format!("Permisos de {}", file.path),
                    format!("{:o}", file.mode.unwrap_or_default()),
                    observed_at,
                )],
                recommended_actions: vec![
                    "Devuelve el archivo a permisos mínimos para su propietario.".to_owned(),
                    "Revisa qué proceso o script relajó los permisos y corrígelo en su origen.".to_owned(),
                ],
                runbook: runbook::verify_file(platform, &file.path),
                techniques: techniques(RULE_PERMISSIONS),
            });
        }
    }
}

fn digest_evidence(file: &WatchedFile, previous: &str, input: &DetectionInput<'_>) -> Evidence {
    Evidence::fact(
        "file.digest.changed",
        format!("Huella SHA-256 de {}", file.path),
        format!(
            "anterior {} → actual {} ({} bytes)",
            short_digest(previous),
            short_digest(&file.digest),
            file.size_bytes
        ),
        file.modified_at.unwrap_or(input.sample.observed_at),
    )
}

fn short_digest(digest: &str) -> String {
    digest.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        detect::{DetectionEngine, fixtures},
        security::SecuritySignals,
    };

    fn watched(path: &str, digest: &str, mode: Option<u32>) -> WatchedFile {
        WatchedFile {
            path: path.to_owned(),
            digest: digest.to_owned(),
            size_bytes: 4096,
            modified_at: None,
            mode,
        }
    }

    fn analyze(
        files: Vec<WatchedFile>,
        baseline: BTreeMap<String, String>,
    ) -> Vec<IncidentCandidate> {
        let registration = fixtures::registration("internal");
        let sample = fixtures::sample();
        let signals = SecuritySignals { watched_files: files, ..SecuritySignals::default() };
        let input = DetectionInput::new(&registration, &sample, sample.observed_at, &baseline)
            .with_security(Some(&signals));
        DetectionEngine::default().analyze(&input)
    }

    #[test]
    fn the_first_observation_only_establishes_the_baseline() {
        let findings =
            analyze(vec![watched("/etc/ssh/sshd_config", "aaaa", Some(0o600))], BTreeMap::new());
        assert!(findings.is_empty());
    }

    #[test]
    fn an_unchanged_file_is_silent() {
        let mut baseline = BTreeMap::new();
        baseline.insert("/etc/ssh/sshd_config".to_owned(), "aaaa".to_owned());
        let findings =
            analyze(vec![watched("/etc/ssh/sshd_config", "aaaa", Some(0o600))], baseline);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_changed_access_file_is_high_and_shows_both_digests() {
        let mut baseline = BTreeMap::new();
        baseline.insert("/etc/ssh/sshd_config".to_owned(), "aaaabbbbccccdddd".to_owned());
        let findings = analyze(
            vec![watched("/etc/ssh/sshd_config", "1111222233334444", Some(0o600))],
            baseline,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        let detail = findings[0].evidence[0].detail.as_deref().unwrap();
        assert!(detail.contains("aaaabbbbcccc"));
        assert!(detail.contains("111122223333"));
    }

    #[test]
    fn a_changed_ordinary_file_is_medium() {
        let mut baseline = BTreeMap::new();
        baseline.insert("/etc/nginx/nginx.conf".to_owned(), "aaaa".to_owned());
        let findings =
            analyze(vec![watched("/etc/nginx/nginx.conf", "bbbb", Some(0o644))], baseline);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn world_writable_permissions_are_reported_on_their_own() {
        let findings = analyze(vec![watched("/etc/sudoers", "aaaa", Some(0o666))], BTreeMap::new());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fingerprint.contains("integrity.file.permissions"));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn windows_paths_are_recognised_as_access_critical() {
        assert!(is_access_critical(r"C:\ProgramData\ssh\sshd_config"));
        assert!(!is_access_critical(r"C:\inetpub\wwwroot\web.config"));
    }
}
