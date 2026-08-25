//! Saturation that ends in an outage — or that is the visible side of an abuse.

use crate::{
    detect::{DetectionInput, fingerprint, techniques},
    models::{Category, Evidence, IncidentCandidate, MetricSample, Severity},
    policy::DetectionPolicy,
};

const RULE_CPU: &str = "resource.cpu.saturation";
const RULE_MEMORY: &str = "resource.memory.pressure";
const RULE_DISK: &str = "resource.disk.capacity";
const RULE_RUNWAY: &str = "resource.disk.runway";

pub(super) fn detect(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    disk(policy, input, findings);
    runway(policy, input, findings);
    memory(policy, input, findings);
    cpu(policy, input, findings);
}

fn disk(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    let used = input.sample.disk_percent;
    if used < policy.resource.disk_high {
        return;
    }
    let severity =
        if used >= policy.resource.disk_critical { Severity::Critical } else { Severity::High };
    findings.push(IncidentCandidate {
        fingerprint: fingerprint(input, RULE_DISK, ""),
        asset_id: input.sample.agent_id,
        title: format!("Capacidad de disco al límite en {}", input.hostname()),
        summary: format!(
            "El disco alcanzó {used:.1}% de uso. Cuando se agota, el servidor deja de escribir sus propios registros: se queda ciego justo cuando hace falta ver."
        ),
        severity,
        category: Category::Resource,
        root_cause: "El uso de disco superó el umbral de seguridad configurado.".to_owned(),
        confidence: 0.96,
        evidence: vec![Evidence::metric(
            "metric.disk.used_percent",
            "Uso de disco frente al umbral",
            f64::from(used),
            f64::from(policy.resource.disk_high),
            input.sample.observed_at,
        )],
        recommended_actions: vec![
            "Identifica los directorios que concentran el crecimiento antes de borrar nada.".to_owned(),
            "Revisa la rotación de registros y la retención de temporales.".to_owned(),
            "Amplía la capacidad si el crecimiento corresponde a uso esperado.".to_owned(),
        ],
        runbook: vec![],
        techniques: techniques(RULE_DISK),
    });
}

/// Hours until the disk fills at the growth rate of the observed window.
fn hours_to_full(history: &[MetricSample], current: &MetricSample) -> Option<f64> {
    let first = history.first()?;
    let elapsed_hours = (current.observed_at - first.observed_at).num_seconds() as f64 / 3600.0;
    if elapsed_hours <= 0.0 {
        return None;
    }
    let growth = f64::from(current.disk_percent - first.disk_percent);
    if growth <= 0.0 {
        return None;
    }
    let remaining = 100.0 - f64::from(current.disk_percent);
    if remaining <= 0.0 {
        return Some(0.0);
    }
    Some(remaining / (growth / elapsed_hours))
}

fn runway(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    if input.history.len() < 3 {
        return;
    }
    let Some(hours) = hours_to_full(input.history, input.sample) else { return };
    if hours > policy.resource.disk_runway_hours {
        return;
    }
    // Already reported by the capacity rule with its own evidence.
    if input.sample.disk_percent >= policy.resource.disk_critical {
        return;
    }
    let severity = if hours <= policy.resource.disk_runway_hours / 4.0 {
        Severity::High
    } else {
        Severity::Medium
    };
    findings.push(IncidentCandidate {
        fingerprint: fingerprint(input, RULE_RUNWAY, ""),
        asset_id: input.sample.agent_id,
        title: format!("El disco de {} se llena en unas {hours:.0} horas", input.hostname()),
        summary: format!(
            "Al ritmo de crecimiento de las últimas muestras, el disco pasa de {:.1}% a lleno en unas {hours:.0} horas. Esto se corrige con calma ahora o con el servicio caído después.",
            input.sample.disk_percent
        ),
        severity,
        category: Category::Resource,
        root_cause:
            "El crecimiento sostenido del disco proyecta el agotamiento dentro de la ventana de alerta."
                .to_owned(),
        confidence: 0.75,
        evidence: vec![Evidence::metric(
            "metric.disk.hours_to_full",
            "Horas proyectadas hasta agotar el disco",
            hours,
            policy.resource.disk_runway_hours,
            input.sample.observed_at,
        )],
        recommended_actions: vec![
            "Busca qué empezó a escribir más que antes: un registro sin rotación, un volcado o una réplica.".to_owned(),
            "Un crecimiento repentino sin cambio de carga también aparece cuando alguien deja datos en el servidor.".to_owned(),
        ],
        runbook: vec![],
        techniques: techniques(RULE_RUNWAY),
    });
}

fn memory(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    let used = input.sample.memory_percent;
    if used < policy.resource.memory_high {
        return;
    }
    let severity =
        if used >= policy.resource.memory_critical { Severity::Critical } else { Severity::High };
    findings.push(IncidentCandidate {
        fingerprint: fingerprint(input, RULE_MEMORY, ""),
        asset_id: input.sample.agent_id,
        title: format!("Presión de memoria en {}", input.hostname()),
        summary: format!(
            "La memoria en uso alcanzó {used:.1}%. A partir de aquí aparecen paginación, latencia y procesos terminados por el sistema sin previo aviso."
        ),
        severity,
        category: Category::Resource,
        root_cause: "La demanda sostenida de memoria superó el umbral de capacidad configurado."
            .to_owned(),
        confidence: 0.84,
        evidence: vec![Evidence::metric(
            "metric.memory.used_percent",
            "Uso de memoria frente al umbral",
            f64::from(used),
            f64::from(policy.resource.memory_high),
            input.sample.observed_at,
        )],
        recommended_actions: vec![
            "Revisa los procesos con mayor consumo y los cambios de carga recientes.".to_owned(),
            "Comprueba si hubo paginación o terminaciones por falta de memoria.".to_owned(),
            "Reinicia un servicio solo después de conservar la evidencia del diagnóstico.".to_owned(),
        ],
        runbook: vec![],
        techniques: techniques(RULE_MEMORY),
    });
}

/// Consecutive samples at the end of the window that were already saturated.
fn sustained_samples(history: &[MetricSample], threshold: f32) -> usize {
    history.iter().rev().take_while(|sample| sample.cpu_percent >= threshold).count()
}

fn cpu(
    policy: &DetectionPolicy,
    input: &DetectionInput<'_>,
    findings: &mut Vec<IncidentCandidate>,
) {
    let used = input.sample.cpu_percent;
    if used < policy.resource.cpu_high {
        return;
    }
    let streak = sustained_samples(input.history, policy.resource.cpu_high) + 1;
    let required = policy.resource.cpu_sustained_samples;
    // One spike is not saturation. Reporting it as such is how a console
    // teaches its operators to ignore it.
    if streak < required {
        return;
    }
    let severity =
        if used >= policy.resource.cpu_critical { Severity::Critical } else { Severity::High };
    let confidence = if streak >= required * 2 { 0.92 } else { 0.78 };

    findings.push(IncidentCandidate {
        fingerprint: fingerprint(input, RULE_CPU, ""),
        asset_id: input.sample.agent_id,
        title: format!("Saturación sostenida de CPU en {}", input.hostname()),
        summary: format!(
            "La CPU lleva {streak} muestra(s) consecutivas por encima de {:.0}%, la última en {used:.1}%. Sostenido y sin cambio de carga que lo explique, este es el patrón de un proceso que no debería estar ahí.",
            policy.resource.cpu_high
        ),
        severity,
        category: Category::Resource,
        root_cause: "La demanda de cómputo se mantuvo por encima del umbral durante toda la ventana observada."
            .to_owned(),
        confidence,
        evidence: vec![
            Evidence::metric(
                "metric.cpu.used_percent",
                "Uso de CPU frente al umbral",
                f64::from(used),
                f64::from(policy.resource.cpu_high),
                input.sample.observed_at,
            ),
            Evidence::metric(
                "metric.cpu.sustained_samples",
                "Muestras consecutivas saturadas",
                streak as f64,
                required as f64,
                input.sample.observed_at,
            ),
        ],
        recommended_actions: vec![
            "Correlaciona la saturación con procesos, despliegues y tareas programadas.".to_owned(),
            "Compara el consumo con el de un día normal antes de terminar ningún proceso.".to_owned(),
            "Descarta minería o compresión masiva revisando qué binario sostiene el consumo.".to_owned(),
        ],
        runbook: vec![],
        techniques: techniques(RULE_CPU),
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, Utc};

    use super::*;
    use crate::detect::{DetectionEngine, fixtures};

    fn analyze(current: MetricSample, history: &[MetricSample]) -> Vec<IncidentCandidate> {
        let registration = fixtures::registration("internal");
        let baseline = BTreeMap::new();
        let input = DetectionInput::new(&registration, &current, current.observed_at, &baseline)
            .with_history(history);
        DetectionEngine::default().analyze(&input)
    }

    fn cpu_sample(percent: f32, seconds_ago: i64) -> MetricSample {
        let mut sample = fixtures::sample_at(Utc::now() - Duration::seconds(seconds_ago));
        sample.cpu_percent = percent;
        sample
    }

    #[test]
    fn a_single_cpu_spike_is_not_reported() {
        let findings = analyze(cpu_sample(99.0, 0), &[cpu_sample(20.0, 60)]);
        assert!(findings.is_empty());
    }

    #[test]
    fn sustained_cpu_saturation_is_reported_with_its_streak() {
        let history = [cpu_sample(94.0, 120), cpu_sample(96.0, 60)];
        let findings = analyze(cpu_sample(99.0, 0), &history);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].evidence[1].observed_value, Some(3.0));
    }

    #[test]
    fn an_interrupted_streak_restarts_the_count() {
        let history = [cpu_sample(95.0, 180), cpu_sample(10.0, 120), cpu_sample(95.0, 60)];
        assert!(analyze(cpu_sample(95.0, 0), &history).is_empty());
    }

    #[test]
    fn a_full_disk_is_critical() {
        let mut sample = fixtures::sample();
        sample.disk_percent = 97.0;
        let findings = analyze(sample, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].fingerprint.ends_with("resource.disk.capacity"));
    }

    #[test]
    fn memory_pressure_is_reported_before_it_becomes_an_outage() {
        let mut sample = fixtures::sample();
        sample.memory_percent = 90.0;
        let findings = analyze(sample, &[]);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn a_filling_disk_is_projected_before_it_is_full() {
        let now = Utc::now();
        let history: Vec<_> = (0..4_u32)
            .map(|step| {
                let mut sample =
                    fixtures::sample_at(now - Duration::seconds(i64::from(3600 * (4 - step))));
                sample.disk_percent = 40.0 + f32::from(step as u16) * 6.0;
                sample
            })
            .collect();
        let mut current = fixtures::sample_at(now);
        current.disk_percent = 70.0;
        let findings = analyze(current, &history);
        let runway = findings
            .iter()
            .find(|finding| finding.fingerprint.ends_with("resource.disk.runway"))
            .expect("a disk filling at this rate must be projected");
        assert!(runway.evidence[0].observed_value.unwrap() < 48.0);
    }

    #[test]
    fn a_stable_disk_is_not_projected() {
        let now = Utc::now();
        let history: Vec<_> = (0..4_u32)
            .map(|step| fixtures::sample_at(now - Duration::seconds(i64::from(3600 * (4 - step)))))
            .collect();
        let findings = analyze(fixtures::sample_at(now), &history);
        assert!(findings.is_empty());
    }

    #[test]
    fn runway_is_not_duplicated_once_the_disk_is_already_critical() {
        let now = Utc::now();
        let history: Vec<_> = (0..4_u32)
            .map(|step| {
                let mut sample =
                    fixtures::sample_at(now - Duration::seconds(i64::from(3600 * (4 - step))));
                sample.disk_percent = 80.0 + f32::from(step as u16) * 4.0;
                sample
            })
            .collect();
        let mut current = fixtures::sample_at(now);
        current.disk_percent = 96.0;
        let findings = analyze(current, &history);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fingerprint.ends_with("resource.disk.capacity"));
    }
}
