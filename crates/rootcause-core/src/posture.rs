//! One number for "how defended is this", and the honesty that must go with it.
//!
//! A posture score is a summary, not a proof. Every score therefore travels
//! with the list of surfaces that could not be inspected, so a high number on
//! an uninspected server never reads as a clean bill of health.

use chrono::{DateTime, Utc};

use crate::{
    models::{Category, Incident, IncidentStatus, PostureDimension, PostureScore, Severity},
    security::SecuritySignals,
};

/// Points removed from a dimension for one open finding.
const fn weight(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => 45,
        Severity::High => 25,
        Severity::Medium => 10,
        Severity::Low => 4,
        Severity::Info => 0,
    }
}

/// Relative importance of each dimension in the overall score.
const fn dimension_weight(category: Category) -> u32 {
    match category {
        Category::Intrusion | Category::Exposure => 5,
        Category::Integrity | Category::Availability => 3,
        Category::Hygiene => 2,
        Category::Resource => 1,
    }
}

fn grade(score: u8) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

fn dimension_summary(category: Category, findings: u32, worst: Option<Severity>) -> String {
    match (findings, worst) {
        (0, _) => format!("Sin hallazgos abiertos de {}.", category.label().to_lowercase()),
        (count, Some(severity)) => format!(
            "{count} hallazgo(s) abierto(s); el peor es de severidad {}.",
            severity.label().to_lowercase()
        ),
        (count, None) => format!("{count} hallazgo(s) abierto(s)."),
    }
}

/// Compute a posture score from the open incidents of a scope.
///
/// `signals` is optional and only contributes the honesty list: what the agent
/// could not inspect during its last cycle.
pub fn compute(
    incidents: &[Incident],
    signals: Option<&SecuritySignals>,
    computed_at: DateTime<Utc>,
) -> PostureScore {
    let open: Vec<&Incident> =
        incidents.iter().filter(|incident| incident.status != IncidentStatus::Resolved).collect();

    let mut dimensions = Vec::with_capacity(Category::ALL.len());
    let mut weighted_total = 0_u32;
    let mut weight_sum = 0_u32;

    for category in Category::ALL {
        let matching: Vec<&&Incident> =
            open.iter().filter(|incident| incident.category == category).collect();
        let penalty: u32 = matching.iter().map(|incident| weight(incident.severity)).sum();
        let score = 100_u32.saturating_sub(penalty).min(100) as u8;
        let worst = matching.iter().map(|incident| incident.severity).max();
        let findings = matching.len() as u32;

        weighted_total += u32::from(score) * dimension_weight(category);
        weight_sum += dimension_weight(category);
        dimensions.push(PostureDimension {
            category,
            score,
            findings,
            summary: dimension_summary(category, findings, worst),
        });
    }

    let average = weighted_total.checked_div(weight_sum).unwrap_or(100) as u8;
    // A weighted average dilutes a single emergency across six dimensions. The
    // worst open finding therefore scales the headline number down, so a server
    // with an exposed database cannot be graded "B" because everything else is
    // in order — while still ranking worse when more dimensions are affected.
    let ceiling =
        open.iter().map(|incident| incident.severity).max().map_or(100_u32, |worst| match worst {
            Severity::Critical => 55,
            Severity::High => 74,
            Severity::Medium => 89,
            Severity::Low | Severity::Info => 100,
        });
    let score = (u32::from(average) * ceiling / 100) as u8;
    let uninspected_surfaces = signals
        .map(|signals| {
            signals
                .collection_gaps
                .iter()
                .map(|gap| format!("{}: {}", gap.surface, gap.reason))
                .collect()
        })
        .unwrap_or_default();

    PostureScore {
        score,
        grade: grade(score).to_owned(),
        dimensions,
        uninspected_surfaces,
        computed_at,
    }
}

/// Convenience wrapper that timestamps the score with the current instant.
pub fn compute_now(incidents: &[Incident], signals: Option<&SecuritySignals>) -> PostureScore {
    compute(incidents, signals, Utc::now())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::security::CollectionGap;

    fn incident(category: Category, severity: Severity, status: IncidentStatus) -> Incident {
        let now = Utc::now();
        Incident {
            id: Uuid::new_v4(),
            fingerprint: format!("{}-{}", category.as_str(), severity.as_str()),
            asset_id: Uuid::nil(),
            title: "t".to_owned(),
            summary: "s".to_owned(),
            severity,
            category,
            status,
            root_cause: "r".to_owned(),
            confidence: 0.9,
            first_seen: now,
            last_seen: now,
            occurrences: 1,
            evidence: vec![],
            recommended_actions: vec![],
            runbook: vec![],
            techniques: vec![],
        }
    }

    #[test]
    fn a_clean_fleet_scores_one_hundred() {
        let posture = compute_now(&[], None);
        assert_eq!(posture.score, 100);
        assert_eq!(posture.grade, "A");
        assert_eq!(posture.dimensions.len(), Category::ALL.len());
    }

    #[test]
    fn resolved_incidents_do_not_count() {
        let incidents =
            vec![incident(Category::Intrusion, Severity::Critical, IncidentStatus::Resolved)];
        assert_eq!(compute_now(&incidents, None).score, 100);
    }

    #[test]
    fn one_critical_finding_caps_the_headline_score() {
        let incidents =
            vec![incident(Category::Exposure, Severity::Critical, IncidentStatus::Open)];
        let posture = compute_now(&incidents, None);
        assert!(posture.score <= 55, "a critical finding must not be diluted: {}", posture.score);
        assert_eq!(posture.grade, "F");
    }

    #[test]
    fn one_high_finding_caps_the_score_below_a_passing_grade() {
        let incidents = vec![incident(Category::Hygiene, Severity::High, IncidentStatus::Open)];
        assert!(compute_now(&incidents, None).score <= 74);
    }

    #[test]
    fn a_critical_intrusion_hurts_more_than_a_critical_resource_finding() {
        let intrusion =
            vec![incident(Category::Intrusion, Severity::Critical, IncidentStatus::Open)];
        let resource = vec![incident(Category::Resource, Severity::Critical, IncidentStatus::Open)];
        assert!(compute_now(&intrusion, None).score < compute_now(&resource, None).score);
    }

    #[test]
    fn the_worst_severity_reaches_the_dimension_summary() {
        let incidents = vec![
            incident(Category::Exposure, Severity::Medium, IncidentStatus::Open),
            incident(Category::Exposure, Severity::Critical, IncidentStatus::Open),
        ];
        let posture = compute_now(&incidents, None);
        let exposure = posture
            .dimensions
            .iter()
            .find(|dimension| dimension.category == Category::Exposure)
            .unwrap();
        assert_eq!(exposure.findings, 2);
        assert!(exposure.summary.contains("crítico"));
    }

    #[test]
    fn a_dimension_never_goes_below_zero() {
        let incidents: Vec<_> = (0..10)
            .map(|_| incident(Category::Exposure, Severity::Critical, IncidentStatus::Open))
            .collect();
        let posture = compute_now(&incidents, None);
        let exposure = posture
            .dimensions
            .iter()
            .find(|dimension| dimension.category == Category::Exposure)
            .unwrap();
        assert_eq!(exposure.score, 0);
        assert_eq!(posture.grade, "F");
    }

    #[test]
    fn collection_gaps_travel_with_the_score() {
        let signals = SecuritySignals {
            collection_gaps: vec![CollectionGap::new(
                "auth-events",
                "el agente no tiene permiso de lectura sobre el registro de autenticación",
            )],
            ..SecuritySignals::default()
        };
        let posture = compute_now(&[], Some(&signals));
        assert_eq!(posture.score, 100);
        assert_eq!(posture.uninspected_surfaces.len(), 1);
        assert!(posture.uninspected_surfaces[0].starts_with("auth-events"));
    }

    #[test]
    fn grades_follow_the_published_bands() {
        assert_eq!(grade(100), "A");
        assert_eq!(grade(90), "A");
        assert_eq!(grade(89), "B");
        assert_eq!(grade(70), "C");
        assert_eq!(grade(60), "D");
        assert_eq!(grade(59), "F");
    }
}
