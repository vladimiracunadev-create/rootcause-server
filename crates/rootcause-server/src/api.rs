//! HTTP contract of the control plane.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use chrono::{Duration, Utc};
use rootcause_core::{
    PROTOCOL_VERSION, RULES,
    detect::DetectionInput,
    models::{
        AssetRegistration, AssetView, AuditEntry, Category, ExposureEntry, ExposureReport,
        HealthResponse, Incident, IncidentStatus, IngestResponse, Severity, StatusResponse,
        TelemetryEnvelope, ThreatReport, TopologyEdge, TopologyNode, TopologySnapshot,
    },
    policy::DetectionPolicy,
    posture, protocol_is_supported,
    runbook::RunbookStep,
    security::{BindScope, SecuritySignals, service_name},
};
use serde::{Deserialize, Serialize};
use tower_http::{
    compression::CompressionLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{auth, error::ApiError, headers, state::AppState, storage::IncidentFilter, ui};

/// Samples of history handed to the detectors on every ingest.
const HISTORY_WINDOW: i64 = 12;
/// Categories whose findings describe a *current* state and may auto-resolve.
const SELF_HEALING: &[Category] = &[Category::Exposure, Category::Hygiene];

pub fn router(state: AppState) -> Router {
    let max_body = state.runtime.max_body_bytes;

    let protected = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/rules", get(rules))
        .route("/api/v1/policy", get(policy))
        .route("/api/v1/assets", get(list_assets))
        .route("/api/v1/assets/register", post(register_asset))
        .route("/api/v1/assets/{id}", get(asset_detail))
        .route("/api/v1/telemetry", post(ingest_telemetry))
        .route("/api/v1/incidents", get(list_incidents))
        .route("/api/v1/incidents/{id}", get(incident_detail))
        .route("/api/v1/incidents/{id}/status", post(change_incident_status))
        .route("/api/v1/incidents/{id}/runbook", get(incident_runbook))
        .route("/api/v1/exposure", get(exposure))
        .route("/api/v1/threats", get(threats))
        .route("/api/v1/topology", get(topology))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/export", get(export))
        .route("/metrics", get(metrics))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::require_auth));

    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .merge(protected)
        .fallback(ui::static_asset)
        .layer(middleware::from_fn(headers::apply))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(30),
        ))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// --------------------------------------------------------------------- health

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        service: "rootcause-server".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    state.database.ping().await.map_err(ApiError::internal)?;
    Ok(Json(HealthResponse {
        status: "ready".to_owned(),
        service: "rootcause-server".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }))
}

// --------------------------------------------------------------------- status

async fn status(State(state): State<AppState>) -> Result<Json<StatusResponse>, ApiError> {
    let counts = state.database.counts().await.map_err(ApiError::internal)?;
    let incidents = state
        .database
        .list_incidents(&IncidentFilter::default())
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(StatusResponse {
        service: "rootcause-server".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        assets_total: counts.assets_total,
        assets_online: counts.assets_online,
        open_incidents: counts.open_incidents,
        critical_incidents: counts.critical_incidents,
        exposed_services: counts.exposed_services,
        blocked_sources: counts.blocked_sources,
        detectors: RULES.len(),
        posture: Some(posture::compute_now(&incidents, None)),
        hardening: state.hardening(),
    }))
}

#[derive(Debug, Serialize)]
struct RuleView {
    id: &'static str,
    category: &'static str,
    category_label: &'static str,
    title: &'static str,
    question: &'static str,
    severity_ceiling: &'static str,
    techniques: Vec<&'static str>,
}

async fn rules() -> Json<Vec<RuleView>> {
    Json(
        RULES
            .iter()
            .map(|rule| RuleView {
                id: rule.id,
                category: rule.category.as_str(),
                category_label: rule.category.label(),
                title: rule.title,
                question: rule.question,
                severity_ceiling: rule.ceiling.as_str(),
                techniques: rule.techniques.to_vec(),
            })
            .collect(),
    )
}

async fn policy(State(state): State<AppState>) -> Json<DetectionPolicy> {
    Json(state.engine.policy().clone())
}

// --------------------------------------------------------------------- assets

async fn register_asset(
    State(state): State<AppState>,
    Json(asset): Json<AssetRegistration>,
) -> Result<StatusCode, ApiError> {
    validate_asset(&asset)?;
    state.database.upsert_asset(&asset).await.map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_assets(State(state): State<AppState>) -> Result<Json<Vec<AssetView>>, ApiError> {
    let mut assets = state.database.list_assets().await.map_err(ApiError::internal)?;
    let incidents = state
        .database
        .list_incidents(&IncidentFilter::default())
        .await
        .map_err(ApiError::internal)?;
    let by_asset = group_incidents(&incidents);
    for asset in &mut assets {
        let own = by_asset.get(&asset.registration.agent_id).cloned().unwrap_or_default();
        asset.posture = Some(posture::compute_now(&own, asset.security.as_ref()));
    }
    Ok(Json(assets))
}

#[derive(Debug, Serialize)]
struct AssetDetail {
    asset: AssetView,
    incidents: Vec<Incident>,
    history: Vec<rootcause_core::models::MetricSample>,
}

async fn asset_detail(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetDetail>, ApiError> {
    let mut assets = state.database.list_assets().await.map_err(ApiError::internal)?;
    let position = assets
        .iter()
        .position(|asset| asset.registration.agent_id == id)
        .ok_or_else(|| ApiError::not_found("no existe un activo con ese identificador"))?;
    let mut asset = assets.swap_remove(position);

    let incidents = state
        .database
        .list_incidents(&IncidentFilter { asset_id: Some(id), ..IncidentFilter::default() })
        .await
        .map_err(ApiError::internal)?;
    asset.posture = Some(posture::compute_now(&incidents, asset.security.as_ref()));
    let history =
        state.database.recent_samples(id, Utc::now(), 120).await.map_err(ApiError::internal)?;

    Ok(Json(AssetDetail { asset, incidents, history }))
}

// ------------------------------------------------------------------ telemetry

async fn ingest_telemetry(
    State(state): State<AppState>,
    Json(envelope): Json<TelemetryEnvelope>,
) -> Result<Json<IngestResponse>, ApiError> {
    if !protocol_is_supported(&envelope.protocol_version) {
        return Err(ApiError::bad_request(format!(
            "versión de protocolo {} no admitida; este servidor habla {}",
            envelope.protocol_version, PROTOCOL_VERSION
        )));
    }
    envelope.sample.validate().map_err(ApiError::bad_request)?;

    let received_at = Utc::now();
    if envelope.sample.observed_at > received_at + Duration::minutes(5)
        || envelope.sample.observed_at < received_at - Duration::hours(24)
    {
        return Err(ApiError::bad_request(
            "la marca de tiempo de la muestra queda fuera de la ventana admitida de 24 horas",
        ));
    }

    let agent_id = envelope.sample.agent_id;
    if let Some(asset) = &envelope.asset {
        validate_asset(asset)?;
        if asset.agent_id != agent_id {
            return Err(ApiError::bad_request(
                "el identificador del activo y el de la muestra no coinciden",
            ));
        }
        state.database.upsert_asset(asset).await.map_err(ApiError::internal)?;
    }

    let registration = state
        .database
        .asset_registration(agent_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("registra el activo antes de enviar telemetría"))?;

    if let Some(security) = &envelope.security {
        validate_security(security)?;
    }

    state.database.store_sample(&envelope.sample).await.map_err(ApiError::internal)?;
    let history = state
        .database
        .recent_samples(agent_id, envelope.sample.observed_at, HISTORY_WINDOW)
        .await
        .map_err(ApiError::internal)?;
    let file_baseline = state.database.file_baseline(agent_id).await.map_err(ApiError::internal)?;

    let mut warnings = Vec::new();
    if let Some(security) = &envelope.security {
        state.database.store_security(agent_id, security).await.map_err(ApiError::internal)?;
        state
            .database
            .record_auth_pressure(agent_id, &security.auth_events)
            .await
            .map_err(ApiError::internal)?;
        for gap in &security.collection_gaps {
            warnings.push(format!("superficie no inspeccionada — {}: {}", gap.surface, gap.reason));
        }
    } else {
        warnings.push(
            "el agente no envió superficie de seguridad; solo se evaluaron los recursos".to_owned(),
        );
    }

    let input = DetectionInput::new(&registration, &envelope.sample, received_at, &file_baseline)
        .with_security(envelope.security.as_ref())
        .with_history(&history);
    let candidates = state.engine.analyze(&input);

    let mut fingerprints = BTreeSet::new();
    let mut incidents_touched = 0;
    for candidate in candidates {
        fingerprints.insert(candidate.fingerprint.clone());
        state
            .database
            .upsert_incident(candidate, envelope.sample.observed_at)
            .await
            .map_err(ApiError::internal)?;
        incidents_touched += 1;
    }

    // Only meaningful once the agent reports the surface those rules read.
    if envelope.security.is_some() {
        state
            .database
            .auto_resolve(agent_id, SELF_HEALING, &fingerprints)
            .await
            .map_err(ApiError::internal)?;
    }
    if let Some(security) = &envelope.security {
        state
            .database
            .update_file_baseline(agent_id, &security.watched_files)
            .await
            .map_err(ApiError::internal)?;
    }

    let own = state
        .database
        .list_incidents(&IncidentFilter { asset_id: Some(agent_id), ..IncidentFilter::default() })
        .await
        .map_err(ApiError::internal)?;
    let score = posture::compute_now(&own, envelope.security.as_ref()).score;
    state.database.store_posture(agent_id, score).await.map_err(ApiError::internal)?;

    Ok(Json(IngestResponse { accepted: true, incidents_touched, warnings }))
}

// ------------------------------------------------------------------ incidents

#[derive(Debug, Deserialize)]
struct IncidentQuery {
    status: Option<String>,
    severity: Option<String>,
    category: Option<String>,
    asset: Option<Uuid>,
    limit: Option<i64>,
}

impl IncidentQuery {
    fn into_filter(self) -> Result<IncidentFilter, ApiError> {
        let status = parse_optional(self.status.as_deref(), IncidentStatus::parse, "status")?;
        let severity = parse_optional(self.severity.as_deref(), Severity::parse, "severity")?;
        let category = parse_optional(self.category.as_deref(), Category::parse, "category")?;
        Ok(IncidentFilter { status, severity, category, asset_id: self.asset, limit: self.limit })
    }
}

fn parse_optional<T>(
    value: Option<&str>,
    parse: impl Fn(&str) -> Option<T>,
    field: &str,
) -> Result<Option<T>, ApiError> {
    match value {
        None => Ok(None),
        Some(raw) => parse(raw)
            .map(Some)
            .ok_or_else(|| ApiError::bad_request(format!("valor inválido para {field}: {raw}"))),
    }
}

async fn list_incidents(
    State(state): State<AppState>,
    Query(query): Query<IncidentQuery>,
) -> Result<Json<Vec<Incident>>, ApiError> {
    let filter = query.into_filter()?;
    state.database.list_incidents(&filter).await.map(Json).map_err(ApiError::internal)
}

async fn incident_detail(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Incident>, ApiError> {
    state
        .database
        .incident(id)
        .await
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no existe un incidente con ese identificador"))
}

async fn incident_runbook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<RunbookStep>>, ApiError> {
    let incident = state
        .database
        .incident(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("no existe un incidente con ese identificador"))?;
    Ok(Json(incident.runbook))
}

#[derive(Debug, Deserialize)]
struct ChangeStatusRequest {
    status: IncidentStatus,
    #[serde(default = "default_actor")]
    actor: String,
}

fn default_actor() -> String {
    "console-user".to_owned()
}

async fn change_incident_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<ChangeStatusRequest>,
) -> Result<Json<Incident>, ApiError> {
    let actor = request.actor.trim();
    if actor.is_empty() || actor.len() > 100 {
        return Err(ApiError::bad_request("el actor debe tener entre 1 y 100 caracteres"));
    }
    state
        .database
        .update_incident_status(id, request.status, actor)
        .await
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no existe un incidente con ese identificador"))
}

// ------------------------------------------------------------------- exposure

/// Build the fleet-wide attack surface from the stored security signals.
pub fn build_exposure(assets: &[AssetView], policy: &DetectionPolicy) -> ExposureReport {
    let mut entries = Vec::new();
    let mut public_services = 0;
    let mut private_services = 0;
    let mut uninspected_assets = Vec::new();

    for asset in assets {
        let Some(security) = &asset.security else {
            uninspected_assets.push(asset.registration.hostname.clone());
            continue;
        };
        if security.listeners.is_empty() && security.has_gap("listeners") {
            uninspected_assets.push(asset.registration.hostname.clone());
        }
        for socket in security.exposed_listeners() {
            match socket.scope {
                BindScope::Public => public_services += 1,
                BindScope::Private => private_services += 1,
                BindScope::Loopback => continue,
            }
            entries.push(ExposureEntry {
                asset_id: asset.registration.agent_id,
                hostname: asset.registration.hostname.clone(),
                platform: asset.registration.platform,
                protocol: socket.protocol.as_str().to_owned(),
                address: socket.address.clone(),
                port: socket.port,
                scope: socket.scope.as_str().to_owned(),
                service: service_name(socket.port),
                class: socket.class().as_str().to_owned(),
                severity: policy.exposure_severity(socket.class(), socket.scope, asset.role),
                process: socket.process.clone(),
                observed_at: asset.last_seen,
            });
        }
    }

    entries.sort_by(|left, right| {
        right
            .severity
            .rank()
            .cmp(&left.severity.rank())
            .then_with(|| left.hostname.cmp(&right.hostname))
            .then_with(|| left.port.cmp(&right.port))
    });

    ExposureReport {
        generated_at: Utc::now(),
        public_services,
        private_services,
        entries,
        uninspected_assets,
    }
}

async fn exposure(State(state): State<AppState>) -> Result<Json<ExposureReport>, ApiError> {
    let assets = state.database.list_assets().await.map_err(ApiError::internal)?;
    Ok(Json(build_exposure(&assets, state.engine.policy())))
}

async fn threats(State(state): State<AppState>) -> Result<Json<ThreatReport>, ApiError> {
    let sources = state.database.threat_sources(100).await.map_err(ApiError::internal)?;
    let total_failures = state.database.total_auth_failures().await.map_err(ApiError::internal)?;
    let control_plane_defense = state
        .database
        .defense_counters()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .map(|(reason, count, last_seen)| rootcause_core::models::DefenseCounter {
            reason,
            count,
            last_seen: Some(last_seen),
        })
        .collect();

    Ok(Json(ThreatReport {
        generated_at: Utc::now(),
        total_failures,
        distinct_sources: sources.len() as u32,
        sources,
        control_plane_defense,
    }))
}

// ------------------------------------------------------------------ topology

/// Build the defence map: what the Internet reaches, and what it does not.
pub fn build_topology(assets: &[AssetView], incidents: &[Incident]) -> TopologySnapshot {
    let risks = worst_risk_by_asset(incidents);
    let open_counts = open_incident_counts(incidents);

    let mut nodes = vec![
        TopologyNode {
            id: "internet".to_owned(),
            label: "Internet".to_owned(),
            kind: "untrusted".to_owned(),
            status: "unknown".to_owned(),
            platform: None,
            risk: None,
            zone: Some("externo".to_owned()),
            exposed_ports: 0,
            open_incidents: 0,
        },
        TopologyNode {
            id: "rootcause-server".to_owned(),
            label: "RootCause Server".to_owned(),
            kind: "control-plane".to_owned(),
            status: "online".to_owned(),
            platform: None,
            risk: None,
            zone: Some("control".to_owned()),
            exposed_ports: 0,
            open_incidents: 0,
        },
    ];
    let mut edges = Vec::new();
    let mut zones = BTreeSet::new();

    for asset in assets {
        let agent_id = asset.registration.agent_id;
        let public_ports = asset
            .security
            .as_ref()
            .map(|security| {
                security.listeners.iter().filter(|socket| socket.scope == BindScope::Public).count()
            })
            .unwrap_or_default() as u32;
        let zone = if public_ports > 0 { "expuesto" } else { "interno" };
        if zones.insert(zone) {
            nodes.push(TopologyNode {
                id: format!("zone:{zone}"),
                label: if zone == "expuesto" {
                    "Superficie expuesta".to_owned()
                } else {
                    "Red interna".to_owned()
                },
                kind: "zone".to_owned(),
                status: "online".to_owned(),
                platform: None,
                risk: None,
                zone: Some(zone.to_owned()),
                exposed_ports: 0,
                open_incidents: 0,
            });
            edges.push(TopologyEdge {
                source: if zone == "expuesto" { "internet" } else { "rootcause-server" }.to_owned(),
                target: format!("zone:{zone}"),
                relation: if zone == "expuesto" { "alcanza" } else { "supervisa" }.to_owned(),
                risk: None,
            });
        }

        let risk = risks.get(&agent_id).copied();
        nodes.push(TopologyNode {
            id: format!("asset:{agent_id}"),
            label: asset.registration.hostname.clone(),
            kind: "endpoint".to_owned(),
            status: asset.status.as_str().to_owned(),
            platform: Some(asset.registration.platform),
            risk,
            zone: Some(zone.to_owned()),
            exposed_ports: public_ports,
            open_incidents: open_counts.get(&agent_id).copied().unwrap_or_default(),
        });
        edges.push(TopologyEdge {
            source: format!("zone:{zone}"),
            target: format!("asset:{agent_id}"),
            relation: "contiene".to_owned(),
            risk,
        });
        edges.push(TopologyEdge {
            source: "rootcause-server".to_owned(),
            target: format!("asset:{agent_id}"),
            relation: "supervisa".to_owned(),
            risk: None,
        });
    }

    TopologySnapshot { generated_at: Utc::now(), nodes, edges }
}

fn worst_risk_by_asset(incidents: &[Incident]) -> HashMap<Uuid, Severity> {
    let mut risks: HashMap<Uuid, Severity> = HashMap::new();
    for incident in incidents.iter().filter(|incident| incident.status != IncidentStatus::Resolved)
    {
        risks
            .entry(incident.asset_id)
            .and_modify(|severity| *severity = (*severity).max(incident.severity))
            .or_insert(incident.severity);
    }
    risks
}

fn open_incident_counts(incidents: &[Incident]) -> HashMap<Uuid, u32> {
    let mut counts: HashMap<Uuid, u32> = HashMap::new();
    for incident in incidents.iter().filter(|incident| incident.status != IncidentStatus::Resolved)
    {
        *counts.entry(incident.asset_id).or_default() += 1;
    }
    counts
}

fn group_incidents(incidents: &[Incident]) -> HashMap<Uuid, Vec<Incident>> {
    let mut grouped: HashMap<Uuid, Vec<Incident>> = HashMap::new();
    for incident in incidents {
        grouped.entry(incident.asset_id).or_default().push(incident.clone());
    }
    grouped
}

async fn topology(State(state): State<AppState>) -> Result<Json<TopologySnapshot>, ApiError> {
    let assets = state.database.list_assets().await.map_err(ApiError::internal)?;
    let incidents = state
        .database
        .list_incidents(&IncidentFilter::default())
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(build_topology(&assets, &incidents)))
}

// --------------------------------------------------------------------- audit

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
}

async fn audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    state
        .database
        .list_audit(query.limit.unwrap_or(200))
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

/// Evidence bundle as newline-delimited JSON, ready for an external archive.
async fn export(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let assets = state.database.list_assets().await.map_err(ApiError::internal)?;
    let incidents = state
        .database
        .list_incidents(&IncidentFilter::default())
        .await
        .map_err(ApiError::internal)?;
    let audit = state.database.list_audit(1_000).await.map_err(ApiError::internal)?;
    let body = render_export(&assets, &incidents, &audit).map_err(ApiError::internal)?;

    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"rootcause-evidencia.ndjson\"",
            ),
        ],
        body,
    ))
}

/// Render the export bundle. One JSON document per line, typed by `kind`.
pub fn render_export(
    assets: &[AssetView],
    incidents: &[Incident],
    audit: &[AuditEntry],
) -> anyhow::Result<String> {
    let mut lines = Vec::with_capacity(assets.len() + incidents.len() + audit.len() + 1);
    lines.push(serde_json::to_string(&serde_json::json!({
        "kind": "export",
        "service": "rootcause-server",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": PROTOCOL_VERSION,
        "generated_at": Utc::now(),
    }))?);
    for asset in assets {
        lines.push(serde_json::to_string(&serde_json::json!({ "kind": "asset", "asset": asset }))?);
    }
    for incident in incidents {
        lines.push(serde_json::to_string(
            &serde_json::json!({ "kind": "incident", "incident": incident }),
        )?);
    }
    for entry in audit {
        lines.push(serde_json::to_string(&serde_json::json!({ "kind": "audit", "audit": entry }))?);
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

// -------------------------------------------------------------------- metrics

/// Prometheus exposition of the numbers an operator alerts on.
pub fn render_metrics(
    counts: &crate::storage::DatabaseCounts,
    posture_score: u8,
    uptime_seconds: u64,
    perimeter: (usize, usize),
    by_category: &BTreeMap<&'static str, u32>,
) -> String {
    let mut out = String::new();
    let mut gauge = |name: &str, help: &str, value: String| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"));
    };
    gauge("rootcause_uptime_seconds", "Segundos desde el arranque.", uptime_seconds.to_string());
    gauge("rootcause_assets_total", "Activos registrados.", counts.assets_total.to_string());
    gauge(
        "rootcause_assets_online",
        "Activos que reportaron hace poco.",
        counts.assets_online.to_string(),
    );
    gauge(
        "rootcause_incidents_open",
        "Incidentes sin resolver.",
        counts.open_incidents.to_string(),
    );
    gauge(
        "rootcause_incidents_critical",
        "Incidentes críticos sin resolver.",
        counts.critical_incidents.to_string(),
    );
    gauge(
        "rootcause_exposed_services",
        "Servicios alcanzables fuera de su host.",
        counts.exposed_services.to_string(),
    );
    gauge(
        "rootcause_blocked_sources",
        "Direcciones bloqueadas por el plano de control.",
        counts.blocked_sources.to_string(),
    );
    gauge(
        "rootcause_posture_score",
        "Puntuación de postura, de 0 a 100.",
        posture_score.to_string(),
    );
    gauge(
        "rootcause_perimeter_locked_sources",
        "Direcciones cumpliendo un bloqueo en este momento.",
        perimeter.0.to_string(),
    );
    gauge(
        "rootcause_perimeter_tracked_clients",
        "Direcciones vigiladas por el perímetro del plano de control.",
        perimeter.1.to_string(),
    );

    out.push_str("# HELP rootcause_incidents_by_category Incidentes abiertos por categoría.\n");
    out.push_str("# TYPE rootcause_incidents_by_category gauge\n");
    for (category, value) in by_category {
        out.push_str(&format!(
            "rootcause_incidents_by_category{{category=\"{category}\"}} {value}\n"
        ));
    }
    out
}

async fn metrics(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let counts = state.database.counts().await.map_err(ApiError::internal)?;
    let incidents = state
        .database
        .list_incidents(&IncidentFilter::default())
        .await
        .map_err(ApiError::internal)?;
    let mut by_category: BTreeMap<&'static str, u32> =
        Category::ALL.iter().map(|category| (category.as_str(), 0)).collect();
    for incident in incidents.iter().filter(|incident| incident.status != IncidentStatus::Resolved)
    {
        *by_category.entry(incident.category.as_str()).or_default() += 1;
    }
    let score = posture::compute_now(&incidents, None).score;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        render_metrics(
            &counts,
            score,
            state.started_at.elapsed().as_secs(),
            (
                state.perimeter.locked_sources(std::time::Instant::now()),
                state.perimeter.tracked_clients(),
            ),
            &by_category,
        ),
    ))
}

// ------------------------------------------------------------------ validation

fn validate_asset(asset: &AssetRegistration) -> Result<(), ApiError> {
    let hostname = asset.hostname.trim();
    if hostname.is_empty() || hostname.len() > 255 {
        return Err(ApiError::bad_request(
            "el nombre de equipo debe tener entre 1 y 255 caracteres",
        ));
    }
    if asset.agent_version.trim().is_empty() || asset.agent_version.len() > 50 {
        return Err(ApiError::bad_request("versión de agente inválida"));
    }
    if asset.architecture.trim().is_empty() || asset.architecture.len() > 50 {
        return Err(ApiError::bad_request("arquitectura inválida"));
    }
    if asset.labels.len() > 32
        || asset.labels.iter().any(|(key, value)| key.len() > 64 || value.len() > 256)
    {
        return Err(ApiError::bad_request(
            "las etiquetas del activo superan los límites admitidos",
        ));
    }
    Ok(())
}

/// Bounds on the security surface, so one agent cannot flood the control plane.
fn validate_security(security: &SecuritySignals) -> Result<(), ApiError> {
    if security.listeners.len() > 1_024 {
        return Err(ApiError::bad_request("demasiados sockets en escucha en un solo envío"));
    }
    if security.peers.len() > 4_096 {
        return Err(ApiError::bad_request("demasiadas conexiones remotas en un solo envío"));
    }
    if security.auth_events.len() > 1_024 {
        return Err(ApiError::bad_request("demasiados eventos de autenticación en un solo envío"));
    }
    if security.watched_files.len() > 512 {
        return Err(ApiError::bad_request("demasiados archivos vigilados en un solo envío"));
    }
    if security.collection_gaps.len() > 64 {
        return Err(ApiError::bad_request("demasiadas brechas de recolección en un solo envío"));
    }
    if security.auth_events.iter().any(|event| {
        event.source_address.len() > 64
            || event.service.len() > 64
            || event.username.as_ref().is_some_and(|name| name.len() > 128)
    }) {
        return Err(ApiError::bad_request(
            "un evento de autenticación supera los límites de campo",
        ));
    }
    if security.watched_files.iter().any(|file| file.path.len() > 512 || file.digest.len() > 128) {
        return Err(ApiError::bad_request("un archivo vigilado supera los límites de campo"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap as Map;

    use rootcause_core::{
        models::{AssetStatus, Platform},
        security::{ListeningSocket, Protocol},
    };

    use super::*;

    fn registration(hostname: &str, role: &str) -> AssetRegistration {
        let mut labels = Map::new();
        labels.insert("role".to_owned(), role.to_owned());
        AssetRegistration {
            agent_id: Uuid::new_v4(),
            hostname: hostname.to_owned(),
            platform: Platform::Linux,
            os_version: None,
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            agent_version: "0.2.0".to_owned(),
            labels,
        }
    }

    fn view(registration: AssetRegistration, security: Option<SecuritySignals>) -> AssetView {
        let role = registration.role();
        AssetView {
            registration,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            status: AssetStatus::Online,
            latest_metrics: None,
            security,
            posture: None,
            role,
        }
    }

    #[test]
    fn asset_validation_rejects_an_empty_hostname() {
        let mut asset = registration(" ", "internal");
        assert!(validate_asset(&asset).is_err());
        asset.hostname = "srv".to_owned();
        assert!(validate_asset(&asset).is_ok());
    }

    #[test]
    fn asset_validation_bounds_the_label_map() {
        let mut asset = registration("srv", "internal");
        for index in 0..40 {
            asset.labels.insert(format!("k{index}"), "v".to_owned());
        }
        assert!(validate_asset(&asset).is_err());
    }

    #[test]
    fn the_security_surface_is_bounded() {
        let signals = SecuritySignals {
            listeners: (0..2_000)
                .map(|n| ListeningSocket::new(Protocol::Tcp, "0.0.0.0", n as u16))
                .collect(),
            ..SecuritySignals::default()
        };
        assert!(validate_security(&signals).is_err());
        assert!(validate_security(&SecuritySignals::default()).is_ok());
    }

    #[test]
    fn exposure_counts_public_and_private_services_apart() {
        let signals = SecuritySignals {
            listeners: vec![
                ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432),
                ListeningSocket::new(Protocol::Tcp, "10.0.0.4", 6379),
                ListeningSocket::new(Protocol::Tcp, "127.0.0.1", 9200),
            ],
            ..SecuritySignals::default()
        };
        let assets = vec![view(registration("srv-db", "database"), Some(signals))];
        let report = build_exposure(&assets, &DetectionPolicy::default());
        assert_eq!(report.public_services, 1);
        assert_eq!(report.private_services, 1);
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].severity, Severity::Critical);
        assert_eq!(report.entries[0].service, "PostgreSQL");
    }

    #[test]
    fn an_asset_without_a_reported_surface_is_listed_as_uninspected() {
        let assets = vec![view(registration("srv-old", "internal"), None)];
        let report = build_exposure(&assets, &DetectionPolicy::default());
        assert_eq!(report.entries.len(), 0);
        assert_eq!(report.uninspected_assets, vec!["srv-old".to_owned()]);
    }

    #[test]
    fn the_topology_separates_the_exposed_zone_from_the_internal_one() {
        let exposed = SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 443)],
            ..SecuritySignals::default()
        };
        let internal = SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "127.0.0.1", 5432)],
            ..SecuritySignals::default()
        };
        let assets = vec![
            view(registration("srv-edge", "edge"), Some(exposed)),
            view(registration("srv-db", "database"), Some(internal)),
        ];
        let snapshot = build_topology(&assets, &[]);

        assert!(snapshot.nodes.iter().any(|node| node.id == "internet"));
        assert!(snapshot.nodes.iter().any(|node| node.id == "zone:expuesto"));
        assert!(snapshot.nodes.iter().any(|node| node.id == "zone:interno"));
        let edge = snapshot.nodes.iter().find(|node| node.label == "srv-edge").unwrap();
        assert_eq!(edge.zone.as_deref(), Some("expuesto"));
        assert_eq!(edge.exposed_ports, 1);
        let database = snapshot.nodes.iter().find(|node| node.label == "srv-db").unwrap();
        assert_eq!(database.zone.as_deref(), Some("interno"));
    }

    #[test]
    fn the_metrics_exposition_is_valid_prometheus_text() {
        let counts = crate::storage::DatabaseCounts {
            assets_total: 3,
            assets_online: 2,
            open_incidents: 4,
            critical_incidents: 1,
            exposed_services: 7,
            blocked_sources: 2,
        };
        let by_category = BTreeMap::from([("exposure", 2_u32), ("intrusion", 1)]);
        let rendered = render_metrics(&counts, 61, 120, (2, 40), &by_category);

        assert!(rendered.contains("# TYPE rootcause_assets_total gauge"));
        assert!(rendered.contains("\nrootcause_assets_total 3\n"));
        assert!(rendered.contains("rootcause_posture_score 61"));
        assert!(rendered.contains("rootcause_perimeter_locked_sources 2"));
        assert!(rendered.contains("rootcause_perimeter_tracked_clients 40"));
        assert!(rendered.contains("rootcause_incidents_by_category{category=\"exposure\"} 2"));
        for line in rendered.lines().filter(|line| !line.starts_with('#') && !line.is_empty()) {
            assert!(line.split_whitespace().count() >= 2, "malformed metric line: {line}");
        }
    }

    #[test]
    fn the_export_bundle_is_newline_delimited_json() {
        let assets = vec![view(registration("srv", "internal"), None)];
        let rendered = render_export(&assets, &[], &[]).unwrap();
        let lines: Vec<&str> = rendered.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let value: serde_json::Value = serde_json::from_str(line).expect("every line is JSON");
            assert!(value.get("kind").is_some());
        }
    }

    #[test]
    fn incident_query_rejects_a_value_it_does_not_understand() {
        let query = IncidentQuery {
            status: Some("cerrado-a-medias".to_owned()),
            severity: None,
            category: None,
            asset: None,
            limit: None,
        };
        assert!(query.into_filter().is_err());
    }

    #[test]
    fn incident_query_accepts_the_published_vocabulary() {
        let query = IncidentQuery {
            status: Some("open".to_owned()),
            severity: Some("critical".to_owned()),
            category: Some("exposure".to_owned()),
            asset: None,
            limit: Some(10),
        };
        let filter = query.into_filter().unwrap();
        assert_eq!(filter.status, Some(IncidentStatus::Open));
        assert_eq!(filter.severity, Some(Severity::Critical));
        assert_eq!(filter.category, Some(Category::Exposure));
    }
}
