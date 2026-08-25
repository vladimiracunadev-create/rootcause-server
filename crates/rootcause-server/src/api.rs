use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    routing::{get, post},
};
use chrono::{Duration, Utc};
use rootcause_core::{
    AssetRegistration, HealthResponse, Incident, IncidentStatus, IngestResponse, Platform,
    PROTOCOL_VERSION, Severity, StatusResponse, TelemetryEnvelope, TopologyEdge, TopologyNode,
    TopologySnapshot,
};
use serde::Deserialize;
use tower_http::{
    compression::CompressionLayer,
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{auth, error::ApiError, state::AppState, ui};

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/assets", get(list_assets))
        .route("/api/v1/assets/register", post(register_asset))
        .route("/api/v1/telemetry", post(ingest_telemetry))
        .route("/api/v1/incidents", get(list_incidents))
        .route("/api/v1/incidents/{id}/status", post(change_incident_status))
        .route("/api/v1/topology", get(topology))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .route("/healthz", get(health))
        .merge(protected)
        .fallback(ui::static_asset)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    state.database.ping().await.map_err(ApiError::internal)?;
    Ok(Json(HealthResponse {
        status: "ok".to_owned(),
        service: "rootcause-server".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }))
}

async fn status(State(state): State<AppState>) -> Result<Json<StatusResponse>, ApiError> {
    let counts = state.database.counts().await.map_err(ApiError::internal)?;
    Ok(Json(StatusResponse {
        service: "rootcause-server".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        assets_total: counts.assets_total,
        assets_online: counts.assets_online,
        open_incidents: counts.open_incidents,
        critical_incidents: counts.critical_incidents,
    }))
}

async fn register_asset(
    State(state): State<AppState>,
    Json(asset): Json<AssetRegistration>,
) -> Result<StatusCode, ApiError> {
    validate_asset(&asset)?;
    state
        .database
        .upsert_asset(&asset)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn ingest_telemetry(
    State(state): State<AppState>,
    Json(envelope): Json<TelemetryEnvelope>,
) -> Result<Json<IngestResponse>, ApiError> {
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(ApiError::bad_request(format!(
            "unsupported protocol version {}; expected {}",
            envelope.protocol_version, PROTOCOL_VERSION
        )));
    }
    envelope
        .sample
        .validate()
        .map_err(ApiError::bad_request)?;
    let now = Utc::now();
    if envelope.sample.observed_at > now + Duration::minutes(5)
        || envelope.sample.observed_at < now - Duration::hours(24)
    {
        return Err(ApiError::bad_request(
            "sample timestamp is outside the accepted 24-hour window",
        ));
    }

    if let Some(asset) = &envelope.asset {
        validate_asset(asset)?;
        if asset.agent_id != envelope.sample.agent_id {
            return Err(ApiError::bad_request(
                "asset and sample agent identifiers do not match",
            ));
        }
        state
            .database
            .upsert_asset(asset)
            .await
            .map_err(ApiError::internal)?;
    }

    let hostname = state
        .database
        .asset_hostname(envelope.sample.agent_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("register the asset before sending telemetry"))?;

    state
        .database
        .store_sample(&envelope.sample)
        .await
        .map_err(ApiError::internal)?;
    let candidates = state.rca.analyze(&envelope.sample, &hostname);
    let touched = candidates.len();
    for candidate in candidates {
        state
            .database
            .upsert_incident(candidate, envelope.sample.observed_at)
            .await
            .map_err(ApiError::internal)?;
    }

    Ok(Json(IngestResponse {
        accepted: true,
        incidents_touched: touched,
    }))
}

async fn list_assets(
    State(state): State<AppState>,
) -> Result<Json<Vec<rootcause_core::AssetView>>, ApiError> {
    state
        .database
        .list_assets()
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn list_incidents(
    State(state): State<AppState>,
) -> Result<Json<Vec<Incident>>, ApiError> {
    state
        .database
        .list_incidents()
        .await
        .map(Json)
        .map_err(ApiError::internal)
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
    if request.actor.trim().is_empty() || request.actor.len() > 100 {
        return Err(ApiError::bad_request("actor must contain 1 through 100 characters"));
    }
    state
        .database
        .update_incident_status(id, request.status, &request.actor)
        .await
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("incident not found"))
}

async fn topology(State(state): State<AppState>) -> Result<Json<TopologySnapshot>, ApiError> {
    let assets = state.database.list_assets().await.map_err(ApiError::internal)?;
    let incidents = state
        .database
        .list_incidents()
        .await
        .map_err(ApiError::internal)?;
    let mut risks: HashMap<Uuid, Severity> = HashMap::new();
    for incident in incidents
        .into_iter()
        .filter(|incident| incident.status != IncidentStatus::Resolved)
    {
        risks
            .entry(incident.asset_id)
            .and_modify(|severity| {
                if incident.severity.rank() > severity.rank() {
                    *severity = incident.severity;
                }
            })
            .or_insert(incident.severity);
    }

    let mut nodes = vec![TopologyNode {
        id: "rootcause-server".to_owned(),
        label: "RootCause Server".to_owned(),
        kind: "control-plane".to_owned(),
        status: "online".to_owned(),
        platform: None,
        risk: None,
    }];
    let mut edges = Vec::new();
    let mut platform_groups: HashMap<&'static str, bool> = HashMap::new();

    for asset in assets {
        let group = asset.registration.platform.as_str();
        if platform_groups.insert(group, true).is_none() {
            nodes.push(TopologyNode {
                id: format!("platform:{group}"),
                label: platform_label(asset.registration.platform).to_owned(),
                kind: "platform-group".to_owned(),
                status: "online".to_owned(),
                platform: Some(asset.registration.platform),
                risk: None,
            });
            edges.push(TopologyEdge {
                source: "rootcause-server".to_owned(),
                target: format!("platform:{group}"),
                relation: "manages".to_owned(),
            });
        }

        let agent_id = asset.registration.agent_id;
        nodes.push(TopologyNode {
            id: format!("asset:{agent_id}"),
            label: asset.registration.hostname,
            kind: "endpoint".to_owned(),
            status: asset.status.as_str().to_owned(),
            platform: Some(asset.registration.platform),
            risk: risks.get(&agent_id).copied(),
        });
        edges.push(TopologyEdge {
            source: format!("platform:{group}"),
            target: format!("asset:{agent_id}"),
            relation: "contains".to_owned(),
        });
    }

    Ok(Json(TopologySnapshot {
        generated_at: Utc::now(),
        nodes,
        edges,
    }))
}

fn validate_asset(asset: &AssetRegistration) -> Result<(), ApiError> {
    let hostname = asset.hostname.trim();
    if hostname.is_empty() || hostname.len() > 255 {
        return Err(ApiError::bad_request(
            "hostname must contain 1 through 255 characters",
        ));
    }
    if asset.agent_version.trim().is_empty() || asset.agent_version.len() > 50 {
        return Err(ApiError::bad_request("invalid agent version"));
    }
    if asset.labels.len() > 32
        || asset
            .labels
            .iter()
            .any(|(key, value)| key.len() > 64 || value.len() > 256)
    {
        return Err(ApiError::bad_request("asset labels exceed the supported limits"));
    }
    Ok(())
}

const fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => "Windows",
        Platform::Linux => "Linux",
        Platform::Macos => "macOS",
        Platform::Unknown => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_validation_rejects_empty_values() {
        let asset = AssetRegistration {
            agent_id: Uuid::nil(),
            hostname: " ".to_owned(),
            platform: Platform::Linux,
            os_version: None,
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            agent_version: "0.1.0".to_owned(),
            labels: Default::default(),
        };
        assert!(validate_asset(&asset).is_err());
    }
}
