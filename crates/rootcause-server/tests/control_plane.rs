//! End-to-end tests over the real HTTP surface.
//!
//! These drive the router the binary serves — same middleware, same order, same
//! database — so the guarantees the README makes about authentication, headers
//! and detection are checked against the thing that actually runs.

use std::collections::BTreeMap;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use http_body_util::BodyExt;
use rootcause_core::{
    DetectionEngine, PROTOCOL_VERSION,
    models::{AssetRegistration, MetricSample, Platform, TelemetryEnvelope},
    security::{AuthEvent, AuthOutcome, ListeningSocket, Protocol, SecuritySignals, WatchedFile},
};
use rootcause_server::{api, config::ServeSettings, state::AppState, storage::Database};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn settings() -> ServeSettings {
    ServeSettings {
        bind: "127.0.0.1:8080".parse().expect("a valid bind address"),
        database_url: "sqlite::memory:".to_owned(),
        api_token: Some(TOKEN.to_owned()),
        insecure_dev_mode: false,
        json_logs: false,
        rate_limit_per_minute: 600,
        lockout_threshold: 3,
        lockout_seconds: 300,
        retention_days: 30,
        agent_interval_seconds: 30,
        trust_forwarded_for: false,
        policy_file: None,
        max_body_kib: 1024,
    }
}

async fn app() -> Router {
    let database = Database::connect("sqlite::memory:").await.expect("in-memory database");
    let state = AppState::new(database, DetectionEngine::default(), &settings());
    api::router(state)
}

fn agent_id() -> Uuid {
    Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("a fixed identifier")
}

fn registration(role: &str) -> AssetRegistration {
    let mut labels = BTreeMap::new();
    labels.insert("role".to_owned(), role.to_owned());
    labels.insert("environment".to_owned(), "production".to_owned());
    AssetRegistration {
        agent_id: agent_id(),
        hostname: "srv-prod-01".to_owned(),
        platform: Platform::Linux,
        os_version: Some("Debian 13".to_owned()),
        kernel_version: Some("6.12.0".to_owned()),
        architecture: "x86_64".to_owned(),
        agent_version: "0.2.0".to_owned(),
        labels,
    }
}

fn sample() -> MetricSample {
    MetricSample {
        agent_id: agent_id(),
        observed_at: Utc::now(),
        cpu_percent: 11.0,
        memory_percent: 42.0,
        disk_percent: 55.0,
        uptime_seconds: 3_600,
        load_average: Some([0.2, 0.3, 0.4]),
        network_rx_bytes: 1_000,
        network_tx_bytes: 2_000,
        disk_free_bytes: Some(80_000_000_000),
        process_count: Some(210),
    }
}

fn authorized(method: &str, path: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
    match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .expect("a valid request"),
        None => builder.body(Body::empty()).expect("a valid request"),
    }
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.expect("a readable body").to_bytes();
    serde_json::from_slice(&bytes).expect("a JSON body")
}

async fn text_body(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.expect("a readable body").to_bytes();
    String::from_utf8(bytes.to_vec()).expect("UTF-8 output")
}

/// Register the asset and post one envelope, returning the ingest response.
async fn ingest(app: &Router, security: Option<SecuritySignals>) -> Value {
    let response = app
        .clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/assets/register",
            Some(serde_json::to_value(registration("database")).expect("serialisable")),
        ))
        .await
        .expect("a response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let envelope = TelemetryEnvelope {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        asset: Some(registration("database")),
        sample: sample(),
        security,
    };
    let response = app
        .clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/telemetry",
            Some(serde_json::to_value(&envelope).expect("serialisable")),
        ))
        .await
        .expect("a response");
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

#[tokio::test]
async fn health_is_public_and_the_api_is_not() {
    let app = app().await;

    let health = app
        .clone()
        .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let status = app
        .clone()
        .oneshot(Request::builder().uri("/api/v1/status").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wrong_token_is_rejected_and_the_body_says_why() {
    let app = app().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header(header::AUTHORIZATION, "Bearer wrong-token-wrong-token-wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "unauthorized");
}

#[tokio::test]
async fn repeated_wrong_tokens_lock_the_caller_out() {
    let app = app().await;
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header(header::AUTHORIZATION, "Bearer wrong-token-wrong-token-wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // The fourth attempt never reaches the token comparison.
    let response = app.clone().oneshot(authorized("GET", "/api/v1/status", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(json_body(response).await["code"], "locked_out");
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let app = app().await;
    let response = app.oneshot(authorized("GET", "/api/v1/status", None)).await.unwrap();
    let headers = response.headers().clone();

    for header_name in [
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ] {
        assert!(headers.contains_key(header_name), "{header_name} must always be sent");
    }
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    let policy = headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(!policy.contains("unsafe-inline"));
}

#[tokio::test]
async fn the_console_is_served_and_is_not_cached_as_evidence() {
    let app = app().await;
    let response =
        app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("content-security-policy"));
    assert!(text_body(response).await.contains("RootCause"));
}

#[tokio::test]
async fn a_healthy_server_produces_no_incidents() {
    let app = app().await;
    let body = ingest(&app, Some(SecuritySignals::default())).await;
    assert_eq!(body["accepted"], true);
    assert_eq!(body["incidents_touched"], 0);

    let response = app.oneshot(authorized("GET", "/api/v1/incidents", None)).await.unwrap();
    assert_eq!(json_body(response).await.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn an_exposed_database_becomes_a_critical_incident_with_a_runbook() {
    let app = app().await;
    let security = SecuritySignals {
        listeners: vec![
            ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432)
                .with_process(Some("postgres".to_owned()), Some(901)),
            ListeningSocket::new(Protocol::Tcp, "127.0.0.1", 6379),
        ],
        ..SecuritySignals::default()
    };
    let body = ingest(&app, Some(security)).await;
    assert_eq!(body["incidents_touched"], 1);

    let response = app
        .clone()
        .oneshot(authorized("GET", "/api/v1/incidents?category=exposure", None))
        .await
        .unwrap();
    let incidents = json_body(response).await;
    let incident = &incidents.as_array().unwrap()[0];
    assert_eq!(incident["severity"], "critical");
    assert_eq!(incident["category"], "exposure");
    assert!(incident["title"].as_str().unwrap().contains("PostgreSQL"));
    assert!(!incident["runbook"].as_array().unwrap().is_empty());
    assert!(incident["techniques"].as_array().unwrap().contains(&Value::from("T1190")));

    // The same finding is reachable through its own runbook endpoint.
    let id = incident["id"].as_str().unwrap();
    let response = app
        .oneshot(authorized("GET", &format!("/api/v1/incidents/{id}/runbook"), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!json_body(response).await.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_closed_port_resolves_its_own_incident_on_the_next_cycle() {
    let app = app().await;
    let exposed = SecuritySignals {
        listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432)],
        ..SecuritySignals::default()
    };
    ingest(&app, Some(exposed)).await;
    ingest(&app, Some(SecuritySignals::default())).await;

    let response =
        app.oneshot(authorized("GET", "/api/v1/incidents?status=open", None)).await.unwrap();
    assert_eq!(json_body(response).await.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_finding_stays_open_when_its_surface_could_not_be_inspected() {
    let app = app().await;
    let exposed = SecuritySignals {
        listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 5432)],
        ..SecuritySignals::default()
    };
    ingest(&app, Some(exposed)).await;

    // Next cycle the agent could not read the socket table. An empty list is
    // not the same fact as "the port was closed", and the console must not be
    // allowed to say it was.
    let blind = SecuritySignals {
        collection_gaps: vec![rootcause_core::security::CollectionGap::new(
            "listeners",
            "el agente no pudo leer la tabla de sockets",
        )],
        ..SecuritySignals::default()
    };
    ingest(&app, Some(blind)).await;

    let response =
        app.oneshot(authorized("GET", "/api/v1/incidents?status=open", None)).await.unwrap();
    let incidents = json_body(response).await;
    assert_eq!(
        incidents.as_array().unwrap().len(),
        1,
        "una superficie no inspeccionada no puede cerrar un hallazgo"
    );
}

#[tokio::test]
async fn a_brute_force_burst_reaches_the_threat_report() {
    let app = app().await;
    let security = SecuritySignals {
        auth_events: vec![AuthEvent {
            service: "sshd".to_owned(),
            source_address: "203.0.113.10".to_owned(),
            username: Some("root".to_owned()),
            outcome: AuthOutcome::Failure,
            count: 120,
            last_seen: Utc::now(),
        }],
        ..SecuritySignals::default()
    };
    ingest(&app, Some(security)).await;

    let response = app.oneshot(authorized("GET", "/api/v1/threats", None)).await.unwrap();
    let report = json_body(response).await;
    assert_eq!(report["total_failures"], 120);
    assert_eq!(report["sources"][0]["source_address"], "203.0.113.10");
    assert_eq!(report["sources"][0]["severity"], "critical");
}

#[tokio::test]
async fn a_changed_watched_file_is_detected_only_after_a_baseline_exists() {
    let app = app().await;
    let file = |digest: &str| WatchedFile {
        path: "/etc/ssh/sshd_config".to_owned(),
        digest: digest.to_owned(),
        size_bytes: 3_200,
        modified_at: None,
        mode: Some(0o600),
    };

    let first = ingest(
        &app,
        Some(SecuritySignals {
            watched_files: vec![file("aaaabbbbccccdddd")],
            ..SecuritySignals::default()
        }),
    )
    .await;
    assert_eq!(first["incidents_touched"], 0, "the first cycle only records the baseline");

    let second = ingest(
        &app,
        Some(SecuritySignals {
            watched_files: vec![file("1111222233334444")],
            ..SecuritySignals::default()
        }),
    )
    .await;
    assert_eq!(second["incidents_touched"], 1);

    let response =
        app.oneshot(authorized("GET", "/api/v1/incidents?category=integrity", None)).await.unwrap();
    let incidents = json_body(response).await;
    assert_eq!(incidents.as_array().unwrap().len(), 1);
    assert_eq!(incidents[0]["severity"], "high");
}

#[tokio::test]
async fn the_status_endpoint_reports_posture_and_hardening() {
    let app = app().await;
    ingest(
        &app,
        Some(SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 3306)],
            ..SecuritySignals::default()
        }),
    )
    .await;

    let response = app.oneshot(authorized("GET", "/api/v1/status", None)).await.unwrap();
    let status = json_body(response).await;
    assert_eq!(status["service"], "rootcause-server");
    assert_eq!(status["exposed_services"], 1);
    assert_eq!(status["critical_incidents"], 1);
    assert!(status["detectors"].as_u64().unwrap() >= 15);
    assert_eq!(status["posture"]["grade"], "F");
    assert_eq!(status["hardening"]["authentication"], true);
    assert_eq!(status["hardening"]["bind_is_loopback"], true);
}

#[tokio::test]
async fn the_exposure_report_lists_the_service_behind_the_port() {
    let app = app().await;
    ingest(
        &app,
        Some(SecuritySignals {
            listeners: vec![
                ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 27017),
                ListeningSocket::new(Protocol::Tcp, "10.0.0.4", 22),
            ],
            ..SecuritySignals::default()
        }),
    )
    .await;

    let response = app.oneshot(authorized("GET", "/api/v1/exposure", None)).await.unwrap();
    let report = json_body(response).await;
    assert_eq!(report["public_services"], 1);
    assert_eq!(report["private_services"], 1);
    assert_eq!(report["entries"][0]["service"], "MongoDB");
    assert_eq!(report["entries"][0]["class"], "database");
}

#[tokio::test]
async fn the_topology_places_an_exposed_host_behind_the_internet_node() {
    let app = app().await;
    ingest(
        &app,
        Some(SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 443)],
            ..SecuritySignals::default()
        }),
    )
    .await;

    let response = app.oneshot(authorized("GET", "/api/v1/topology", None)).await.unwrap();
    let snapshot = json_body(response).await;
    let ids: Vec<&str> =
        snapshot["nodes"].as_array().unwrap().iter().map(|n| n["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"internet"));
    assert!(ids.contains(&"zone:expuesto"));
}

#[tokio::test]
async fn an_unsupported_protocol_version_is_refused() {
    let app = app().await;
    app.clone()
        .oneshot(authorized(
            "POST",
            "/api/v1/assets/register",
            Some(serde_json::to_value(registration("internal")).unwrap()),
        ))
        .await
        .unwrap();

    let mut envelope = serde_json::to_value(TelemetryEnvelope {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        asset: None,
        sample: sample(),
        security: None,
    })
    .unwrap();
    envelope["protocol_version"] = Value::from("9.9");

    let response =
        app.oneshot(authorized("POST", "/api/v1/telemetry", Some(envelope))).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn telemetry_for_an_unknown_asset_is_refused() {
    let app = app().await;
    let envelope = serde_json::to_value(TelemetryEnvelope {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        asset: None,
        sample: sample(),
        security: None,
    })
    .unwrap();
    let response =
        app.oneshot(authorized("POST", "/api/v1/telemetry", Some(envelope))).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_agent_without_a_security_surface_is_told_so() {
    let app = app().await;
    let body = ingest(&app, None).await;
    let warnings = body["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("no envió superficie de seguridad"))
    );
}

#[tokio::test]
async fn a_collection_gap_is_reported_back_to_the_agent() {
    let app = app().await;
    let security = SecuritySignals {
        collection_gaps: vec![rootcause_core::security::CollectionGap::new(
            "auth-events",
            "sin permiso de lectura",
        )],
        ..SecuritySignals::default()
    };
    let body = ingest(&app, Some(security)).await;
    let warnings = body["warnings"].as_array().unwrap();
    assert!(warnings.iter().any(|warning| warning.as_str().unwrap().contains("auth-events")));
}

#[tokio::test]
async fn an_incident_can_be_acknowledged_and_the_change_is_audited() {
    let app = app().await;
    ingest(
        &app,
        Some(SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 6379)],
            ..SecuritySignals::default()
        }),
    )
    .await;

    let response = app.clone().oneshot(authorized("GET", "/api/v1/incidents", None)).await.unwrap();
    let incidents = json_body(response).await;
    let id = incidents[0]["id"].as_str().unwrap().to_owned();

    let response = app
        .clone()
        .oneshot(authorized(
            "POST",
            &format!("/api/v1/incidents/{id}/status"),
            Some(serde_json::json!({ "status": "acknowledged", "actor": "vladimir" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"], "acknowledged");

    let response = app.oneshot(authorized("GET", "/api/v1/audit", None)).await.unwrap();
    let audit = json_body(response).await;
    assert!(audit.as_array().unwrap().iter().any(|entry| entry["actor"] == "vladimir"));
}

#[tokio::test]
async fn the_rule_catalog_is_published_with_its_attack_mapping() {
    let app = app().await;
    let response = app.oneshot(authorized("GET", "/api/v1/rules", None)).await.unwrap();
    let rules = json_body(response).await;
    let rules = rules.as_array().unwrap();
    assert!(rules.len() >= 15);
    assert!(rules.iter().all(|rule| !rule["techniques"].as_array().unwrap().is_empty()));
    assert!(rules.iter().all(|rule| !rule["question"].as_str().unwrap().is_empty()));
}

#[tokio::test]
async fn the_policy_in_force_can_be_read_back() {
    let app = app().await;
    let response = app.oneshot(authorized("GET", "/api/v1/policy", None)).await.unwrap();
    let policy = json_body(response).await;
    assert!(policy["resource"]["cpu_high"].as_f64().unwrap() > 0.0);
    assert!(policy["intrusion"]["failures_per_source_high"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn metrics_are_exposed_in_prometheus_format() {
    let app = app().await;
    ingest(&app, Some(SecuritySignals::default())).await;

    let response = app.oneshot(authorized("GET", "/metrics", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = text_body(response).await;
    assert!(body.contains("# TYPE rootcause_assets_total gauge"));
    assert!(body.contains("rootcause_posture_score"));
}

#[tokio::test]
async fn the_evidence_export_is_newline_delimited_json() {
    let app = app().await;
    ingest(
        &app,
        Some(SecuritySignals {
            listeners: vec![ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 23)],
            ..SecuritySignals::default()
        }),
    )
    .await;

    let response = app.oneshot(authorized("GET", "/api/v1/export", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = text_body(response).await;
    let lines: Vec<&str> = body.lines().filter(|line| !line.is_empty()).collect();
    assert!(lines.len() >= 3);
    for line in lines {
        let value: Value = serde_json::from_str(line).expect("every line must be JSON");
        assert!(value.get("kind").is_some());
    }
}

#[tokio::test]
async fn an_invalid_filter_value_is_rejected_instead_of_ignored() {
    let app = app().await;
    let response = app
        .oneshot(authorized("GET", "/api/v1/incidents?severity=catastrofico", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_asset_detail_carries_its_own_posture_and_history() {
    let app = app().await;
    ingest(&app, Some(SecuritySignals::default())).await;

    let response = app
        .oneshot(authorized("GET", &format!("/api/v1/assets/{}", agent_id()), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let detail = json_body(response).await;
    assert_eq!(detail["asset"]["registration"]["hostname"], "srv-prod-01");
    assert_eq!(detail["asset"]["role"], "database-server");
    assert!(detail["asset"]["posture"]["score"].as_u64().unwrap() <= 100);
    assert_eq!(detail["history"].as_array().unwrap().len(), 1);
}
