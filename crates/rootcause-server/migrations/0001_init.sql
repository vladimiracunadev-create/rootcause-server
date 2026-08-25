CREATE TABLE IF NOT EXISTS assets (
    agent_id TEXT PRIMARY KEY NOT NULL,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    registration_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    latest_metrics_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_assets_platform ON assets(platform);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    sample_json TEXT NOT NULL,
    FOREIGN KEY(agent_id) REFERENCES assets(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_telemetry_asset_time
    ON telemetry(agent_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    asset_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    incident_json TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incidents_status_severity
    ON incidents(status, severity, last_seen DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(observed_at DESC);
