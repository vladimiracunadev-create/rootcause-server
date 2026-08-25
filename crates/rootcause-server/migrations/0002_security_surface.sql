-- Security surface, integrity baselines and control-plane defence.
--
-- Added in 0.2.0. Every column is nullable or carries a default so that a
-- database created by 0.1.0 keeps working after the upgrade.

ALTER TABLE assets ADD COLUMN security_json TEXT;
ALTER TABLE assets ADD COLUMN role TEXT NOT NULL DEFAULT 'internal-server';
ALTER TABLE assets ADD COLUMN exposed_services INTEGER NOT NULL DEFAULT 0;
ALTER TABLE assets ADD COLUMN posture_score INTEGER;

ALTER TABLE incidents ADD COLUMN category TEXT NOT NULL DEFAULT 'resource';

CREATE INDEX IF NOT EXISTS idx_incidents_category
    ON incidents(category, status, last_seen DESC);

-- Last known digest of every watched file, so a change is detected exactly once.
CREATE TABLE IF NOT EXISTS file_baselines (
    agent_id TEXT NOT NULL,
    path TEXT NOT NULL,
    digest TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, path),
    FOREIGN KEY (agent_id) REFERENCES assets(agent_id) ON DELETE CASCADE
);

-- Authentication pressure per source address, aggregated across the fleet.
CREATE TABLE IF NOT EXISTS auth_pressure (
    agent_id TEXT NOT NULL,
    source_address TEXT NOT NULL,
    service TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    failures INTEGER NOT NULL DEFAULT 0,
    successes INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (agent_id, source_address, service, username),
    FOREIGN KEY (agent_id) REFERENCES assets(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_pressure_source
    ON auth_pressure(source_address, last_seen DESC);

-- What the control plane itself rejected at its own perimeter.
CREATE TABLE IF NOT EXISTS defense_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    source TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_defense_events_time
    ON defense_events(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_defense_events_reason
    ON defense_events(reason, observed_at DESC);
