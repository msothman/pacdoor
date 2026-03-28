CREATE TABLE IF NOT EXISTS hosts (
    id          TEXT PRIMARY KEY,
    ip          TEXT NOT NULL UNIQUE,
    hostname    TEXT,
    os          TEXT,
    os_version  TEXT,
    mac         TEXT,
    domain      TEXT,
    profile     TEXT DEFAULT 'unknown',
    alive       INTEGER DEFAULT 1,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ports (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES hosts(id),
    port            INTEGER NOT NULL,
    protocol        TEXT DEFAULT 'tcp',
    state           TEXT DEFAULT 'open',
    service_name    TEXT,
    service_version TEXT,
    banner          TEXT,
    product         TEXT,
    discovered_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT PRIMARY KEY,
    host_id             TEXT REFERENCES hosts(id),
    port_id             TEXT REFERENCES ports(id),
    title               TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL,
    cvss_score          REAL,
    cvss_vector         TEXT,
    cve_id              TEXT,
    attack_technique_ids TEXT,
    module_name         TEXT,
    remediation         TEXT,
    refs                TEXT,
    verified            INTEGER DEFAULT 0,
    status              TEXT DEFAULT 'new',
    analyst_notes       TEXT DEFAULT '',
    evidence            TEXT,
    discovered_at       TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    host_id         TEXT REFERENCES hosts(id),
    username        TEXT,
    cred_type       TEXT,
    value           TEXT,
    domain          TEXT,
    source_module   TEXT,
    valid           INTEGER DEFAULT 0,
    admin           INTEGER DEFAULT 0,
    discovered_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, username, cred_type)
);

CREATE TABLE IF NOT EXISTS module_runs (
    id              TEXT PRIMARY KEY,
    module_name     TEXT NOT NULL,
    host_id         TEXT,
    status          TEXT DEFAULT 'pending',
    started_at      TEXT,
    completed_at    TEXT,
    error           TEXT,
    findings_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id              TEXT PRIMARY KEY,
    from_host_id    TEXT REFERENCES hosts(id),
    to_host_id      TEXT REFERENCES hosts(id),
    technique_id    TEXT,
    credential_id   TEXT REFERENCES credentials(id),
    description     TEXT,
    step_order      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module_name);
CREATE INDEX IF NOT EXISTS idx_credentials_host ON credentials(host_id);
CREATE INDEX IF NOT EXISTS idx_credentials_valid ON credentials(valid);
CREATE INDEX IF NOT EXISTS idx_module_runs_status ON module_runs(status);
CREATE INDEX IF NOT EXISTS idx_attack_paths_from ON attack_paths(from_host_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_to ON attack_paths(to_host_id);
