CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    organization VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan TIMESTAMP,
    scan_interval_hours INTEGER NOT NULL DEFAULT 24
);

CREATE TABLE IF NOT EXISTS subdomains (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    subdomain VARCHAR(255) NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
    ip_addresses TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE(domain_id, subdomain)
);

CREATE TABLE IF NOT EXISTS live_hosts (
    id SERIAL PRIMARY KEY,
    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    url VARCHAR(500) NOT NULL UNIQUE,
    port INTEGER,
    protocol VARCHAR(10),
    status_code INTEGER,
    title TEXT,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    path VARCHAR(1000) NOT NULL,
    method VARCHAR(10) NOT NULL DEFAULT 'GET',
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_tags TEXT[] NOT NULL DEFAULT '{}',
    source VARCHAR(50) NOT NULL DEFAULT 'unknown',
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(live_host_id, path, method, source)
);

CREATE TABLE IF NOT EXISTS url_parameters (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    param_name VARCHAR(255) NOT NULL,
    example_value TEXT,
    risk_tags TEXT[] NOT NULL DEFAULT '{}',
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(endpoint_id, param_name)
);

CREATE TABLE IF NOT EXISTS js_assets (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    asset_url TEXT NOT NULL,
    source VARCHAR(50) NOT NULL DEFAULT 'unknown',
    sha256 VARCHAR(64),
    size_bytes BIGINT,
    http_status INTEGER,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(live_host_id, asset_url)
);

CREATE TABLE IF NOT EXISTS js_analysis_results (
    id SERIAL PRIMARY KEY,
    js_asset_id INTEGER NOT NULL REFERENCES js_assets(id) ON DELETE CASCADE,
    extraction JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    analyzed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(js_asset_id)
);

CREATE TABLE IF NOT EXISTS technologies (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    technology VARCHAR(100) NOT NULL,
    version VARCHAR(50),
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(live_host_id, technology, version)
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    finding_key VARCHAR(64) NOT NULL UNIQUE,
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    location TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    alert_type VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_domains_active ON domains(active);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_last_seen ON subdomains(last_seen);
CREATE INDEX IF NOT EXISTS idx_live_hosts_subdomain ON live_hosts(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_live_hosts_last_seen ON live_hosts(last_seen);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(live_host_id);
CREATE INDEX IF NOT EXISTS idx_url_parameters_endpoint ON url_parameters(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_url_parameters_risk_tags ON url_parameters USING GIN (risk_tags);
CREATE INDEX IF NOT EXISTS idx_endpoints_risk_tags ON endpoints USING GIN (risk_tags);
CREATE INDEX IF NOT EXISTS idx_js_assets_host ON js_assets(live_host_id);
CREATE INDEX IF NOT EXISTS idx_js_assets_last_seen ON js_assets(last_seen);
CREATE INDEX IF NOT EXISTS idx_findings_is_new ON findings(is_new);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
