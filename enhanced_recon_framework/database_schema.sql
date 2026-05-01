CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    organization VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan TIMESTAMP,
    scan_interval_hours INTEGER NOT NULL DEFAULT 24,
    include_subdomains BOOLEAN NOT NULL DEFAULT TRUE,
    max_live_hosts INTEGER,
    max_wayback_urls INTEGER,
    max_js_assets INTEGER,
    enable_gau BOOLEAN,
    enable_katana BOOLEAN,
    enable_hakrawler BOOLEAN,
    enable_js_analysis BOOLEAN,
    enable_ffuf BOOLEAN,
    enable_nuclei BOOLEAN,
    enable_screenshots BOOLEAN
);

ALTER TABLE domains ADD COLUMN IF NOT EXISTS include_subdomains BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS max_live_hosts INTEGER;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS max_wayback_urls INTEGER;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS max_js_assets INTEGER;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_gau BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_katana BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_hakrawler BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_js_analysis BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_ffuf BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_nuclei BOOLEAN;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_screenshots BOOLEAN;

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
    webserver TEXT,
    content_length BIGINT,
    fingerprint_hash VARCHAR(64),
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_new BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE live_hosts ADD COLUMN IF NOT EXISTS webserver TEXT;
ALTER TABLE live_hosts ADD COLUMN IF NOT EXISTS content_length BIGINT;
ALTER TABLE live_hosts ADD COLUMN IF NOT EXISTS fingerprint_hash VARCHAR(64);

CREATE TABLE IF NOT EXISTS live_host_fingerprints (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    fingerprint_hash VARCHAR(64) NOT NULL,
    status_code INTEGER,
    title TEXT,
    webserver TEXT,
    content_length BIGINT,
    technologies JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(live_host_id, fingerprint_hash)
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

CREATE TABLE IF NOT EXISTS screenshots (
    id SERIAL PRIMARY KEY,
    live_host_id INTEGER NOT NULL REFERENCES live_hosts(id) ON DELETE CASCADE,
    screenshot_path TEXT NOT NULL,
    sha256 VARCHAR(64),
    file_size BIGINT,
    capture_reason VARCHAR(50) NOT NULL DEFAULT 'new_live_host',
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(live_host_id, screenshot_path)
);

CREATE TABLE IF NOT EXISTS scan_snapshots (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    scan_started_at TIMESTAMP NOT NULL,
    scan_finished_at TIMESTAMP NOT NULL,
    duration_seconds DOUBLE PRECISION NOT NULL,
    first_run BOOLEAN NOT NULL DEFAULT FALSE,
    totals JSONB NOT NULL DEFAULT '{}'::jsonb,
    new_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
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
CREATE INDEX IF NOT EXISTS idx_live_hosts_fingerprint_hash ON live_hosts(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_fingerprints_live_host_current ON live_host_fingerprints(live_host_id, is_current);
CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen ON live_host_fingerprints(last_seen);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(live_host_id);
CREATE INDEX IF NOT EXISTS idx_url_parameters_endpoint ON url_parameters(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_url_parameters_risk_tags ON url_parameters USING GIN (risk_tags);
CREATE INDEX IF NOT EXISTS idx_endpoints_risk_tags ON endpoints USING GIN (risk_tags);
CREATE INDEX IF NOT EXISTS idx_js_assets_host ON js_assets(live_host_id);
CREATE INDEX IF NOT EXISTS idx_js_assets_last_seen ON js_assets(last_seen);
CREATE INDEX IF NOT EXISTS idx_screenshots_live_host ON screenshots(live_host_id);
CREATE INDEX IF NOT EXISTS idx_screenshots_captured_at ON screenshots(captured_at);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_domain ON scan_snapshots(domain_id, scan_finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_is_new ON findings(is_new);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE OR REPLACE VIEW parameter_risk_clusters AS
SELECT
    up.param_name,
    ARRAY_REMOVE(ARRAY_AGG(DISTINCT tag), NULL) AS risk_tags,
    COUNT(*) AS occurrence_count,
    COUNT(DISTINCT d.id) AS domain_count,
    ARRAY_AGG(DISTINCT d.domain) AS domains,
    MAX(up.last_seen) AS last_seen
FROM url_parameters up
JOIN endpoints e ON e.id = up.endpoint_id
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
LEFT JOIN LATERAL UNNEST(up.risk_tags) AS tag ON TRUE
GROUP BY up.param_name
HAVING COUNT(*) > 0;

CREATE OR REPLACE VIEW ai_review_endpoint_queue AS
SELECT
    e.id AS endpoint_id,
    d.domain,
    lh.url AS base_url,
    e.path,
    e.source,
    e.risk_tags,
    e.parameters,
    e.first_seen,
    e.last_seen,
    jsonb_build_object(
        'domain', d.domain,
        'base_url', lh.url,
        'path', e.path,
        'source', e.source,
        'risk_tags', e.risk_tags,
        'parameters', e.parameters,
        'first_seen', e.first_seen,
        'last_seen', e.last_seen
    ) AS review_item
FROM endpoints e
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE cardinality(e.risk_tags) > 0
   OR e.first_seen > NOW() - INTERVAL '24 hours';

CREATE OR REPLACE VIEW ai_review_js_queue AS
SELECT
    ja.id AS js_asset_id,
    d.domain,
    ja.asset_url,
    ja.source,
    ja.http_status,
    ja.size_bytes,
    jar.analyzed_at,
    jar.extraction,
    jar.risk_summary,
    jsonb_build_object(
        'domain', d.domain,
        'asset_url', ja.asset_url,
        'source', ja.source,
        'http_status', ja.http_status,
        'size_bytes', ja.size_bytes,
        'analyzed_at', jar.analyzed_at,
        'analysis', jar.extraction,
        'risk_summary', jar.risk_summary
    ) AS review_item
FROM js_analysis_results jar
JOIN js_assets ja ON ja.id = jar.js_asset_id
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE COALESCE(jsonb_array_length(jar.extraction->'tokens_or_secret_like_strings'), 0) > 0
   OR COALESCE(jsonb_array_length(jar.extraction->'dangerous_dom_sinks'), 0) > 0
   OR COALESCE(jsonb_array_length(jar.extraction->'graphql_hints'), 0) > 0
   OR (jar.risk_summary->>'api_url_count')::int > 0;

CREATE OR REPLACE VIEW ai_review_findings_queue AS
SELECT
    f.id AS finding_id,
    d.domain,
    f.finding_type,
    f.severity,
    f.location,
    f.details,
    f.first_seen,
    f.last_seen,
    jsonb_build_object(
        'domain', d.domain,
        'finding_type', f.finding_type,
        'severity', f.severity,
        'location', f.location,
        'details', f.details,
        'first_seen', f.first_seen,
        'last_seen', f.last_seen
    ) AS review_item
FROM findings f
LEFT JOIN domains d ON d.id = f.domain_id
WHERE f.severity IN ('critical', 'high', 'medium')
   OR f.last_seen > NOW() - INTERVAL '24 hours';
