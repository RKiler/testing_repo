# Recon Review Queries

This file contains ready-to-run PostgreSQL queries for reviewing the data collected by the framework.

Open a database shell:

```bash
docker compose exec postgres psql -U recon_user -d recon_framework
```

## New subdomains in the last 24 hours

```sql
SELECT
  d.domain,
  s.subdomain,
  s.first_seen,
  s.last_seen
FROM subdomains s
JOIN domains d ON d.id = s.domain_id
WHERE s.first_seen > NOW() - INTERVAL '24 hours'
ORDER BY s.first_seen DESC;
```

## New live hosts in the last 24 hours

```sql
SELECT
  d.domain,
  s.subdomain,
  lh.url,
  lh.status_code,
  lh.title,
  lh.first_seen
FROM live_hosts lh
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE lh.first_seen > NOW() - INTERVAL '24 hours'
ORDER BY lh.first_seen DESC;
```

## New URLs in the last 24 hours

```sql
SELECT
  d.domain,
  lh.url AS base_url,
  e.path,
  e.source,
  e.risk_tags,
  e.first_seen
FROM endpoints e
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE e.first_seen > NOW() - INTERVAL '24 hours'
ORDER BY e.first_seen DESC;
```

## New JS assets in the last 24 hours

```sql
SELECT
  d.domain,
  lh.url AS host_url,
  ja.asset_url,
  ja.source,
  ja.http_status,
  ja.size_bytes,
  ja.first_seen
FROM js_assets ja
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE ja.first_seen > NOW() - INTERVAL '24 hours'
ORDER BY ja.first_seen DESC;
```

## Risky URL parameters for manual XSS, IDOR, and SSRF review

```sql
SELECT
  d.domain,
  lh.url AS base_url,
  e.path,
  up.param_name,
  up.example_value,
  up.risk_tags,
  up.first_seen
FROM url_parameters up
JOIN endpoints e ON e.id = up.endpoint_id
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE cardinality(up.risk_tags) > 0
ORDER BY up.first_seen DESC, array_length(up.risk_tags, 1) DESC;
```

## SSRF-prone parameters first

```sql
SELECT
  d.domain,
  lh.url AS base_url,
  e.path,
  up.param_name,
  up.example_value,
  up.first_seen
FROM url_parameters up
JOIN endpoints e ON e.id = up.endpoint_id
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE up.risk_tags @> ARRAY['ssrf']::text[]
ORDER BY up.first_seen DESC;
```

## XSS-prone parameters first

```sql
SELECT
  d.domain,
  lh.url AS base_url,
  e.path,
  up.param_name,
  up.example_value,
  up.first_seen
FROM url_parameters up
JOIN endpoints e ON e.id = up.endpoint_id
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE up.risk_tags @> ARRAY['xss']::text[]
ORDER BY up.first_seen DESC;
```

## IDOR-prone parameters first

```sql
SELECT
  d.domain,
  lh.url AS base_url,
  e.path,
  up.param_name,
  up.example_value,
  up.first_seen
FROM url_parameters up
JOIN endpoints e ON e.id = up.endpoint_id
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE up.risk_tags @> ARRAY['idor']::text[]
ORDER BY up.first_seen DESC;
```

## JS files with secret-looking strings

```sql
SELECT
  d.domain,
  ja.asset_url,
  (jar.risk_summary->>'api_url_count')::int AS api_url_count,
  jsonb_array_length(jar.extraction->'tokens_or_secret_like_strings') AS secret_match_count,
  jar.analyzed_at
FROM js_analysis_results jar
JOIN js_assets ja ON ja.id = jar.js_asset_id
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE jsonb_array_length(jar.extraction->'tokens_or_secret_like_strings') > 0
ORDER BY jar.analyzed_at DESC;
```

## JS files with dangerous DOM sinks

```sql
SELECT
  d.domain,
  ja.asset_url,
  jsonb_array_length(jar.extraction->'dangerous_dom_sinks') AS dom_sink_count,
  jsonb_array_length(jar.extraction->'fetch_xhr_usage') AS fetch_xhr_count,
  jar.analyzed_at
FROM js_analysis_results jar
JOIN js_assets ja ON ja.id = jar.js_asset_id
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE jsonb_array_length(jar.extraction->'dangerous_dom_sinks') > 0
ORDER BY jar.analyzed_at DESC;
```

## JS files with GraphQL hints

```sql
SELECT
  d.domain,
  ja.asset_url,
  jsonb_array_length(jar.extraction->'graphql_hints') AS graphql_hint_count,
  jar.analyzed_at
FROM js_analysis_results jar
JOIN js_assets ja ON ja.id = jar.js_asset_id
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE jsonb_array_length(jar.extraction->'graphql_hints') > 0
ORDER BY jar.analyzed_at DESC;
```

## URLs discovered from JS analysis

```sql
SELECT
  d.domain,
  lh.url AS base_url,
  e.path,
  e.risk_tags,
  e.first_seen
FROM endpoints e
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE e.source = 'js_analysis'
ORDER BY e.first_seen DESC;
```

## Most interesting findings for quick triage

```sql
SELECT
  d.domain,
  f.finding_type,
  f.severity,
  f.location,
  f.details,
  f.first_seen
FROM findings f
LEFT JOIN domains d ON d.id = f.domain_id
WHERE f.severity IN ('critical', 'high', 'medium')
ORDER BY
  CASE f.severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    ELSE 4
  END,
  f.first_seen DESC;
```

## Domains with the fastest growth in URLs

```sql
SELECT
  d.domain,
  COUNT(*) AS new_url_count_24h
FROM endpoints e
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE e.first_seen > NOW() - INTERVAL '24 hours'
GROUP BY d.domain
ORDER BY new_url_count_24h DESC, d.domain;
```

## Domains with the most new JS assets

```sql
SELECT
  d.domain,
  COUNT(*) AS new_js_count_24h
FROM js_assets ja
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE ja.first_seen > NOW() - INTERVAL '24 hours'
GROUP BY d.domain
ORDER BY new_js_count_24h DESC, d.domain;
```

## Export a compact queue for an AI review agent

```sql
SELECT jsonb_build_object(
  'domain', d.domain,
  'base_url', lh.url,
  'path', e.path,
  'source', e.source,
  'risk_tags', e.risk_tags,
  'parameters', e.parameters,
  'first_seen', e.first_seen
) AS review_item
FROM endpoints e
JOIN live_hosts lh ON lh.id = e.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE e.first_seen > NOW() - INTERVAL '24 hours'
   OR cardinality(e.risk_tags) > 0
ORDER BY e.first_seen DESC
LIMIT 500;
```

## Export JS analysis queue for an AI review agent

```sql
SELECT jsonb_build_object(
  'domain', d.domain,
  'asset_url', ja.asset_url,
  'source', ja.source,
  'http_status', ja.http_status,
  'size_bytes', ja.size_bytes,
  'analysis', jar.extraction,
  'risk_summary', jar.risk_summary,
  'analyzed_at', jar.analyzed_at
) AS js_review_item
FROM js_analysis_results jar
JOIN js_assets ja ON ja.id = jar.js_asset_id
JOIN live_hosts lh ON lh.id = ja.live_host_id
JOIN subdomains s ON s.id = lh.subdomain_id
JOIN domains d ON d.id = s.domain_id
WHERE jsonb_array_length(jar.extraction->'tokens_or_secret_like_strings') > 0
   OR jsonb_array_length(jar.extraction->'dangerous_dom_sinks') > 0
   OR jsonb_array_length(jar.extraction->'graphql_hints') > 0
   OR (jar.risk_summary->>'api_url_count')::int > 0
ORDER BY jar.analyzed_at DESC
LIMIT 500;
```
