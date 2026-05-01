# Enhanced Recon Framework

This directory contains the continuous recon stack plus the phase-two upgrades for richer discovery, safer deltas, and cleaner handoff into an AI review agent.

## What it does now

- continuously scans active domains from Postgres
- supports per-domain controls for:
  - including or skipping subdomain enumeration
  - enabling `gau`, `katana`, `hakrawler`
  - enabling JS analysis
  - enabling `ffuf`
  - enabling `nuclei`
  - enabling screenshots
  - capping live hosts, historical URLs, and JS assets
- discovers subdomains with:
  - `assetfinder`
  - `subfinder`
  - `findomain`
  - `amass`
  - `sublist3r`
  - `crt.sh`
- probes live hosts with `httpx`
- discovers URLs from:
  - `waybackurls`
  - `gau`
  - optional `katana`
  - optional `hakrawler`
  - common-path probing
  - optional low-rate `ffuf`
- downloads and analyzes JS assets
- extracts:
  - endpoint-like paths
  - API URLs
  - GraphQL hints
  - auth-related keywords
  - secret-looking strings
  - DOM sinks
  - location-based DOM XSS source hints
  - `postMessage` usage
  - storage usage
  - `fetch` and XHR usage
  - admin, invite, export, role, billing-style terms
- classifies URL parameters for:
  - XSS-prone names
  - IDOR-prone names
  - SSRF-prone names
- records live-host HTTP fingerprints and flags changes
- captures screenshots for new live hosts and optional fingerprint changes
- optionally runs `nuclei` on newly discovered live hosts
- creates scan snapshots and AI-ready review queues
- prunes old alerts, snapshots, screenshots, and stale fingerprint history

## Installed tools

Subdomain enumeration:
- `assetfinder`
- `subfinder`
- `findomain`
- `amass`
- `sublist3r`

URL, JS, and crawl discovery:
- `waybackurls`
- `gau`
- `katana`
- `hakrawler`

Probing and network helpers:
- `httpx`
- `dnsx`
- `naabu`

Additional scanners and helpers:
- `ffuf`
- `nuclei`
- `gowitness`
- `unfurl`
- `anew`
- `jq`
- `curl`

## Main files

- `continuous_recon.py`: scan loop, alerting, snapshots, retention, and per-domain controls
- `js_analysis.py`: JS extraction and heuristic severity tuning
- `database_schema.sql`: tables plus AI review and clustering views
- `dashboard.py`: dashboard and JSON API endpoints
- `export_review_queue.py`: dumps AI review queues to JSON files
- `queries.md`: ready-to-run SQL for triage
- `config.example.yaml`: global defaults

## Fresh setup

1. Copy config and env files:

```bash
cp config.example.yaml config.yaml
cp .env.example .env
```

2. Set at least these in `.env`:

```env
RECON_DB_PASSWORD=change_me
GRAFANA_ADMIN_PASSWORD=change_me
```

3. Put your ffuf wordlist here if you want directory brute forcing:

```bash
mkdir -p wordlists
cp /path/to/commons.txt wordlists/commons.txt
```

4. Build and start:

```bash
docker compose up -d --build
```

5. Add domains:

```bash
docker compose exec postgres psql -U recon_user -d recon_framework -c \
  "INSERT INTO domains (domain, organization, scan_interval_hours) VALUES ('example.com', 'Example', 24) ON CONFLICT (domain) DO NOTHING;"
```

## Important migration note

This phase-two upgrade changes the schema significantly.

If you already have an older Postgres volume for this stack, the easiest path is:

```bash
docker compose down -v
docker compose up -d --build
```

Only do that if you are okay wiping the old framework data.

## Per-domain controls

You can update controls directly in the `domains` table.

Example:

```sql
UPDATE domains
SET
  enable_nuclei = TRUE,
  enable_ffuf = TRUE,
  enable_screenshots = TRUE,
  enable_katana = TRUE,
  max_live_hosts = 50,
  max_wayback_urls = 100,
  max_js_assets = 40
WHERE domain = 'example.com';
```

Useful columns:
- `include_subdomains`
- `max_live_hosts`
- `max_wayback_urls`
- `max_js_assets`
- `enable_gau`
- `enable_katana`
- `enable_hakrawler`
- `enable_js_analysis`
- `enable_ffuf`
- `enable_nuclei`
- `enable_screenshots`

## Screenshots

Screenshots are stored in the shared Docker volume mounted at `/app/screenshots`.

The dashboard serves them at:

- `/screenshots/<relative-path>`

By default:
- new live hosts are screenshotted
- fingerprint changes can also trigger new screenshots

## Snapshots and review queues

This version stores:
- `scan_snapshots`
- `live_host_fingerprints`
- `screenshots`

It also exposes AI-ready views:
- `ai_review_endpoint_queue`
- `ai_review_js_queue`
- `ai_review_findings_queue`
- `parameter_risk_clusters`

To export them to JSON:

```bash
docker compose exec recon-framework python export_review_queue.py
```

Files are written to:

- `/app/exports/endpoint_review_queue.json`
- `/app/exports/js_review_queue.json`
- `/app/exports/findings_review_queue.json`

The `exports` directory is persisted in a Docker volume.

## Dashboard and APIs

Dashboard:
- `http://YOUR_VPS_IP:5000`

Useful API endpoints:
- `/api/stats`
- `/api/snapshots`
- `/api/clusters/parameters`
- `/api/review/endpoints`
- `/api/review/js`
- `/api/review/findings`

## Recommended starting config

Start conservatively:

```yaml
scan:
  max_concurrent_domains: 2
  max_concurrent_live_hosts: 3
  enable_gau: true
  enable_katana: false
  enable_hakrawler: false
  directory_bruteforce_enabled: false
  nuclei_enabled: false
```

Then enable heavier features per domain as needed.

## Suggested operator flow

1. Confirm subdomains and live hosts are being inserted.
2. Check the dashboard snapshot deltas.
3. Review risky parameter clusters.
4. Export AI review queues.
5. Turn on `ffuf`, `nuclei`, `katana`, and screenshots selectively for higher-value domains.
