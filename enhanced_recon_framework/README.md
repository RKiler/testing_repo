# Enhanced Recon Framework

This directory contains the corrected and extended version of the framework described in `new.txt`. It is now wired for continuous recon plus JS and URL signal collection, so you can layer an AI review agent on top of structured data instead of raw logs.

## What this stack does

- continuously scans active domains from Postgres on a schedule
- discovers subdomains with `assetfinder`, `subfinder`, optional `findomain`, and `crt.sh`
- probes live hosts with `httpx`
- discovers URLs from `waybackurls` plus common-path probing
- discovers JS assets from wayback results and live HTML pages
- downloads JS and extracts:
  - endpoint-like paths
  - API URLs
  - GraphQL hints
  - auth-related keywords
  - token or secret-looking strings
  - dangerous DOM sinks
  - `postMessage` usage
  - storage usage
  - `fetch` or XHR usage
  - webhook, admin, invite, export, role-related terms
- classifies URL query parameters with heuristics for:
  - XSS-prone names
  - IDOR-prone names
  - SSRF-prone names
- alerts on:
  - new subdomains
  - new URLs
  - new JS assets
  - new findings such as risky parameters or interesting JS signals
- exposes a simple dashboard, Prometheus metrics, and Grafana

## Main files

- `continuous_recon.py`: continuous recon loop and alerting
- `js_analysis.py`: JS extraction and URL-parameter risk heuristics
- `database_schema.sql`: PostgreSQL schema
- `dashboard.py`: lightweight dashboard
- `config.example.yaml`: scan and alert settings
- `docker-compose.yml`: local or VPS stack definition
- `Dockerfile`: recon worker and dashboard image
- `queries.md`: ready-to-run SQL for manual triage and AI-agent handoff

## VPS setup

1. Install Docker and the Compose plugin on the VPS.

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
newgrp docker
```

2. Copy this directory to the VPS.

```bash
scp -r enhanced_recon_framework user@YOUR_VPS_IP:/home/user/
ssh user@YOUR_VPS_IP
cd /home/user/enhanced_recon_framework
```

3. Create the live config files.

```bash
cp config.example.yaml config.yaml
cp .env.example .env
```

4. Edit `.env`.

Required:
- `RECON_DB_PASSWORD`
- `GRAFANA_ADMIN_PASSWORD`

Optional:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

5. Edit `config.yaml`.

Start with these sections:
- `scan.max_concurrent_domains`
- `scan.idle_sleep_seconds`
- `scan.max_wayback_urls_per_host`
- `scan.max_js_assets_per_host`
- `alerts.webhook_urls`
- `alerts.telegram`
- `alerts.smtp`

6. Start the stack.

```bash
docker compose up -d --build
```

7. Confirm containers are healthy.

```bash
docker compose ps
docker compose logs -f recon-framework
```

8. Add your first target domain.

```bash
docker compose exec postgres psql -U recon_user -d recon_framework -c \
  "INSERT INTO domains (domain, organization, scan_interval_hours) VALUES ('example.com', 'Example', 24) ON CONFLICT (domain) DO NOTHING;"
```

## How to access the dashboard

If you expose ports publicly, open these in your browser:

- Grafana: `http://YOUR_VPS_IP:3000`
- Recon dashboard: `http://YOUR_VPS_IP:5000`
- Prometheus: `http://YOUR_VPS_IP:9090`

Safer option for a private VPS: keep the ports closed and use SSH tunneling.

```bash
ssh -L 3000:localhost:3000 -L 5000:localhost:5000 -L 9090:localhost:9090 user@YOUR_VPS_IP
```

Then open locally:

- `http://localhost:3000`
- `http://localhost:5000`
- `http://localhost:9090`

## What gets stored

- `domains`
- `subdomains`
- `live_hosts`
- `endpoints`
- `url_parameters`
- `js_assets`
- `js_analysis_results`
- `technologies`
- `findings`
- `alerts`

This makes it straightforward to add an AI agent later that reads from Postgres and focuses on:

- new JS assets with risky signals
- URLs and parameters that look XSS, IDOR, or SSRF-prone
- endpoint growth over time
- cross-domain patterns in the collected data

Start with [queries.md](/abs/path/c:/Users/rohan/OneDrive/Documents/GitHub/amazon/enhanced_recon_framework/queries.md) for ready-made SQL pivots.

## Operational notes

- The framework skips optional binaries that are missing instead of crashing.
- `findomain` is optional and not installed by default in the container.
- Redis is only used for short-lived alert de-duplication.
- Prometheus owns host port `9090`. The recon metrics endpoint stays internal on the Compose network.
- This stack is for continuous recon and signal collection. It is not pretending to be an autonomous vulnerability exploiter.

## Recommended rollout

1. Start with one domain and confirm inserts into `subdomains`, `live_hosts`, `endpoints`, and `js_assets`.
2. Verify you receive `new_subdomain`, `new_url`, and `new_js_asset` alerts.
3. Inspect `url_parameters` and `js_analysis_results` in Postgres.
4. Tune concurrency and URL or JS limits before adding more domains.
