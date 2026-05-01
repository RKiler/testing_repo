#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import asyncpg
import yaml
from flask import Flask, jsonify, render_template_string, send_from_directory


SCREENSHOT_ROOT = Path("/app/screenshots")


def load_config() -> dict:
    config_path = Path("/app/config.yaml")
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    data["database"]["password"] = os.getenv("RECON_DB_PASSWORD", data["database"]["password"])
    return data


class Dashboard:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.pool: asyncpg.Pool | None = None

    async def init(self) -> None:
        self.pool = await asyncpg.create_pool(
            host=self.config["database"]["host"],
            port=self.config["database"]["port"],
            database=self.config["database"]["name"],
            user=self.config["database"]["user"],
            password=self.config["database"]["password"],
            min_size=1,
            max_size=5,
        )

    async def get_stats(self) -> dict:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                  (SELECT COUNT(*) FROM domains WHERE active = TRUE) AS total_domains,
                  (SELECT COUNT(*) FROM subdomains WHERE first_seen > NOW() - INTERVAL '24 hours') AS new_subdomains_24h,
                  (SELECT COUNT(*) FROM live_hosts WHERE first_seen > NOW() - INTERVAL '24 hours') AS new_live_hosts_24h,
                  (SELECT COUNT(*) FROM endpoints WHERE first_seen > NOW() - INTERVAL '24 hours') AS new_urls_24h,
                  (SELECT COUNT(*) FROM js_assets WHERE first_seen > NOW() - INTERVAL '24 hours') AS new_js_assets_24h,
                  (SELECT COUNT(*) FROM screenshots WHERE captured_at > NOW() - INTERVAL '24 hours') AS screenshots_24h,
                  (SELECT COUNT(*) FROM findings WHERE finding_type = 'host_fingerprint_changed' AND last_seen > NOW() - INTERVAL '24 hours') AS changed_fingerprints_24h,
                  (SELECT COUNT(*) FROM url_parameters WHERE first_seen > NOW() - INTERVAL '24 hours' AND cardinality(risk_tags) > 0) AS risky_params_24h,
                  (SELECT COUNT(*) FROM findings WHERE finding_type LIKE 'nuclei_%' AND last_seen > NOW() - INTERVAL '24 hours') AS nuclei_hits_24h,
                  (SELECT COUNT(*) FROM alerts WHERE sent_at > NOW() - INTERVAL '24 hours') AS alerts_24h
                """
            )
            return dict(row)

    async def get_recent_findings(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT d.domain, finding_type, severity, location, first_seen
                FROM findings f
                LEFT JOIN domains d ON d.id = f.domain_id
                ORDER BY first_seen DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]

    async def get_recent_risky_parameters(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
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
                ORDER BY up.first_seen DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]

    async def get_recent_js_assets(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT d.domain, ja.asset_url, ja.source, ja.size_bytes, ja.http_status, ja.first_seen
                FROM js_assets ja
                JOIN live_hosts lh ON lh.id = ja.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                ORDER BY ja.first_seen DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]

    async def get_recent_snapshots(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  d.domain,
                  ss.scan_finished_at,
                  ss.duration_seconds,
                  ss.first_run,
                  ss.totals,
                  ss.new_counts
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                ORDER BY ss.scan_finished_at DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]

    async def get_recent_fingerprint_changes(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT d.domain, location, details, last_seen
                FROM findings f
                LEFT JOIN domains d ON d.id = f.domain_id
                WHERE f.finding_type = 'host_fingerprint_changed'
                ORDER BY f.last_seen DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]

    async def get_parameter_clusters(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT param_name, risk_tags, occurrence_count, domain_count, domains, last_seen
                FROM parameter_risk_clusters
                ORDER BY occurrence_count DESC, domain_count DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]

    async def get_recent_screenshots(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  d.domain,
                  lh.url,
                  sc.screenshot_path,
                  sc.capture_reason,
                  sc.captured_at
                FROM screenshots sc
                JOIN live_hosts lh ON lh.id = sc.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                ORDER BY sc.captured_at DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]

    async def get_review_queue(self, view_name: str, limit: int = 50) -> list[dict]:
        assert self.pool is not None
        if view_name not in {"ai_review_endpoint_queue", "ai_review_js_queue", "ai_review_findings_queue"}:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"SELECT review_item FROM {view_name} LIMIT {int(limit)}")
            return [dict(row["review_item"]) for row in rows]


config = load_config()
dashboard = Dashboard(config)
asyncio.run(dashboard.init())

app = Flask(__name__)


@app.route("/screenshots/<path:filename>")
def screenshot_file(filename: str):
    return send_from_directory(SCREENSHOT_ROOT, filename)


@app.route("/")
def index():
    stats = asyncio.run(dashboard.get_stats())
    findings = asyncio.run(dashboard.get_recent_findings())
    risky_params = asyncio.run(dashboard.get_recent_risky_parameters())
    js_assets = asyncio.run(dashboard.get_recent_js_assets())
    snapshots = asyncio.run(dashboard.get_recent_snapshots())
    fingerprint_changes = asyncio.run(dashboard.get_recent_fingerprint_changes())
    parameter_clusters = asyncio.run(dashboard.get_parameter_clusters())
    screenshots = asyncio.run(dashboard.get_recent_screenshots())
    return render_template_string(
        """
        <html>
        <head>
          <title>Recon Dashboard</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 2rem; background: #f7f8fa; color: #1c2733; }
            .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
            .card { background: white; padding: 1rem; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
            .section { margin-bottom: 2rem; }
            table { width: 100%; background: white; border-collapse: collapse; border-radius: 10px; overflow: hidden; margin-bottom: 1rem; }
            th, td { text-align: left; padding: .8rem; border-bottom: 1px solid #eee; vertical-align: top; }
            .tag { display: inline-block; padding: .15rem .5rem; border-radius: 999px; background: #eef3ff; margin-right: .35rem; font-size: .85rem; }
            .mono { font-family: Consolas, monospace; word-break: break-all; }
            a { color: #1f4fad; text-decoration: none; }
            pre { white-space: pre-wrap; margin: 0; font-family: Consolas, monospace; }
          </style>
        </head>
        <body>
          <h1>Enhanced Recon Dashboard</h1>
          <div class="cards">
            {% for key, value in stats.items() %}
            <div class="card">
              <strong>{{ key }}</strong>
              <div style="font-size: 2rem; margin-top: .5rem;">{{ value }}</div>
            </div>
            {% endfor %}
          </div>

          <div class="section">
            <h2>Recent Snapshot Deltas</h2>
            <table>
              <tr><th>Domain</th><th>Finished</th><th>Duration</th><th>Type</th><th>Totals</th><th>New Counts</th></tr>
              {% for item in snapshots %}
              <tr>
                <td>{{ item.domain }}</td>
                <td>{{ item.scan_finished_at }}</td>
                <td>{{ "%.1fs"|format(item.duration_seconds) }}</td>
                <td>{{ "first" if item.first_run else "delta" }}</td>
                <td><pre>{{ item.totals }}</pre></td>
                <td><pre>{{ item.new_counts }}</pre></td>
              </tr>
              {% endfor %}
            </table>
          </div>

          <div class="section">
            <h2>Recent Findings</h2>
            <table>
              <tr><th>Domain</th><th>Type</th><th>Severity</th><th>Location</th><th>Seen</th></tr>
              {% for item in findings %}
              <tr>
                <td>{{ item.domain }}</td>
                <td>{{ item.finding_type }}</td>
                <td>{{ item.severity }}</td>
                <td class="mono">{{ item.location }}</td>
                <td>{{ item.first_seen }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>

          <div class="section">
            <h2>Fingerprint Changes</h2>
            <table>
              <tr><th>Domain</th><th>Location</th><th>Details</th><th>Seen</th></tr>
              {% for item in fingerprint_changes %}
              <tr>
                <td>{{ item.domain }}</td>
                <td class="mono">{{ item.location }}</td>
                <td><pre>{{ item.details }}</pre></td>
                <td>{{ item.last_seen }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>

          <div class="section">
            <h2>Risk Parameter Clusters</h2>
            <table>
              <tr><th>Parameter</th><th>Risk Tags</th><th>Occurrences</th><th>Domains</th><th>Seen</th></tr>
              {% for item in parameter_clusters %}
              <tr>
                <td>{{ item.param_name }}</td>
                <td>{% for tag in item.risk_tags %}<span class="tag">{{ tag }}</span>{% endfor %}</td>
                <td>{{ item.occurrence_count }}</td>
                <td>{{ item.domain_count }}</td>
                <td>{{ item.last_seen }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>

          <div class="section">
            <h2>Recent Risky Parameters</h2>
            <table>
              <tr><th>Domain</th><th>URL</th><th>Parameter</th><th>Example Value</th><th>Risk Tags</th><th>Seen</th></tr>
              {% for item in risky_params %}
              <tr>
                <td>{{ item.domain }}</td>
                <td class="mono">{{ item.base_url }}{{ item.path }}</td>
                <td>{{ item.param_name }}</td>
                <td class="mono">{{ item.example_value }}</td>
                <td>{% for tag in item.risk_tags %}<span class="tag">{{ tag }}</span>{% endfor %}</td>
                <td>{{ item.first_seen }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>

          <div class="section">
            <h2>Recent JS Assets</h2>
            <table>
              <tr><th>Domain</th><th>Asset URL</th><th>Source</th><th>Status</th><th>Size</th><th>Seen</th></tr>
              {% for item in js_assets %}
              <tr>
                <td>{{ item.domain }}</td>
                <td class="mono">{{ item.asset_url }}</td>
                <td>{{ item.source }}</td>
                <td>{{ item.http_status }}</td>
                <td>{{ item.size_bytes }}</td>
                <td>{{ item.first_seen }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>

          <div class="section">
            <h2>Recent Screenshots</h2>
            <table>
              <tr><th>Domain</th><th>URL</th><th>Reason</th><th>Captured</th><th>File</th></tr>
              {% for item in screenshots %}
              <tr>
                <td>{{ item.domain }}</td>
                <td class="mono">{{ item.url }}</td>
                <td>{{ item.capture_reason }}</td>
                <td>{{ item.captured_at }}</td>
                <td><a href="/screenshots/{{ item.screenshot_path }}" target="_blank">{{ item.screenshot_path }}</a></td>
              </tr>
              {% endfor %}
            </table>
          </div>
        </body>
        </html>
        """,
        stats=stats,
        findings=findings,
        risky_params=risky_params,
        js_assets=js_assets,
        snapshots=snapshots,
        fingerprint_changes=fingerprint_changes,
        parameter_clusters=parameter_clusters,
        screenshots=screenshots,
    )


@app.route("/api/stats")
def api_stats():
    return jsonify(asyncio.run(dashboard.get_stats()))


@app.route("/api/snapshots")
def api_snapshots():
    return jsonify(asyncio.run(dashboard.get_recent_snapshots()))


@app.route("/api/clusters/parameters")
def api_parameter_clusters():
    return jsonify(asyncio.run(dashboard.get_parameter_clusters()))


@app.route("/api/review/endpoints")
def api_review_endpoints():
    return jsonify(asyncio.run(dashboard.get_review_queue("ai_review_endpoint_queue")))


@app.route("/api/review/js")
def api_review_js():
    return jsonify(asyncio.run(dashboard.get_review_queue("ai_review_js_queue")))


@app.route("/api/review/findings")
def api_review_findings():
    return jsonify(asyncio.run(dashboard.get_review_queue("ai_review_findings_queue")))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
