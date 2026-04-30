#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import asyncpg
import yaml
from flask import Flask, jsonify, render_template_string


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
                  (SELECT COUNT(*) FROM url_parameters WHERE first_seen > NOW() - INTERVAL '24 hours' AND cardinality(risk_tags) > 0) AS risky_params_24h,
                  (SELECT COUNT(*) FROM findings WHERE last_seen > NOW() - INTERVAL '24 hours' AND severity IN ('critical', 'high')) AS high_findings_24h,
                  (SELECT COUNT(*) FROM alerts WHERE sent_at > NOW() - INTERVAL '24 hours') AS alerts_24h
                """
            )
            return dict(row)

    async def get_recent_findings(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT finding_type, severity, location, first_seen
                FROM findings
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
                  lh.url AS base_url,
                  e.path,
                  up.param_name,
                  up.example_value,
                  up.risk_tags,
                  up.first_seen
                FROM url_parameters up
                JOIN endpoints e ON e.id = up.endpoint_id
                JOIN live_hosts lh ON lh.id = e.live_host_id
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
                SELECT asset_url, source, size_bytes, http_status, first_seen
                FROM js_assets
                ORDER BY first_seen DESC
                LIMIT 20
                """
            )
            return [dict(row) for row in rows]


config = load_config()
dashboard = Dashboard(config)
asyncio.run(dashboard.init())

app = Flask(__name__)


@app.route("/")
def index():
    stats = asyncio.run(dashboard.get_stats())
    findings = asyncio.run(dashboard.get_recent_findings())
    risky_params = asyncio.run(dashboard.get_recent_risky_parameters())
    js_assets = asyncio.run(dashboard.get_recent_js_assets())
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
            th, td { text-align: left; padding: .8rem; border-bottom: 1px solid #eee; }
            .tag { display: inline-block; padding: .15rem .5rem; border-radius: 999px; background: #eef3ff; margin-right: .35rem; font-size: .85rem; }
            .mono { font-family: Consolas, monospace; word-break: break-all; }
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
            <h2>Recent Findings</h2>
            <table>
              <tr><th>Type</th><th>Severity</th><th>Location</th><th>Seen</th></tr>
              {% for item in findings %}
              <tr>
                <td>{{ item.finding_type }}</td>
                <td>{{ item.severity }}</td>
                <td class="mono">{{ item.location }}</td>
                <td>{{ item.first_seen }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>
          <div class="section">
            <h2>Recent Risky Parameters</h2>
            <table>
              <tr><th>URL</th><th>Parameter</th><th>Example Value</th><th>Risk Tags</th><th>Seen</th></tr>
              {% for item in risky_params %}
              <tr>
                <td class="mono">{{ item.base_url }}{{ item.path }}</td>
                <td>{{ item.param_name }}</td>
                <td class="mono">{{ item.example_value }}</td>
                <td>
                  {% for tag in item.risk_tags %}
                  <span class="tag">{{ tag }}</span>
                  {% endfor %}
                </td>
                <td>{{ item.first_seen }}</td>
              </tr>
              {% endfor %}
            </table>
          </div>
          <div class="section">
            <h2>Recent JS Assets</h2>
            <table>
              <tr><th>Asset URL</th><th>Source</th><th>Status</th><th>Size</th><th>Seen</th></tr>
              {% for item in js_assets %}
              <tr>
                <td class="mono">{{ item.asset_url }}</td>
                <td>{{ item.source }}</td>
                <td>{{ item.http_status }}</td>
                <td>{{ item.size_bytes }}</td>
                <td>{{ item.first_seen }}</td>
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
    )


@app.route("/api/stats")
def api_stats():
    return jsonify(asyncio.run(dashboard.get_stats()))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
