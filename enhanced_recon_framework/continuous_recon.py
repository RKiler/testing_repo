#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import logging
import os
import shutil
import smtplib
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp
import asyncpg
import redis
import yaml
from prometheus_client import Counter, Gauge, start_http_server

from js_analysis import (
    extract_js_signals,
    extract_query_parameters,
    extract_script_urls_from_html,
    looks_like_js_url,
    severity_for_js_signals,
    severity_for_param_tags,
)


LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOT_ROOT = Path("/app/screenshots")
SCREENSHOT_ROOT.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "recon_framework.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("recon-framework")

SUBDOMAINS_FOUND = Counter("subdomains_found_total", "Total subdomains discovered")
LIVE_HOSTS_FOUND = Counter("live_hosts_found_total", "Total live hosts discovered")
ENDPOINTS_FOUND = Counter("endpoints_found_total", "Total endpoints discovered")
JS_ASSETS_FOUND = Counter("js_assets_found_total", "Total JS assets discovered")
SCREENSHOTS_CAPTURED = Counter("screenshots_captured_total", "Total screenshots captured")
RISKY_PARAMS_FOUND = Counter("risky_params_found_total", "Total risky URL parameters discovered")
FINDINGS_FOUND = Counter("findings_found_total", "Total findings discovered")
SCAN_DURATION = Gauge("scan_duration_seconds", "Most recent domain scan duration")

DEFAULT_SUMMARY_PREVIEW_LIMIT = 20


@dataclass
class AppConfig:
    data: dict[str, Any]

    @property
    def scan(self) -> dict[str, Any]:
        return self.data["scan"]

    @property
    def database(self) -> dict[str, Any]:
        return self.data["database"]

    @property
    def redis(self) -> dict[str, Any]:
        return self.data["redis"]

    @property
    def alerts(self) -> dict[str, Any]:
        return self.data["alerts"]

    @property
    def tools(self) -> dict[str, Any]:
        return self.data["tools"]

    @property
    def retention(self) -> dict[str, Any]:
        return self.data.get("retention", {})


def load_config() -> AppConfig:
    config_path = Path("/app/config.yaml")
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if os.getenv("RECON_DB_PASSWORD"):
        data["database"]["password"] = os.getenv("RECON_DB_PASSWORD")

    telegram = data["alerts"].get("telegram", {})
    if os.getenv("TELEGRAM_BOT_TOKEN"):
        telegram["bot_token"] = os.getenv("TELEGRAM_BOT_TOKEN")
    if os.getenv("TELEGRAM_CHAT_ID"):
        telegram["chat_id"] = os.getenv("TELEGRAM_CHAT_ID")
    data["alerts"]["telegram"] = telegram
    return AppConfig(data)


def domain_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)


def chunk_message(message: str, limit: int = 3500) -> list[str]:
    if len(message) <= limit:
        return [message]
    lines = message.splitlines()
    parts: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in lines:
        projected = current_len + len(line) + 1
        if current and projected > limit:
            parts.append("\n".join(current))
            current = [line]
            current_len = len(line) + 1
        else:
            current.append(line)
            current_len = projected
    if current:
        parts.append("\n".join(current))
    return parts


def new_scan_summary(domain: str, first_run: bool) -> dict[str, Any]:
    return {
        "domain": domain,
        "first_run": first_run,
        "new_subdomains": [],
        "new_live_hosts": [],
        "new_urls": [],
        "new_js_assets": [],
        "changed_js_assets": [],
        "changed_fingerprints": [],
        "new_screenshots": [],
        "findings": [],
    }


class ContinuousReconFramework:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.db_pool: asyncpg.Pool | None = None
        self.redis_client: redis.Redis | None = None
        self.scan_semaphore = asyncio.Semaphore(int(self.config.scan["max_concurrent_domains"]))
        self.live_host_semaphore = asyncio.Semaphore(int(self.config.scan.get("max_concurrent_live_hosts", 5)))
        self.last_maintenance_run: datetime | None = None

    @staticmethod
    def append_summary(summary: dict[str, Any] | None, key: str, item: Any) -> None:
        if summary is None:
            return
        items = summary.setdefault(key, [])
        if item not in items:
            items.append(item)

    @staticmethod
    def summary_has_changes(summary: dict[str, Any]) -> bool:
        return any(
            summary.get(key)
            for key in (
                "new_subdomains",
                "new_live_hosts",
                "new_urls",
                "new_js_assets",
                "changed_js_assets",
                "changed_fingerprints",
                "new_screenshots",
                "findings",
            )
        )

    def domain_bool(self, domain_info: dict[str, Any], key: str, default: bool) -> bool:
        value = domain_info.get(key)
        return default if value is None else bool(value)

    def domain_int(self, domain_info: dict[str, Any], key: str, default: int) -> int:
        value = domain_info.get(key)
        return default if value is None else int(value)

    def render_summary_section(self, title: str, items: list[Any], formatter, first_run: bool) -> list[str]:
        if not items:
            return []
        if first_run:
            limit = int(self.config.alerts.get("first_run_summary_preview_limit", 0))
        else:
            limit = int(self.config.alerts.get("summary_preview_limit", DEFAULT_SUMMARY_PREVIEW_LIMIT))
        if limit <= 0:
            limit = len(items)
        lines = [f"{title} ({len(items)}):"]
        for item in items[:limit]:
            lines.append(f"- {formatter(item)}")
        if len(items) > limit:
            lines.append(f"- ... and {len(items) - limit} more")
        return lines

    def build_scan_summary_message(self, summary: dict[str, Any], duration: float) -> str:
        lines = [
            f"Recon Summary: {summary['domain']}",
            f"Scan type: {'first run' if summary['first_run'] else 'delta scan'}",
            f"Duration: {duration:.1f}s",
        ]
        first_run = summary["first_run"]
        lines.extend(self.render_summary_section("New subdomains", summary["new_subdomains"], lambda item: item, first_run))
        lines.extend(self.render_summary_section("New live hosts", summary["new_live_hosts"], lambda item: item, first_run))
        lines.extend(
            self.render_summary_section(
                "New URLs",
                summary["new_urls"],
                lambda item: f"{item['url']} [{item['source']}]",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "New JS assets",
                summary["new_js_assets"],
                lambda item: f"{item['asset_url']} [{item['source']}]",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Changed JS assets",
                summary["changed_js_assets"],
                lambda item: f"{item['asset_url']} sha256={item['sha256'] or 'unknown'}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Changed HTTP fingerprints",
                summary["changed_fingerprints"],
                lambda item: f"{item['url']} [{item['status_code']}] server={item['webserver'] or 'unknown'}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "New screenshots",
                summary["new_screenshots"],
                lambda item: f"{item['url']} -> {item['screenshot_path']}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Findings",
                summary["findings"],
                lambda item: f"[{item['severity'].upper()}] {item['finding_type']} @ {item['location']}",
                first_run,
            )
        )
        if not self.summary_has_changes(summary):
            lines.append("No new discoveries in this scan.")
        return "\n".join(lines)

    async def init(self) -> None:
        self.db_pool = await asyncpg.create_pool(
            host=self.config.database["host"],
            port=self.config.database["port"],
            database=self.config.database["name"],
            user=self.config.database["user"],
            password=self.config.database["password"],
            min_size=1,
            max_size=20,
        )
        if self.config.redis.get("enabled", False):
            try:
                self.redis_client = redis.Redis(
                    host=self.config.redis["host"],
                    port=self.config.redis["port"],
                    decode_responses=True,
                )
                self.redis_client.ping()
            except redis.RedisError as exc:
                logger.warning("Redis unavailable, continuing without it: %s", exc)
                self.redis_client = None

    async def get_domains_to_scan(self) -> list[dict[str, Any]]:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  id,
                  domain,
                  organization,
                  scan_interval_hours,
                  last_scan,
                  include_subdomains,
                  max_live_hosts,
                  max_wayback_urls,
                  max_js_assets,
                  enable_gau,
                  enable_katana,
                  enable_hakrawler,
                  enable_js_analysis,
                  enable_ffuf,
                  enable_nuclei,
                  enable_screenshots
                FROM domains
                WHERE active = TRUE
                  AND (
                    last_scan IS NULL OR
                    last_scan < NOW() - make_interval(hours => scan_interval_hours)
                  )
                ORDER BY last_scan NULLS FIRST
                LIMIT $1
                """,
                self.config.scan["max_concurrent_domains"],
            )
            return [dict(row) for row in rows]

    async def update_domain_last_scan(self, domain_id: int) -> None:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            await conn.execute("UPDATE domains SET last_scan = NOW() WHERE id = $1", domain_id)

    async def run_tool(self, *args: str, stdin_text: str | None = None) -> str:
        binary = args[0]
        if shutil.which(binary) is None:
            logger.info("Skipping missing tool: %s", binary)
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            if exc.errno == errno.EMFILE:
                logger.warning("Too many open files while starting tool %s; skipping this run", binary)
                return ""
            logger.warning("Failed to start tool %s: %r", binary, exc)
            return ""

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(stdin_text.encode() if stdin_text is not None else None),
                timeout=self.config.scan["tool_timeout_seconds"],
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("Tool timed out: %s", " ".join(args))
            return ""

        if proc.returncode not in (0, 1):
            logger.warning("Tool returned %s: %s %s", proc.returncode, binary, stderr.decode(errors="ignore"))
        return stdout.decode(errors="ignore")

    async def run_crtsh(self, domain: str) -> set[str]:
        results: set[str] = set()
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json") as response:
                    if response.status != 200:
                        return results
                    payload = await response.json(content_type=None)
        except Exception as exc:
            logger.warning("crt.sh failed for %s: %s", domain, exc)
            return results

        for entry in payload:
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.lower().strip().lstrip("*.")
                if name.endswith(domain):
                    results.add(name)
        return results

    async def enumerate_subdomains(self, domain_info: dict[str, Any]) -> set[str]:
        domain = domain_info["domain"]
        if not self.domain_bool(domain_info, "include_subdomains", True):
            return {domain}

        tool_map = [
            (self.config.tools.get("assetfinder", "assetfinder"), [domain]),
            (self.config.tools.get("subfinder", "subfinder"), ["-d", domain, "-silent"]),
            (self.config.tools.get("findomain", "findomain"), ["-t", domain, "-q"]),
            (self.config.tools.get("amass", "amass"), ["enum", "-passive", "-norecursive", "-noalts", "-d", domain]),
            (self.config.tools.get("sublist3r", "sublist3r"), ["-d", domain, "-n", "-t", "10"]),
        ]
        tasks = [self.run_tool(binary, *args) for binary, args in tool_map]
        tasks.append(self.run_crtsh(domain))
        outputs = await asyncio.gather(*tasks, return_exceptions=True)

        subdomains: set[str] = {domain}
        for item in outputs:
            if isinstance(item, Exception):
                continue
            if isinstance(item, set):
                subdomains.update(item)
                continue
            for line in str(item).splitlines():
                line = line.strip().lower().lstrip("*.")
                if line and line.endswith(domain):
                    subdomains.add(line)
        return subdomains

    async def save_subdomain(self, domain_id: int, subdomain: str, summary: dict[str, Any] | None = None) -> int:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO subdomains (domain_id, subdomain)
                VALUES ($1, $2)
                ON CONFLICT (domain_id, subdomain)
                DO UPDATE SET last_seen = NOW()
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                subdomain,
            )
        if row and row["inserted"]:
            SUBDOMAINS_FOUND.inc()
            self.append_summary(summary, "new_subdomains", subdomain)
        return int(row["id"])

    async def save_live_host(
        self,
        subdomain_id: int,
        payload: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> tuple[int, bool]:
        assert self.db_pool is not None
        url = payload["url"]
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        title = payload.get("title") or None
        status_code = payload.get("status_code")
        webserver = payload.get("webserver") or None
        content_length = payload.get("content_length")

        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO live_hosts (subdomain_id, url, port, protocol, status_code, title, webserver, content_length)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (url)
                DO UPDATE SET
                  last_seen = NOW(),
                  status_code = EXCLUDED.status_code,
                  title = EXCLUDED.title,
                  webserver = EXCLUDED.webserver,
                  content_length = EXCLUDED.content_length
                RETURNING id, (xmax = 0) AS inserted
                """,
                subdomain_id,
                url,
                port,
                parsed.scheme,
                status_code,
                title,
                webserver,
                content_length,
            )

            for tech in payload.get("tech", []) or []:
                await conn.execute(
                    """
                    INSERT INTO technologies (live_host_id, technology, version)
                    VALUES ($1, $2, NULL)
                    ON CONFLICT (live_host_id, technology, version)
                    DO UPDATE SET last_seen = NOW()
                    """,
                    row["id"],
                    str(tech),
                )

        if row and row["inserted"]:
            LIVE_HOSTS_FOUND.inc()
            self.append_summary(summary, "new_live_hosts", url)
        return int(row["id"]), bool(row["inserted"])

    async def probe_live_hosts(
        self,
        domain_info: dict[str, Any],
        subdomains: list[str],
        summary: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        httpx_binary = self.config.tools.get("httpx", "httpx")
        stdout = await self.run_tool(
            httpx_binary,
            "-json",
            "-silent",
            "-threads",
            str(self.config.scan.get("httpx_threads", 50)),
            "-tech-detect",
            "-status-code",
            "-content-length",
            stdin_text="\n".join(subdomains),
        )
        if not stdout:
            return []

        results: list[dict[str, Any]] = []
        subdomain_ids = {sub: await self.save_subdomain(domain_info["id"], sub, summary) for sub in subdomains}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = urlsplit(payload["url"]).hostname
            if not host or host not in subdomain_ids:
                continue
            live_host_id, is_new_live_host = await self.save_live_host(subdomain_ids[host], payload, summary)
            fingerprint_changed = await self.record_host_fingerprint(domain_info["id"], live_host_id, payload, summary)
            payload["live_host_id"] = live_host_id
            payload["is_new_live_host"] = is_new_live_host
            payload["fingerprint_changed"] = fingerprint_changed
            results.append(payload)

        max_live_hosts = domain_info.get("max_live_hosts")
        if max_live_hosts:
            results = results[: int(max_live_hosts)]
        return results

    async def record_host_fingerprint(
        self,
        domain_id: int,
        live_host_id: int,
        payload: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> bool:
        assert self.db_pool is not None
        techs = sorted(str(item) for item in (payload.get("tech", []) or []))
        fingerprint_material = {
            "status_code": payload.get("status_code"),
            "title": payload.get("title"),
            "webserver": payload.get("webserver"),
            "content_length": payload.get("content_length"),
            "tech": techs,
        }
        fingerprint_hash = hashlib.sha256(json.dumps(fingerprint_material, sort_keys=True).encode()).hexdigest()
        changed = False

        async with self.db_pool.acquire() as conn:
            current = await conn.fetchrow(
                "SELECT id, fingerprint_hash FROM live_host_fingerprints WHERE live_host_id = $1 AND is_current = TRUE",
                live_host_id,
            )

            await conn.execute(
                """
                UPDATE live_hosts
                SET fingerprint_hash = $2,
                    status_code = $3,
                    title = $4,
                    webserver = $5,
                    content_length = $6,
                    last_seen = NOW()
                WHERE id = $1
                """,
                live_host_id,
                fingerprint_hash,
                payload.get("status_code"),
                payload.get("title"),
                payload.get("webserver"),
                payload.get("content_length"),
            )

            if current and current["fingerprint_hash"] == fingerprint_hash:
                await conn.execute(
                    """
                    UPDATE live_host_fingerprints
                    SET last_seen = NOW()
                    WHERE live_host_id = $1 AND fingerprint_hash = $2
                    """,
                    live_host_id,
                    fingerprint_hash,
                )
                return False

            if current:
                changed = True
                await conn.execute(
                    "UPDATE live_host_fingerprints SET is_current = FALSE, last_seen = NOW() WHERE live_host_id = $1 AND is_current = TRUE",
                    live_host_id,
                )

            await conn.execute(
                """
                INSERT INTO live_host_fingerprints (
                  live_host_id,
                  fingerprint_hash,
                  status_code,
                  title,
                  webserver,
                  content_length,
                  technologies,
                  metadata,
                  is_current
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, TRUE)
                ON CONFLICT (live_host_id, fingerprint_hash)
                DO UPDATE SET last_seen = NOW(), is_current = TRUE
                """,
                live_host_id,
                fingerprint_hash,
                payload.get("status_code"),
                payload.get("title"),
                payload.get("webserver"),
                payload.get("content_length"),
                json.dumps(techs),
                json.dumps(fingerprint_material),
            )

        if changed:
            location = payload.get("url") or f"live_host:{live_host_id}"
            self.append_summary(
                summary,
                "changed_fingerprints",
                {
                    "url": location,
                    "status_code": payload.get("status_code"),
                    "webserver": payload.get("webserver"),
                },
            )
            await self.save_finding(
                domain_id,
                "host_fingerprint_changed",
                "info",
                location,
                fingerprint_material,
                summary,
            )
        return changed

    async def save_finding(
        self,
        domain_id: int | None,
        finding_type: str,
        severity: str,
        location: str,
        details: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> int | None:
        assert self.db_pool is not None
        finding_key = hashlib.sha256(
            f"{domain_id}|{finding_type}|{location}|{json.dumps(details, sort_keys=True)}".encode()
        ).hexdigest()
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO findings (domain_id, finding_key, finding_type, severity, location, details)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                ON CONFLICT (finding_key)
                DO UPDATE SET last_seen = NOW(), is_resolved = FALSE
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                finding_key,
                finding_type,
                severity,
                location,
                json.dumps(details),
            )

        if row and row["inserted"]:
            FINDINGS_FOUND.inc()
            self.append_summary(
                summary,
                "findings",
                {"finding_type": finding_type, "severity": severity, "location": location, "details": details},
            )
            return int(row["id"])
        return None

    async def send_alert(
        self,
        alert_type: str,
        message: str,
        payload: dict[str, Any],
        finding_id: int | None = None,
    ) -> None:
        assert self.db_pool is not None

        if self.redis_client is not None:
            key = f"alert:{hashlib.sha1(message.encode()).hexdigest()}"
            if self.redis_client.get(key):
                return
            self.redis_client.setex(key, 1800, "1")

        async with self.db_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO alerts (finding_id, alert_type, message, payload) VALUES ($1, $2, $3, $4::jsonb)",
                finding_id,
                alert_type,
                message,
                json.dumps(payload),
            )

        for url in self.config.alerts.get("webhook_urls", []):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    await session.post(url, json={"type": alert_type, "message": message, "payload": payload})
            except Exception as exc:
                logger.warning("Webhook alert failed: %s", exc)

        telegram = self.config.alerts.get("telegram", {})
        if telegram.get("enabled") and telegram.get("bot_token") and telegram.get("chat_id"):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    for part in chunk_message(message):
                        async with session.post(
                            f"https://api.telegram.org/bot{telegram['bot_token']}/sendMessage",
                            data={"chat_id": telegram["chat_id"], "text": part},
                        ) as response:
                            if response.status >= 400:
                                body = await response.text()
                                logger.warning("Telegram alert failed: status=%s body=%s", response.status, body[:300])
            except Exception as exc:
                logger.warning("Telegram alert failed: %r", exc)

        smtp_cfg = self.config.alerts.get("smtp", {})
        if smtp_cfg.get("enabled"):
            try:
                msg = EmailMessage()
                msg["Subject"] = f"Recon alert: {alert_type}"
                msg["From"] = smtp_cfg["from_email"]
                msg["To"] = ", ".join(smtp_cfg["to_emails"])
                msg.set_content(f"{message}\n\n{json.dumps(payload, indent=2)}")
                with smtplib.SMTP(smtp_cfg["server"], smtp_cfg["port"]) as server:
                    server.starttls()
                    server.login(smtp_cfg["username"], smtp_cfg["password"])
                    server.send_message(msg)
            except Exception as exc:
                logger.warning("SMTP alert failed: %s", exc)

    async def save_url_parameters(
        self,
        domain_id: int,
        endpoint_id: int,
        full_url: str,
        source: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        parsed = urlsplit(full_url)
        path = parsed.path or "/"
        parameters = extract_query_parameters(full_url)
        if not parameters:
            return

        for item in parameters:
            async with self.db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO url_parameters (endpoint_id, param_name, example_value, risk_tags)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (endpoint_id, param_name)
                    DO UPDATE SET last_seen = NOW(), example_value = EXCLUDED.example_value, risk_tags = EXCLUDED.risk_tags
                    RETURNING id, (xmax = 0) AS inserted
                    """,
                    endpoint_id,
                    item["name"],
                    item["example_value"],
                    item["risk_tags"],
                )

            if row and row["inserted"] and item["risk_tags"]:
                RISKY_PARAMS_FOUND.inc()
                severity = severity_for_param_tags(item["risk_tags"], item["name"], item["example_value"], path)
                await self.save_finding(
                    domain_id,
                    "risky_url_parameter",
                    severity,
                    full_url,
                    {
                        "parameter": item["name"],
                        "example_value": item["example_value"],
                        "risk_tags": item["risk_tags"],
                        "source": source,
                    },
                    summary,
                )

    async def save_endpoint(
        self,
        domain_id: int,
        live_host_id: int,
        full_url: str,
        source: str,
        summary: dict[str, Any] | None = None,
    ) -> int:
        assert self.db_pool is not None
        parsed = urlsplit(full_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        parameter_payload = extract_query_parameters(full_url)
        risk_tags = sorted({tag for item in parameter_payload for tag in item["risk_tags"]})
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO endpoints (live_host_id, path, method, parameters, risk_tags, source)
                VALUES ($1, $2, 'GET', $3::jsonb, $4, $5)
                ON CONFLICT (live_host_id, path, method, source)
                DO UPDATE SET last_seen = NOW(), parameters = EXCLUDED.parameters, risk_tags = EXCLUDED.risk_tags
                RETURNING id, (xmax = 0) AS inserted
                """,
                live_host_id,
                path,
                json.dumps(parameter_payload),
                risk_tags,
                source,
            )

        endpoint_id = int(row["id"])
        await self.save_url_parameters(domain_id, endpoint_id, full_url, source, summary)

        if row and row["inserted"]:
            ENDPOINTS_FOUND.inc()
            self.append_summary(summary, "new_urls", {"url": full_url, "source": source, "risk_tags": risk_tags})
        return endpoint_id

    async def discover_wayback_urls(self, hostname: str, limit: int) -> list[str]:
        wayback_binary = self.config.tools.get("waybackurls", "waybackurls")
        stdout = await self.run_tool(wayback_binary, stdin_text=f"{hostname}\n")
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)
        return urls[:limit]

    async def discover_gau_urls(self, hostname: str, limit: int) -> list[str]:
        gau_binary = self.config.tools.get("gau", "gau")
        stdout = await self.run_tool(gau_binary, "--threads", "2", hostname)
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)
        return urls[:limit]

    async def discover_katana_urls(self, url: str, limit: int) -> list[str]:
        katana_binary = self.config.tools.get("katana", "katana")
        stdout = await self.run_tool(
            katana_binary,
            "-u",
            url,
            "-d",
            str(self.config.scan.get("katana_depth", 1)),
            "-silent",
        )
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)
        return urls[:limit]

    async def discover_hakrawler_urls(self, url: str, limit: int) -> list[str]:
        hakrawler_binary = self.config.tools.get("hakrawler", "hakrawler")
        stdout = await self.run_tool(hakrawler_binary, "-url", url, "-depth", "1", "-plain")
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)
        return urls[:limit]

    async def discover_urls_for_host(self, domain_info: dict[str, Any], live_host: dict[str, Any]) -> list[str]:
        hostname = urlsplit(live_host["url"]).hostname or live_host["url"]
        max_wayback = self.domain_int(domain_info, "max_wayback_urls", int(self.config.scan["max_wayback_urls_per_host"]))
        max_urls = int(self.config.scan.get("max_discovered_urls_per_host", 500))
        tasks = [self.discover_wayback_urls(hostname, max_wayback)]
        if self.domain_bool(domain_info, "enable_gau", self.config.scan.get("enable_gau", True)):
            tasks.append(self.discover_gau_urls(hostname, int(self.config.scan.get("gau_max_urls_per_host", 200))))
        if self.domain_bool(domain_info, "enable_katana", self.config.scan.get("enable_katana", False)):
            tasks.append(self.discover_katana_urls(live_host["url"], int(self.config.scan.get("katana_max_urls_per_host", 100))))
        if self.domain_bool(domain_info, "enable_hakrawler", self.config.scan.get("enable_hakrawler", False)):
            tasks.append(self.discover_hakrawler_urls(live_host["url"], int(self.config.scan.get("hakrawler_max_urls_per_host", 100))))

        discovered: list[str] = []
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, Exception):
                continue
            discovered.extend(result)

        deduped: list[str] = []
        seen = set()
        for item in discovered:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped[:max_urls]

    async def fetch_html(self, url: str) -> str:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True) as response:
                    content_type = response.headers.get("content-type", "").lower()
                    if response.status >= 400 or "html" not in content_type:
                        return ""
                    return await response.text(errors="ignore")
        except Exception:
            return ""

    async def download_js(self, asset_url: str) -> tuple[int | None, bytes | None]:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["js_download_timeout_seconds"])
        max_bytes = int(self.config.scan["js_max_download_bytes"])
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(asset_url, allow_redirects=True) as response:
                    body = await response.content.read(max_bytes + 1)
                    if len(body) > max_bytes:
                        logger.info("Skipping oversized JS asset: %s", asset_url)
                        return response.status, None
                    return response.status, body
        except Exception:
            return None, None

    async def store_js_analysis(
        self,
        domain_id: int,
        live_host_id: int,
        js_asset_id: int,
        asset_url: str,
        source_text: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        signals = extract_js_signals(source_text)
        risk_summary = {
            "api_url_count": len(signals["api_urls"]),
            "endpoint_path_count": len(signals["endpoint_paths"]),
            "graphql_hint_count": len(signals["graphql_hints"]),
            "auth_keyword_count": len(signals["auth_related_keywords"]),
            "dom_sink_count": len(signals["dangerous_dom_sinks"]),
            "location_source_count": len(signals["location_sources"]),
            "postmessage_count": len(signals["postmessage_usage"]),
            "storage_count": len(signals["storage_usage"]),
            "fetch_xhr_count": len(signals["fetch_xhr_usage"]),
        }
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO js_analysis_results (js_asset_id, extraction, risk_summary, analyzed_at)
                VALUES ($1, $2::jsonb, $3::jsonb, NOW())
                ON CONFLICT (js_asset_id)
                DO UPDATE SET extraction = EXCLUDED.extraction, risk_summary = EXCLUDED.risk_summary, analyzed_at = NOW()
                """,
                js_asset_id,
                json.dumps(signals),
                json.dumps(risk_summary),
            )

        for endpoint in signals["api_urls"] + signals["endpoint_paths"]:
            target = endpoint if endpoint.startswith(("http://", "https://")) else urljoin(asset_url, endpoint)
            await self.save_endpoint(domain_id, live_host_id, target, "js_analysis", summary)

        for finding in severity_for_js_signals(signals):
            await self.save_finding(
                domain_id,
                finding["finding_type"],
                finding["severity"],
                asset_url,
                finding["details"],
                summary,
            )

    async def save_js_asset(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        asset_url: str,
        source: str,
        summary: dict[str, Any] | None = None,
    ) -> int | None:
        assert self.db_pool is not None
        http_status, body = await self.download_js(asset_url)
        sha256 = hashlib.sha256(body).hexdigest() if body is not None else None
        size_bytes = len(body) if body is not None else None

        async with self.db_pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT id, sha256 FROM js_assets WHERE live_host_id = $1 AND asset_url = $2",
                live_host_id,
                asset_url,
            )
            row = await conn.fetchrow(
                """
                INSERT INTO js_assets (live_host_id, asset_url, source, sha256, size_bytes, http_status)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (live_host_id, asset_url)
                DO UPDATE SET last_seen = NOW(), sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes, http_status = EXCLUDED.http_status
                RETURNING id, (xmax = 0) AS inserted
                """,
                live_host_id,
                asset_url,
                source,
                sha256,
                size_bytes,
                http_status,
            )

        is_new = bool(row and row["inserted"])
        is_changed = bool(body is not None and existing is not None and existing["sha256"] not in (None, sha256) and sha256 is not None)

        if is_new:
            JS_ASSETS_FOUND.inc()
            self.append_summary(summary, "new_js_assets", {"asset_url": asset_url, "source": source, "sha256": sha256})
        elif is_changed:
            self.append_summary(summary, "changed_js_assets", {"asset_url": asset_url, "source": source, "sha256": sha256})
            await self.save_finding(
                domain_info["id"],
                "js_asset_changed",
                "info",
                asset_url,
                {"source": source, "sha256": sha256},
                summary,
            )

        if body is not None and self.domain_bool(domain_info, "enable_js_analysis", self.config.scan.get("analyze_js_assets", True)) and (is_new or is_changed):
            try:
                await self.store_js_analysis(
                    domain_info["id"],
                    live_host_id,
                    int(row["id"]),
                    asset_url,
                    body.decode("utf-8", errors="ignore"),
                    summary,
                )
            except Exception as exc:
                logger.warning("JS analysis failed for %s: %s", asset_url, exc)

        return int(row["id"]) if row else None

    async def save_screenshot_record(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        url: str,
        screenshot_path: Path,
        capture_reason: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        if not screenshot_path.is_file():
            return
        data = screenshot_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        relative_path = str(screenshot_path.relative_to(SCREENSHOT_ROOT))
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO screenshots (live_host_id, screenshot_path, sha256, file_size, capture_reason)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (live_host_id, screenshot_path)
                DO UPDATE SET last_seen = NOW(), sha256 = EXCLUDED.sha256, file_size = EXCLUDED.file_size, capture_reason = EXCLUDED.capture_reason
                RETURNING id, (xmax = 0) AS inserted
                """,
                live_host_id,
                relative_path,
                sha256,
                screenshot_path.stat().st_size,
                capture_reason,
            )
        if row and row["inserted"]:
            SCREENSHOTS_CAPTURED.inc()
            self.append_summary(summary, "new_screenshots", {"url": url, "screenshot_path": relative_path})

    async def capture_screenshot(
        self,
        domain_info: dict[str, Any],
        live_host: dict[str, Any],
        capture_reason: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.domain_bool(domain_info, "enable_screenshots", self.config.scan.get("screenshots_enabled", True)):
            return

        gowitness_binary = self.config.tools.get("gowitness", "gowitness")
        target_url = live_host["url"]
        host_slug = domain_slug(urlsplit(target_url).hostname or "host")
        destination = SCREENSHOT_ROOT / domain_slug(domain_info["domain"])
        destination.mkdir(parents=True, exist_ok=True)
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{host_slug}.png"
        await self.run_tool(
            gowitness_binary,
            "single",
            "--destination",
            str(destination),
            "-o",
            filename,
            target_url,
        )
        await self.save_screenshot_record(domain_info, live_host["live_host_id"], target_url, destination / filename, capture_reason, summary)

    async def probe_common_paths(
        self,
        domain_id: int,
        live_host: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for path in self.config.scan["common_paths"]:
                target = live_host["url"].rstrip("/") + path
                try:
                    async with session.get(target, allow_redirects=True) as response:
                        if response.status < 500:
                            await self.save_endpoint(domain_id, live_host["live_host_id"], target, "common_path_probe", summary)
                            if path in {"/.env", "/.git/HEAD", "/swagger", "/swagger.json", "/v2/api-docs"} and response.status == 200:
                                await self.save_finding(
                                    domain_id,
                                    "interesting_exposed_path",
                                    "medium",
                                    target,
                                    {"status_code": response.status, "source": "common_path_probe"},
                                    summary,
                                )
                except Exception:
                    continue

    async def run_directory_bruteforce(
        self,
        domain_info: dict[str, Any],
        domain_id: int,
        live_host: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.domain_bool(domain_info, "enable_ffuf", self.config.scan.get("directory_bruteforce_enabled", False)):
            return

        wordlist = Path(self.config.scan.get("ffuf_wordlist", "/app/wordlists/commons.txt"))
        if not wordlist.is_file():
            logger.info("Skipping ffuf for %s, wordlist not found: %s", live_host["url"], wordlist)
            return

        ffuf_binary = self.config.tools.get("ffuf", "ffuf")
        stdout = await self.run_tool(
            ffuf_binary,
            "-w",
            str(wordlist),
            "-u",
            f"{live_host['url'].rstrip('/')}/FUZZ",
            "-mc",
            ",".join(str(status) for status in self.config.scan.get("ffuf_match_status", [200, 204, 301, 302, 307, 308, 401, 403])),
            "-t",
            str(self.config.scan.get("ffuf_threads", 10)),
            "-rate",
            str(self.config.scan.get("ffuf_rate", 30)),
            "-timeout",
            str(self.config.scan.get("ffuf_timeout_seconds", 10)),
            "-noninteractive",
            "-json",
        )
        if not stdout:
            return

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = payload.get("url")
            status = payload.get("status")
            if not url or status is None:
                continue
            await self.save_endpoint(domain_id, live_host["live_host_id"], url, "ffuf", summary)
            if int(status) in {401, 403}:
                await self.save_finding(
                    domain_id,
                    "interesting_bruteforce_hit",
                    "info",
                    url,
                    {"status_code": status, "source": "ffuf"},
                    summary,
                )

    async def run_nuclei_scan(
        self,
        domain_info: dict[str, Any],
        domain_id: int,
        live_host: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.domain_bool(domain_info, "enable_nuclei", self.config.scan.get("nuclei_enabled", False)):
            return
        if self.config.scan.get("nuclei_only_on_new_live_hosts", True) and not live_host.get("is_new_live_host", False):
            return

        nuclei_binary = self.config.tools.get("nuclei", "nuclei")
        severities = self.config.scan.get("nuclei_severities", ["critical", "high", "medium"])
        args = [
            nuclei_binary,
            "-target",
            live_host["url"],
            "-jsonl",
            "-duc",
            "-rl",
            str(self.config.scan.get("nuclei_rate_limit", 20)),
            "-c",
            str(self.config.scan.get("nuclei_concurrency", 5)),
            "-bulk-size",
            str(self.config.scan.get("nuclei_bulk_size", 25)),
            "-timeout",
            str(self.config.scan.get("nuclei_timeout_seconds", 10)),
            "-retries",
            str(self.config.scan.get("nuclei_retries", 1)),
        ]
        if severities:
            args.extend(["-severity", ",".join(str(item) for item in severities)])
        templates_dir = self.config.scan.get("nuclei_templates_dir", "")
        if templates_dir:
            args.extend(["-t", templates_dir])

        stdout = await self.run_tool(*args)
        if not stdout:
            return

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = payload.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            matched_at = payload.get("matched-at") or payload.get("host") or live_host["url"]
            template_id = payload.get("template-id") or "unknown"
            await self.save_finding(
                domain_id,
                f"nuclei_{template_id}",
                severity,
                matched_at,
                {
                    "template_id": template_id,
                    "template_name": info.get("name"),
                    "severity": severity,
                    "matcher_name": payload.get("matcher-name"),
                    "matched_at": matched_at,
                    "type": payload.get("type"),
                    "tags": info.get("tags") or [],
                    "description": info.get("description"),
                },
                summary,
            )

    async def process_live_host(
        self,
        domain_info: dict[str, Any],
        host: dict[str, Any],
        summary: dict[str, Any] | None = None,
        run_ffuf: bool = False,
    ) -> None:
        async with self.live_host_semaphore:
            if host.get("is_new_live_host"):
                await self.capture_screenshot(domain_info, host, "new_live_host", summary)
            elif host.get("fingerprint_changed") and self.config.scan.get("screenshots_on_fingerprint_change", True):
                await self.capture_screenshot(domain_info, host, "fingerprint_change", summary)

            discovered_urls = await self.discover_urls_for_host(domain_info, host)
            for endpoint in discovered_urls:
                await self.save_endpoint(domain_info["id"], host["live_host_id"], endpoint, "historical_or_crawl", summary)

            js_urls = [url for url in discovered_urls if looks_like_js_url(url)]
            html = await self.fetch_html(host["url"])
            if html:
                js_urls.extend(extract_script_urls_from_html(host["url"], html))

            unique_js_urls: list[str] = []
            seen = set()
            for item in js_urls:
                if item not in seen:
                    seen.add(item)
                    unique_js_urls.append(item)

            max_js_assets = self.domain_int(domain_info, "max_js_assets", int(self.config.scan["max_js_assets_per_host"]))
            for asset_url in unique_js_urls[:max_js_assets]:
                await self.save_js_asset(domain_info, host["live_host_id"], asset_url, "html_or_historical", summary)

            await self.probe_common_paths(domain_info["id"], host, summary)
            if run_ffuf and self.domain_bool(domain_info, "enable_ffuf", False):
                await self.run_directory_bruteforce(domain_info, domain_info["id"], host, summary)
            if self.domain_bool(domain_info, "enable_nuclei", False):
                await self.run_nuclei_scan(domain_info, domain_info["id"], host, summary)

    async def collect_domain_totals(self, domain_id: int) -> dict[str, int]:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                  (SELECT COUNT(*) FROM subdomains s WHERE s.domain_id = $1) AS subdomains,
                  (SELECT COUNT(*)
                   FROM live_hosts lh
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS live_hosts,
                  (SELECT COUNT(*)
                   FROM endpoints e
                   JOIN live_hosts lh ON lh.id = e.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS endpoints,
                  (SELECT COUNT(*)
                   FROM js_assets ja
                   JOIN live_hosts lh ON lh.id = ja.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS js_assets,
                  (SELECT COUNT(*)
                   FROM url_parameters up
                   JOIN endpoints e ON e.id = up.endpoint_id
                   JOIN live_hosts lh ON lh.id = e.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1 AND cardinality(up.risk_tags) > 0) AS risky_params,
                  (SELECT COUNT(*)
                   FROM findings f
                   WHERE f.domain_id = $1) AS findings,
                  (SELECT COUNT(*)
                   FROM findings f
                   WHERE f.domain_id = $1 AND f.finding_type LIKE 'nuclei_%') AS nuclei_hits,
                  (SELECT COUNT(*)
                   FROM screenshots sc
                   JOIN live_hosts lh ON lh.id = sc.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS screenshots
                """,
                domain_id,
            )
            return {key: int(value or 0) for key, value in dict(row).items()}

    async def record_scan_snapshot(
        self,
        domain_info: dict[str, Any],
        scan_started_at: datetime,
        scan_finished_at: datetime,
        duration_seconds: float,
        summary: dict[str, Any],
    ) -> None:
        assert self.db_pool is not None
        totals = await self.collect_domain_totals(domain_info["id"])
        new_counts = {
            "new_subdomains": len(summary["new_subdomains"]),
            "new_live_hosts": len(summary["new_live_hosts"]),
            "new_urls": len(summary["new_urls"]),
            "new_js_assets": len(summary["new_js_assets"]),
            "changed_js_assets": len(summary["changed_js_assets"]),
            "changed_fingerprints": len(summary["changed_fingerprints"]),
            "new_screenshots": len(summary["new_screenshots"]),
            "new_findings": len(summary["findings"]),
        }
        metadata = {
            "organization": domain_info.get("organization"),
            "include_subdomains": domain_info.get("include_subdomains"),
        }
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scan_snapshots (
                  domain_id,
                  scan_started_at,
                  scan_finished_at,
                  duration_seconds,
                  first_run,
                  totals,
                  new_counts,
                  metadata
                )
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb)
                """,
                domain_info["id"],
                scan_started_at,
                scan_finished_at,
                duration_seconds,
                bool(summary["first_run"]),
                json.dumps(totals),
                json.dumps(new_counts),
                json.dumps(metadata),
            )

    async def prune_old_data(self) -> None:
        assert self.db_pool is not None
        retention = self.config.retention
        alerts_days = int(retention.get("alerts_days", 30))
        snapshots_days = int(retention.get("snapshots_days", 120))
        screenshots_days = int(retention.get("screenshots_days", 60))
        fingerprints_days = int(retention.get("fingerprints_days", 120))

        cutoff_alerts = datetime.utcnow() - timedelta(days=alerts_days)
        cutoff_snapshots = datetime.utcnow() - timedelta(days=snapshots_days)
        cutoff_screenshots = datetime.utcnow() - timedelta(days=screenshots_days)
        cutoff_fingerprints = datetime.utcnow() - timedelta(days=fingerprints_days)

        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                "DELETE FROM screenshots WHERE captured_at < $1 RETURNING screenshot_path",
                cutoff_screenshots,
            )
            await conn.execute("DELETE FROM alerts WHERE sent_at < $1", cutoff_alerts)
            await conn.execute("DELETE FROM scan_snapshots WHERE scan_finished_at < $1", cutoff_snapshots)
            await conn.execute(
                "DELETE FROM live_host_fingerprints WHERE is_current = FALSE AND last_seen < $1",
                cutoff_fingerprints,
            )

        for row in rows:
            try:
                path = SCREENSHOT_ROOT / str(row["screenshot_path"])
                if path.is_file():
                    path.unlink()
            except OSError:
                continue

    async def maybe_run_maintenance(self) -> None:
        interval_minutes = int(self.config.retention.get("maintenance_interval_minutes", 60))
        now = datetime.utcnow()
        if self.last_maintenance_run and now - self.last_maintenance_run < timedelta(minutes=interval_minutes):
            return
        await self.prune_old_data()
        self.last_maintenance_run = now

    async def run_domain_scan(self, domain_info: dict[str, Any]) -> None:
        async with self.scan_semaphore:
            domain = domain_info["domain"]
            first_run = domain_info["last_scan"] is None
            summary = new_scan_summary(domain, first_run)
            started_at = datetime.utcnow()
            logger.info("Scanning %s", domain)

            try:
                subdomains = sorted(await self.enumerate_subdomains(domain_info))
                if not subdomains:
                    await self.update_domain_last_scan(domain_info["id"])
                    finished_at = datetime.utcnow()
                    duration = (finished_at - started_at).total_seconds()
                    await self.record_scan_snapshot(domain_info, started_at, finished_at, duration, summary)
                    if first_run:
                        await self.send_alert(
                            "scan_summary",
                            self.build_scan_summary_message(summary, duration),
                            {"domain_id": domain_info["id"], **summary, "duration_seconds": duration},
                        )
                    return

                live_hosts = await self.probe_live_hosts(domain_info, subdomains, summary)
                if live_hosts:
                    max_ffuf_hosts = int(self.config.scan.get("ffuf_max_hosts_per_domain", 3))
                    await asyncio.gather(
                        *(
                            self.process_live_host(
                                domain_info,
                                host,
                                summary,
                                run_ffuf=index < max_ffuf_hosts,
                            )
                            for index, host in enumerate(live_hosts)
                        )
                    )

                await self.update_domain_last_scan(domain_info["id"])
                finished_at = datetime.utcnow()
                duration = (finished_at - started_at).total_seconds()
                SCAN_DURATION.set(duration)
                await self.record_scan_snapshot(domain_info, started_at, finished_at, duration, summary)
                if first_run or self.summary_has_changes(summary):
                    await self.send_alert(
                        "scan_summary",
                        self.build_scan_summary_message(summary, duration),
                        {"domain_id": domain_info["id"], **summary, "duration_seconds": duration},
                    )
                logger.info("Finished %s in %.2fs", domain, duration)
            except Exception as exc:
                logger.exception("Scan failed for %s: %s", domain, exc)
                await self.send_alert(
                    "scan_error",
                    f"Recon scan failed: {domain}",
                    {"domain_id": domain_info["id"], "domain": domain, "error": repr(exc)},
                )

    async def continuous_loop(self) -> None:
        while True:
            await self.maybe_run_maintenance()
            domains = await self.get_domains_to_scan()
            if not domains:
                await asyncio.sleep(self.config.scan["idle_sleep_seconds"])
                continue
            await asyncio.gather(*(self.run_domain_scan(domain) for domain in domains))
            await asyncio.sleep(5)


async def main() -> None:
    config = load_config()
    start_http_server(config.scan["metrics_port"])
    framework = ContinuousReconFramework(config)
    await framework.init()
    await framework.continuous_loop()


if __name__ == "__main__":
    asyncio.run(main())
