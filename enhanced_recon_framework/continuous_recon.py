#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import smtplib
from dataclasses import dataclass
from datetime import datetime
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
RISKY_PARAMS_FOUND = Counter("risky_params_found_total", "Total risky URL parameters discovered")
FINDINGS_FOUND = Counter("findings_found_total", "Total findings discovered")
SCAN_DURATION = Gauge("scan_duration_seconds", "Most recent domain scan duration")


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


class ContinuousReconFramework:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.db_pool: asyncpg.Pool | None = None
        self.redis_client: redis.Redis | None = None
        self.scan_semaphore = asyncio.Semaphore(self.config.scan["max_concurrent_domains"])

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
                SELECT id, domain, organization, scan_interval_hours, last_scan
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

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
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

    async def enumerate_subdomains(self, domain: str) -> set[str]:
        tool_map = [
            (self.config.tools.get("assetfinder", "assetfinder"), [domain]),
            (self.config.tools.get("subfinder", "subfinder"), ["-d", domain, "-silent"]),
            (self.config.tools.get("findomain", "findomain"), ["-t", domain, "-q"]),
        ]
        tasks = [self.run_tool(binary, *args) for binary, args in tool_map]
        tasks.append(self.run_crtsh(domain))
        outputs = await asyncio.gather(*tasks, return_exceptions=True)

        subdomains: set[str] = set()
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

    async def save_subdomain(self, domain_id: int, subdomain: str) -> int:
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
            await self.send_alert(
                "new_subdomain",
                f"New subdomain discovered: {subdomain}",
                {"domain_id": domain_id, "subdomain": subdomain},
            )
        return int(row["id"])

    async def save_live_host(self, subdomain_id: int, payload: dict[str, Any]) -> int:
        assert self.db_pool is not None
        url = payload["url"]
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        title = payload.get("title") or None
        status_code = payload.get("status_code")

        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO live_hosts (subdomain_id, url, port, protocol, status_code, title)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (url)
                DO UPDATE SET last_seen = NOW(), status_code = EXCLUDED.status_code, title = EXCLUDED.title
                RETURNING id, (xmax = 0) AS inserted
                """,
                subdomain_id,
                url,
                port,
                parsed.scheme,
                status_code,
                title,
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
        return int(row["id"])

    async def probe_live_hosts(self, domain_id: int, subdomains: list[str]) -> list[dict[str, Any]]:
        httpx_binary = self.config.tools.get("httpx", "httpx")
        stdout = await self.run_tool(
            httpx_binary,
            "-json",
            "-silent",
            "-threads",
            "50",
            "-tech-detect",
            "-status-code",
            stdin_text="\n".join(subdomains),
        )
        if not stdout:
            return []

        results: list[dict[str, Any]] = []
        subdomain_ids = {sub: await self.save_subdomain(domain_id, sub) for sub in subdomains}
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
            live_host_id = await self.save_live_host(subdomain_ids[host], payload)
            payload["live_host_id"] = live_host_id
            results.append(payload)
        return results

    async def save_finding(
        self,
        domain_id: int | None,
        finding_type: str,
        severity: str,
        location: str,
        details: dict[str, Any],
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
            await self.send_alert(
                "finding",
                f"[{severity.upper()}] {finding_type} at {location}",
                details,
                int(row["id"]),
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
                    await session.post(
                        f"https://api.telegram.org/bot{telegram['bot_token']}/sendMessage",
                        data={"chat_id": telegram["chat_id"], "text": message},
                    )
            except Exception as exc:
                logger.warning("Telegram alert failed: %s", exc)

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
    ) -> None:
        assert self.db_pool is not None
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
                severity = severity_for_param_tags(item["risk_tags"])
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
                )

    async def save_endpoint(
        self,
        domain_id: int,
        live_host_id: int,
        full_url: str,
        source: str,
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
        await self.save_url_parameters(domain_id, endpoint_id, full_url, source)

        if row and row["inserted"]:
            ENDPOINTS_FOUND.inc()
            await self.send_alert(
                "new_url",
                f"New URL discovered: {full_url}",
                {
                    "domain_id": domain_id,
                    "live_host_id": live_host_id,
                    "url": full_url,
                    "source": source,
                    "risk_tags": risk_tags,
                },
            )
        return endpoint_id

    async def discover_wayback_urls(self, hostname: str) -> list[str]:
        wayback_binary = self.config.tools.get("waybackurls", "waybackurls")
        stdout = await self.run_tool(wayback_binary, stdin_text=f"{hostname}\n")
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
        limit = int(self.config.scan["max_wayback_urls_per_host"])
        return urls[:limit]

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
    ) -> None:
        assert self.db_pool is not None
        signals = extract_js_signals(source_text)
        risk_summary = {
            "api_url_count": len(signals["api_urls"]),
            "endpoint_path_count": len(signals["endpoint_paths"]),
            "graphql_hint_count": len(signals["graphql_hints"]),
            "auth_keyword_count": len(signals["auth_related_keywords"]),
            "dom_sink_count": len(signals["dangerous_dom_sinks"]),
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
            await self.save_endpoint(domain_id, live_host_id, target, "js_analysis")

        for finding in severity_for_js_signals(signals):
            await self.save_finding(
                domain_id,
                finding["finding_type"],
                finding["severity"],
                asset_url,
                finding["details"],
            )

    async def save_js_asset(
        self,
        domain_id: int,
        live_host_id: int,
        asset_url: str,
        source: str,
    ) -> int | None:
        assert self.db_pool is not None
        http_status, body = await self.download_js(asset_url)
        sha256 = hashlib.sha256(body).hexdigest() if body is not None else None
        size_bytes = len(body) if body is not None else None

        async with self.db_pool.acquire() as conn:
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

        if row and row["inserted"]:
            JS_ASSETS_FOUND.inc()
            await self.send_alert(
                "new_js_asset",
                f"New JS asset discovered: {asset_url}",
                {
                    "domain_id": domain_id,
                    "live_host_id": live_host_id,
                    "asset_url": asset_url,
                    "source": source,
                },
            )

        if body is not None and self.config.scan.get("analyze_js_assets", True):
            try:
                await self.store_js_analysis(
                    domain_id,
                    live_host_id,
                    int(row["id"]),
                    asset_url,
                    body.decode("utf-8", errors="ignore"),
                )
            except Exception as exc:
                logger.warning("JS analysis failed for %s: %s", asset_url, exc)

        return int(row["id"]) if row else None

    async def probe_common_paths(self, domain_id: int, live_host: dict[str, Any]) -> None:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for path in self.config.scan["common_paths"]:
                target = live_host["url"].rstrip("/") + path
                try:
                    async with session.get(target, allow_redirects=True) as response:
                        if response.status < 500:
                            await self.save_endpoint(domain_id, live_host["live_host_id"], target, "common_path_probe")
                            if path in {"/.env", "/.git/HEAD", "/swagger", "/swagger.json", "/v2/api-docs"} and response.status == 200:
                                await self.save_finding(
                                    domain_id,
                                    "interesting_exposed_path",
                                    "medium",
                                    target,
                                    {"status_code": response.status, "source": "common_path_probe"},
                                )
                except Exception:
                    continue

    async def process_live_host(self, domain_id: int, host: dict[str, Any]) -> None:
        hostname = urlsplit(host["url"]).hostname
        if not hostname:
            return

        wayback_urls = await self.discover_wayback_urls(hostname)
        for endpoint in wayback_urls:
            await self.save_endpoint(domain_id, host["live_host_id"], endpoint, "wayback")

        js_urls = [url for url in wayback_urls if looks_like_js_url(url)]
        html = await self.fetch_html(host["url"])
        if html:
            js_urls.extend(extract_script_urls_from_html(host["url"], html))

        unique_js_urls = []
        seen = set()
        for item in js_urls:
            if item not in seen:
                seen.add(item)
                unique_js_urls.append(item)

        for asset_url in unique_js_urls[: int(self.config.scan["max_js_assets_per_host"])]:
            await self.save_js_asset(domain_id, host["live_host_id"], asset_url, "html_or_wayback")

        await self.probe_common_paths(domain_id, host)

    async def run_domain_scan(self, domain_info: dict[str, Any]) -> None:
        async with self.scan_semaphore:
            domain = domain_info["domain"]
            domain_id = domain_info["id"]
            start = datetime.now()
            logger.info("Scanning %s", domain)

            try:
                subdomains = sorted(await self.enumerate_subdomains(domain))
                if not subdomains:
                    await self.update_domain_last_scan(domain_id)
                    return

                live_hosts = await self.probe_live_hosts(domain_id, subdomains)
                if live_hosts:
                    await asyncio.gather(*(self.process_live_host(domain_id, host) for host in live_hosts))

                await self.update_domain_last_scan(domain_id)
                duration = (datetime.now() - start).total_seconds()
                SCAN_DURATION.set(duration)
                logger.info("Finished %s in %.2fs", domain, duration)
            except Exception as exc:
                logger.exception("Scan failed for %s: %s", domain, exc)

    async def continuous_loop(self) -> None:
        while True:
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
