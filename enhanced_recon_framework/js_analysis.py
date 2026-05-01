from __future__ import annotations

import re
from html import unescape
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse


ABSOLUTE_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
PATH_RE = re.compile(r"(?<![:A-Za-z0-9])/(?:[A-Za-z0-9._~:%@${}-]+/){0,12}[A-Za-z0-9._~:%@${}-]*(?:\?[A-Za-z0-9=&_.~:%@${}-]+)?")
QUOTED_ENDPOINT_RE = re.compile(r'''(?:"([^"\r\n]{1,240})"|'([^'\r\n]{1,240})'|`([^`\r\n]{1,240})`)''')
GRAPHQL_RE = re.compile(r"\b(?:graphql|gql|query|mutation|subscription|fragment|__schema|__typename)\b", re.I)
AUTH_RE = re.compile(
    r"\b(?:auth|authorization|bearer|login|logout|signup|signin|oauth|sso|jwt|token|refresh[_-]?token|access[_-]?token|password|passwd|apikey|api[_-]?key|secret)\b",
    re.I,
)
SECRET_RE = re.compile(
    r"(?:"
    r"(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{8,}['\"]"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_\-]{20,}"
    r"|sk_(?:live|test)_[0-9A-Za-z]{16,}"
    r"|Bearer\s+[A-Za-z0-9._\-+/=]{12,}"
    r")",
    re.I,
)
DOM_SINK_RE = re.compile(
    r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|eval|new\s+Function|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"])\b",
    re.I,
)
POSTMESSAGE_RE = re.compile(r"\b(?:postMessage|addEventListener\s*\(\s*['\"]message['\"]|onmessage\b)\b", re.I)
STORAGE_RE = re.compile(r"\b(?:localStorage|sessionStorage|indexedDB|document\.cookie)\b", re.I)
FETCH_XHR_RE = re.compile(
    r"\b(?:fetch\s*\(|XMLHttpRequest|axios(?:\.[a-z]+)?\s*\(|\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH)|\$.ajax\s*\()",
    re.I,
)
LOCATION_SOURCE_RE = re.compile(
    r"\b(?:location(?:\.href|\.search|\.hash|\.pathname)?|document\.URL|documentURI|window\.name)\b",
    re.I,
)
SENSITIVE_TERM_RE = re.compile(
    r"\b(?:webhook|admin|invite|invitation|export|role|roles|permission|permissions|impersonat(?:e|ion)|tenant|organization|org|billing|user[_-]?management)\b",
    re.I,
)
GRAPHQL_ENDPOINT_RE = re.compile(r"/graphql\b|graphql", re.I)
API_HINT_RE = re.compile(r"/api(?:/[A-Za-z0-9._~%-]+)*|/v[0-9]+(?:/[A-Za-z0-9._~%-]+)*", re.I)
API_SUBSTRING_RE = re.compile(r"/(?:api|graphql|oauth|auth|login|logout|signup|signin|admin|invite|role|permission|export|import|webhook|callback|token|session|profile|account|user|member|org|team|billing|payment|checkout|order|search|report|setting|notification|upload|download|file|attachment)(?:/[A-Za-z0-9._~:%@${}-]+){0,12}", re.I)
ROUTE_HINT_RE = re.compile(
    r"(?:^|/)(?:api|graphql|rest|rpc|service|services|auth|oauth|login|logout|signup|signin|admin|user|users|account|accounts|invite|invites|role|roles|permission|permissions|export|imports?|webhook|hooks|callback|callbacks|token|tokens|session|sessions|profile|profiles|org|organization|organizations|team|teams|member|members|billing|payments?|checkout|cart|orders?|search|reports?|settings|notifications?|upload|download|files?|attachments?)(?:/|$)",
    re.I,
)
EXTENSION_NOISE_RE = re.compile(r"\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|html?)$", re.I)
PATH_KEYWORD_RE = re.compile(
    r"(?:^|[_/\-.])(?:api|graphql|auth|oauth|login|logout|signup|signin|admin|invite|role|permission|export|import|webhook|callback|token|session|profile|account|user|member|org|team|billing|payment|checkout|order|search|report|setting|notification|upload|download|file|attachment)(?:s)?(?:$|[_/\-.])",
    re.I,
)
REGEX_LIKE_RE = re.compile(r"[()[\]{}^$|*+]|/[gimsuy]{1,6}$")
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
INLINE_JS_URL_RE = re.compile(r"https?://[^\s\"']+\.js(?:[?#][^\s\"']*)?|/[^\"'\s]+\.js(?:[?#][^\s\"']*)?", re.I)

XSS_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:q|query|search|keyword|term|name|title|message|comment|content|body|text|html|template|view|return|next|redirect|redirect_uri|callback)(?:$|[_-])",
    re.I,
)
IDOR_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:id|user|user_id|account|account_id|org|org_id|tenant|tenant_id|project|project_id|workspace|workspace_id|team|team_id|group|group_id|member|member_id|file|file_id|doc|doc_id|document|document_id|order|order_id|invoice|invoice_id|ticket|ticket_id)(?:$|[_-])",
    re.I,
)
SSRF_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:url|uri|dest|destination|redirect|redirect_uri|return|return_to|next|continue|callback|callback_url|endpoint|feed|image|image_url|avatar|link|target|proxy|webhook)(?:$|[_-])",
    re.I,
)


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def normalize_candidate(value: str) -> str:
    value = unescape(value.strip())
    value = value.replace("\\/", "/").replace("\\u002F", "/").replace("\\x2F", "/")
    value = re.sub(r"\s+", "", value)
    return value.rstrip(";,.)]}\"'")


def looks_like_endpoint_candidate(value: str) -> bool:
    if not value or len(value) < 4 or len(value) > 240:
        return False
    if " " in value or value.startswith("//"):
        return False
    if not (value.startswith("/") or value.startswith("http://") or value.startswith("https://")):
        return False
    if value in {"/", "//"}:
        return False
    path_part = urlparse(value).path if value.startswith(("http://", "https://")) else value
    if EXTENSION_NOISE_RE.search(path_part):
        return False
    if any(ch in value for ch in ("<", ">", "|")):
        return False
    if REGEX_LIKE_RE.search(value):
        return False
    if API_HINT_RE.search(value) or GRAPHQL_ENDPOINT_RE.search(value) or ROUTE_HINT_RE.search(value):
        return True
    segments = [segment for segment in value.split("/") if segment]
    if len(segments) >= 2:
        return True
    return bool(PATH_KEYWORD_RE.search(value))


def extract_endpoint_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for regex in (ABSOLUTE_URL_RE, PATH_RE, API_SUBSTRING_RE):
        for match in regex.finditer(text):
            candidate = normalize_candidate(match.group(0))
            if looks_like_endpoint_candidate(candidate):
                candidates.append(candidate)

    for match in QUOTED_ENDPOINT_RE.finditer(text):
        candidate = normalize_candidate(next(group for group in match.groups() if group is not None))
        if looks_like_endpoint_candidate(candidate):
            candidates.append(candidate)

    return dedupe_keep_order(candidates)


def unique_matches(regex: re.Pattern[str], text: str, limit: int = 200) -> list[str]:
    return dedupe_keep_order([match.group(0) for match in regex.finditer(text)])[:limit]


def extract_js_signals(text: str) -> dict[str, list[str]]:
    absolute_urls = unique_matches(ABSOLUTE_URL_RE, text)
    endpoint_candidates = extract_endpoint_candidates(text)
    api_urls = [value for value in endpoint_candidates if value.startswith(("http://", "https://"))]
    endpoint_paths = [value for value in endpoint_candidates if value.startswith("/")]
    return {
        "absolute_urls": absolute_urls,
        "api_urls": api_urls,
        "endpoint_paths": endpoint_paths,
        "graphql_hints": unique_matches(GRAPHQL_RE, text),
        "auth_related_keywords": unique_matches(AUTH_RE, text),
        "tokens_or_secret_like_strings": unique_matches(SECRET_RE, text),
        "dangerous_dom_sinks": unique_matches(DOM_SINK_RE, text),
        "location_sources": unique_matches(LOCATION_SOURCE_RE, text),
        "postmessage_usage": unique_matches(POSTMESSAGE_RE, text),
        "storage_usage": unique_matches(STORAGE_RE, text),
        "fetch_xhr_usage": unique_matches(FETCH_XHR_RE, text),
        "sensitive_terms": unique_matches(SENSITIVE_TERM_RE, text),
    }


def extract_script_urls_from_html(base_url: str, html: str) -> list[str]:
    results: list[str] = []
    for match in SCRIPT_SRC_RE.finditer(html):
        results.append(urljoin(base_url, match.group(1)))
    for match in INLINE_JS_URL_RE.finditer(html):
        results.append(urljoin(base_url, match.group(0)))
    return dedupe_keep_order([url for url in results if url.lower().endswith(".js") or ".js?" in url.lower()])


def looks_like_js_url(url: str) -> bool:
    lower = url.lower()
    return lower.endswith(".js") or ".js?" in lower


def classify_parameter_risks(name: str, value: str = "") -> list[str]:
    tags: list[str] = []
    lowered_value = value.lower()
    if XSS_PARAM_RE.search(name):
        tags.append("xss")
    if IDOR_PARAM_RE.search(name):
        tags.append("idor")
    if SSRF_PARAM_RE.search(name):
        tags.append("ssrf")
    if lowered_value.startswith(("http://", "https://")) and "ssrf" not in tags and XSS_PARAM_RE.search(name):
        tags.append("ssrf")
    return tags


def extract_query_parameters(url: str) -> list[dict[str, Any]]:
    parsed = urlparse(url)
    params = []
    seen = set()
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        params.append(
            {
                "name": name,
                "example_value": value,
                "risk_tags": classify_parameter_risks(name, value),
            }
        )
    return params


def severity_for_param_tags(tags: list[str], name: str = "", value: str = "", path: str = "") -> str:
    tag_set = set(tags)
    lowered_name = name.lower()
    lowered_value = value.lower()
    lowered_path = path.lower()
    if "ssrf" in tag_set and lowered_value.startswith(("http://", "https://")):
        return "high"
    if "ssrf" in tag_set:
        return "high"
    if "idor" in tag_set and any(marker in lowered_path for marker in ("/admin", "/api/", "/users", "/accounts", "/members")):
        return "high"
    if "xss" in tag_set and ("idor" in tag_set or lowered_name in {"html", "template", "redirect", "callback"}):
        return "high"
    if "xss" in tag_set and any(marker in lowered_value for marker in ("<", "%3c", "javascript:")):
        return "high"
    if "xss" in tag_set or "idor" in tag_set:
        return "medium"
    return "info"


def severity_for_js_signals(signals: dict[str, list[str]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if signals["tokens_or_secret_like_strings"]:
        findings.append(
            {
                "finding_type": "js_secret_like_strings",
                "severity": "high",
                "details": {"matches": signals["tokens_or_secret_like_strings"][:20]},
            }
        )
    if signals["dangerous_dom_sinks"]:
        findings.append(
            {
                "finding_type": "js_dom_xss_sinks",
                "severity": "medium",
                "details": {"matches": signals["dangerous_dom_sinks"][:20]},
            }
        )
    if signals["dangerous_dom_sinks"] and signals["location_sources"]:
        findings.append(
            {
                "finding_type": "js_dom_xss_candidate",
                "severity": "high",
                "details": {
                    "sinks": signals["dangerous_dom_sinks"][:20],
                    "sources": signals["location_sources"][:20],
                },
            }
        )
    if signals["sensitive_terms"] and (signals["api_urls"] or signals["endpoint_paths"]):
        findings.append(
            {
                "finding_type": "js_sensitive_admin_surface",
                "severity": "medium",
                "details": {
                    "sensitive_terms": signals["sensitive_terms"][:20],
                    "sample_endpoints": (signals["api_urls"] + signals["endpoint_paths"])[:20],
                },
            }
        )
    return findings
