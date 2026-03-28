"""YAML template-based vulnerability scanner (Nuclei-compatible subset).

Loads YAML templates from ``src/pacdoor/templates/vulns/`` and runs every
template against each discovered HTTP service.  Templates describe a single
HTTP request plus a set of matchers (word, regex, status) that determine
whether the target is vulnerable.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import aiohttp
    _aiohttp_available = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    _aiohttp_available = False

try:
    import yaml
    _yaml_available = True
except ImportError:
    yaml = None  # type: ignore[assignment]
    _yaml_available = False

from pacdoor.core.models import (
    Evidence,
    ExploitSafety,
    Finding,
    Phase,
    Port,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Directory that holds the YAML template tree.
_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates" / "vulns"

# Per-request timeout in seconds.
_REQUEST_TIMEOUT = 10

# Maximum concurrent template checks.
_CONCURRENCY = 20

# Maximum bytes of response body to read (prevents huge allocations).
_MAX_BODY_BYTES = 512 * 1024  # 512 KiB

# Severity string -> models.Severity enum.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


# ── Template loading ─────────────────────────────────────────────────────


def _load_templates(root: Path) -> list[dict[str, Any]]:
    """Recursively load all ``.yaml`` / ``.yml`` files under *root*."""
    templates: list[dict[str, Any]] = []
    if not root.is_dir():
        log.debug("template dir %s does not exist, skipping", root)
        return templates

    for path in sorted(root.rglob("*.y*ml")):
        if path.suffix not in (".yaml", ".yml"):
            continue
        try:
            with path.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict) and "id" in data:
                data["_source_file"] = str(path)
                templates.append(data)
        except Exception:
            log.debug("failed to parse template %s", path, exc_info=True)
    return templates


# ── Matcher evaluation ───────────────────────────────────────────────────


def _get_part(resp_status: int, resp_headers: dict[str, str], resp_body: str, part: str) -> str:
    """Extract the portion of the response to match against."""
    part = (part or "body").lower()
    if part == "body":
        return resp_body
    if part == "header":
        return "\r\n".join(f"{k}: {v}" for k, v in resp_headers.items())
    if part == "status":
        return str(resp_status)
    # Fallback: treat unrecognised part as body.
    return resp_body


def _evaluate_matcher(
    matcher: dict[str, Any],
    resp_status: int,
    resp_headers: dict[str, str],
    resp_body: str,
) -> bool:
    """Return True if a single matcher block matches the response."""
    m_type = matcher.get("type", "word").lower()
    negative = bool(matcher.get("negative", False))
    part_text = _get_part(resp_status, resp_headers, resp_body, matcher.get("part"))

    matched = False
    if m_type == "word":
        words: list[str] = matcher.get("words", [])
        # Condition within the words list is implicitly OR (any word).
        matched = any(w in part_text for w in words) if words else False

    elif m_type == "regex":
        patterns: list[str] = matcher.get("regex", [])
        matched = any(re.search(p, part_text) is not None for p in patterns) if patterns else False

    elif m_type == "status":
        codes: list[int] = matcher.get("status", [])
        matched = resp_status in codes

    return (not matched) if negative else matched


def _evaluate_matchers(
    matchers: list[dict[str, Any]],
    condition: str,
    resp_status: int,
    resp_headers: dict[str, str],
    resp_body: str,
) -> bool:
    """Evaluate all matchers under the given condition (and/or)."""
    if not matchers:
        return False
    results = [
        _evaluate_matcher(m, resp_status, resp_headers, resp_body)
        for m in matchers
    ]
    if condition == "or":
        return any(results)
    # Default is "and".
    return all(results)


# ── Module ───────────────────────────────────────────────────────────────


class TemplateScannerModule(BaseModule):
    """YAML-template vulnerability scanner."""

    name = "vuln.template_scanner"
    description = "Nuclei-style YAML template vulnerability scanner"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1190"]
    required_facts = ["service.http"]
    produced_facts = ["vuln.template_match"]
    safety = ExploitSafety.SAFE

    async def check(self, ctx: ModuleContext) -> bool:
        if not _yaml_available:
            log.debug("PyYAML not installed — skipping template scanner")
            return False
        if not _aiohttp_available:
            log.debug("aiohttp not installed — skipping template scanner")
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        templates = _load_templates(_TEMPLATES_DIR)
        if not templates:
            log.debug("no vulnerability templates loaded")
            return []

        # Gather all HTTP service ports.
        http_ports: list[Port] = await ctx.facts.get_values("service.http")
        if not http_ports:
            return []

        findings: list[Finding] = []
        sem = asyncio.Semaphore(_CONCURRENCY)

        timeout = aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT)
        connector = aiohttp.TCPConnector(limit=_CONCURRENCY, ssl=False)
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
        ) as session:
            tasks: list[asyncio.Task] = []
            for port_obj in http_ports:
                ip = await self.resolve_ip(ctx, port_obj.host_id)
                if ip is None:
                    continue
                scheme = "https" if port_obj.port in (443, 8443) else "http"
                base_url = f"{scheme}://{ip}:{port_obj.port}"

                for tpl in templates:
                    tasks.append(
                        asyncio.ensure_future(
                            self._check_template(
                                ctx, session, sem, base_url,
                                port_obj, tpl, findings,
                            )
                        )
                    )

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        return findings

    async def _check_template(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        port_obj: Port,
        tpl: dict[str, Any],
        findings: list[Finding],
    ) -> None:
        """Run a single template against a single base URL."""
        tpl_id: str = tpl.get("id", "unknown")
        info: dict[str, Any] = tpl.get("info", {})
        http_blocks: list[dict[str, Any]] = tpl.get("http", [])
        if not http_blocks:
            return

        for http_block in http_blocks:
            method = http_block.get("method", "GET").upper()
            paths: list[str] = http_block.get("path", [])
            extra_headers: dict[str, str] = http_block.get("headers", {})
            matchers: list[dict[str, Any]] = http_block.get("matchers", [])
            condition: str = http_block.get("matchers-condition", "and").lower()

            for raw_path in paths:
                url = raw_path.replace("{{BaseURL}}", base_url)
                async with sem:
                    await ctx.rate_limiter.acquire()
                    try:
                        resp_status, resp_headers, resp_body = await self._send_request(
                            session, method, url, extra_headers,
                        )
                    except Exception:
                        log.debug("request failed for template %s at %s", tpl_id, url, exc_info=True)
                        continue

                if _evaluate_matchers(matchers, condition, resp_status, resp_headers, resp_body):
                    finding = self._build_finding(
                        tpl_id, info, port_obj, url,
                        method, resp_status, resp_body,
                    )
                    findings.append(finding)

                    # Publish fact so downstream modules can react.
                    await ctx.facts.add(
                        "vuln.template_match",
                        {
                            "template_id": tpl_id,
                            "url": url,
                            "host_id": port_obj.host_id,
                            "severity": info.get("severity", "info"),
                        },
                        self.name,
                        host_id=port_obj.host_id,
                    )

                    # Persist to database.
                    if ctx.db is not None:
                        await ctx.db.insert_finding(finding)

    # ── HTTP helpers ─────────────────────────────────────────────────────

    @staticmethod
    async def _send_request(
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        extra_headers: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        """Issue a single HTTP request and return (status, headers, body)."""
        async with session.request(method, url, headers=extra_headers, allow_redirects=False) as resp:
            body_bytes = await resp.content.read(_MAX_BODY_BYTES)
            body = body_bytes.decode("utf-8", errors="replace")
            headers = {k: v for k, v in resp.headers.items()}
            return resp.status, headers, body

    # ── Finding construction ─────────────────────────────────────────────

    @staticmethod
    def _build_finding(
        tpl_id: str,
        info: dict[str, Any],
        port_obj: Port,
        url: str,
        method: str,
        resp_status: int,
        resp_body: str,
    ) -> Finding:
        severity_str = info.get("severity", "info").lower()
        severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)
        classification = info.get("classification", {})
        cve_id = classification.get("cve-id")
        cvss_score = classification.get("cvss-score")
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        remediation = info.get("remediation", "")

        # Truncate body evidence to a reasonable size.
        body_snippet = resp_body[:1024]
        evidence = [
            Evidence(kind="request", data=f"{method} {url}"),
            Evidence(kind="response_status", data=str(resp_status)),
            Evidence(kind="response_body_snippet", data=body_snippet),
        ]

        return Finding(
            title=f"[{tpl_id}] {info.get('name', tpl_id)}",
            description=info.get("description", f"Template {tpl_id} matched on {url}"),
            severity=severity,
            host_id=port_obj.host_id,
            port_id=port_obj.id,
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            cve_id=cve_id,
            attack_technique_ids=["T1190"],
            module_name="vuln.template_scanner",
            evidence=evidence,
            remediation=remediation,
            references=references,
            verified=True,
        )
