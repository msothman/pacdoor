"""Web application vulnerability scanner — active OWASP Top 10 detection.

Tests for SQL injection, reflected XSS, local file inclusion, open redirects,
and server-side template injection across discovered HTTP services.  Detection
only — no exploitation payloads are sent.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import aiohttp
    _aiohttp_available = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    _aiohttp_available = False

from pacdoor.core.models import Evidence, Finding, Phase, Port, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────

# Ports that use HTTPS by default.
HTTPS_PORTS: set[int] = {443, 8443}

# Per-request timeout.
_REQUEST_TIMEOUT_SECS = 8

# Maximum concurrent requests.
_CONCURRENCY = 20

# Maximum response body bytes to read per request.
_MAX_BODY_BYTES = 256 * 1024  # 256 KiB

# Common parameter names to fuzz when no parameters are discovered.
_FUZZ_PARAMS: list[str] = [
    "id", "page", "search", "q", "file", "path", "url",
    "redirect", "template", "name", "item", "cat", "dir",
    "doc", "view", "content", "folder", "pg", "style",
]

# ── SQL Injection ────────────────────────────────────────────────────────

_SQLI_PAYLOADS: list[str] = [
    "'",
    '"',
    "1 OR 1=1",
    "1' AND '1'='2",
]

# Boolean-based pair: (true_suffix, false_suffix).
_SQLI_BOOLEAN_PAIR = (" AND 1=1", " AND 1=2")

# DB-specific error signatures → DB engine name.
_SQLI_ERROR_SIGNATURES: list[tuple[str, str]] = [
    # MySQL
    ("You have an error in your SQL syntax", "MySQL"),
    ("mysql_fetch", "MySQL"),
    ("Warning: mysql", "MySQL"),
    # MSSQL
    ("Unclosed quotation mark", "MSSQL"),
    ("Microsoft OLE DB", "MSSQL"),
    ("SQL Server", "MSSQL"),
    # PostgreSQL
    ("ERROR: syntax error at or near", "PostgreSQL"),
    ("PG::SyntaxError", "PostgreSQL"),
    ("org.postgresql", "PostgreSQL"),
    # SQLite
    ("SQLITE_ERROR", "SQLite"),
    ("unrecognized token", "SQLite"),
    ("near \"", "SQLite"),
    # Oracle
    ("ORA-01756", "Oracle"),
    ("ORA-00933", "Oracle"),
    ("Oracle error", "Oracle"),
]

# ── XSS ──────────────────────────────────────────────────────────────────

_XSS_CANARY = "<pacdoor_xss_test>"
_XSS_SCRIPT = "<script>alert(1)</script>"

# ── LFI ──────────────────────────────────────────────────────────────────

_LFI_PAYLOADS: list[str] = [
    "../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

_LFI_LINUX_MARKER = "root:x:0:0:"
_LFI_WINDOWS_MARKER = "[fonts]"

# ── Open Redirect ────────────────────────────────────────────────────────

_REDIRECT_PAYLOADS: list[str] = [
    "https://evil.com",
    "//evil.com",
]

# ── SSTI ─────────────────────────────────────────────────────────────────

_SSTI_PAYLOADS: list[tuple[str, str]] = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
]


# ── Helpers ──────────────────────────────────────────────────────────────


def _scheme_for_port(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace a single query parameter's value in *url* with *value*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _ensure_param(url: str, param: str, default: str = "1") -> str:
    """If *param* is not already in the URL, append it with *default*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        qs[param] = [default]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _extract_params(url: str) -> list[str]:
    """Return the list of query parameter names in *url*."""
    return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


# ── Module ───────────────────────────────────────────────────────────────


class WebVulnsModule(BaseModule):
    """Active OWASP Top 10 web vulnerability detection (no exploitation)."""

    name = "vuln.web_vulns"
    description = "Web application vulnerability scanner (SQLi, XSS, LFI, redirect, SSTI)"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1190"]
    required_facts = ["service.http"]
    produced_facts = ["vuln.sqli", "vuln.xss", "vuln.lfi", "vuln.redirect"]

    # ── Pre-check ────────────────────────────────────────────────────────

    async def check(self, ctx: ModuleContext) -> bool:
        if not _aiohttp_available:
            log.debug("aiohttp not installed — skipping web vuln scanner")
            return False
        return await super().check(ctx)

    # ── Main entry point ─────────────────────────────────────────────────

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        http_ports: list[Port] = await ctx.facts.get_values("service.http")
        if not http_ports:
            return []

        findings: list[Finding] = []
        sem = asyncio.Semaphore(_CONCURRENCY)

        timeout = aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT_SECS)
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
                scheme = _scheme_for_port(port_obj.port)
                base_url = f"{scheme}://{ip}:{port_obj.port}"

                target_urls = await self._gather_target_urls(ctx, port_obj, base_url)
                for url in target_urls:
                    tasks.append(
                        asyncio.ensure_future(
                            self._test_url(ctx, session, sem, url, port_obj, findings)
                        )
                    )

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        return findings

    # ── URL gathering ────────────────────────────────────────────────────

    async def _gather_target_urls(
        self,
        ctx: ModuleContext,
        port_obj: Port,
        base_url: str,
    ) -> list[str]:
        """Collect URLs to test from http_enum facts + the root URL."""
        urls: list[str] = [base_url]

        # Pull discovered paths from http_enum facts.
        http_paths: list[dict] = await ctx.facts.get_for_host(
            "http.paths", port_obj.host_id,
        )
        for entry in http_paths:
            if isinstance(entry, dict) and "path" in entry:
                path = entry["path"]
                # Only include paths that match this port.
                if entry.get("port") == port_obj.port:
                    url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"
                    urls.append(url)

        # Deduplicate while preserving order.
        seen: set[str] = set()
        unique: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)
        return unique

    # ── Per-URL test orchestrator ────────────────────────────────────────

    async def _test_url(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Run all vuln checks against every injectable parameter of *url*."""
        params = _extract_params(url)
        if not params:
            # No parameters in the URL — inject common ones.
            params = list(_FUZZ_PARAMS)
            url_with_params = url
            for p in params:
                url_with_params = _ensure_param(url_with_params, p)
            url = url_with_params

        for param in params:
            await self._test_sqli(ctx, session, sem, url, param, port_obj, findings)
            await self._test_xss(ctx, session, sem, url, param, port_obj, findings)
            await self._test_lfi(ctx, session, sem, url, param, port_obj, findings)
            await self._test_open_redirect(ctx, session, sem, url, param, port_obj, findings)
            await self._test_ssti(ctx, session, sem, url, param, port_obj, findings)

    # ── HTTP helper ──────────────────────────────────────────────────────

    async def _fetch(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
    ) -> tuple[int, dict[str, str], str] | None:
        """Rate-limited GET request; returns (status, headers, body) or None."""
        async with sem:
            await ctx.rate_limiter.acquire()
            try:
                async with session.get(
                    url, allow_redirects=False,
                ) as resp:
                    body_bytes = await resp.content.read(_MAX_BODY_BYTES)
                    body = body_bytes.decode("utf-8", errors="replace")
                    headers = {k: v for k, v in resp.headers.items()}
                    return resp.status, headers, body
            except (TimeoutError, aiohttp.ClientError, OSError):
                return None

    # ── 1. SQL Injection ─────────────────────────────────────────────────

    async def _test_sqli(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        param: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        # Error-based detection.
        for payload in _SQLI_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            _status, _headers, body = result
            body_lower = body.lower()

            for signature, db_engine in _SQLI_ERROR_SIGNATURES:
                if signature.lower() in body_lower:
                    finding = Finding(
                        title=f"SQL Injection ({db_engine}) via '{param}' on {url}",
                        description=(
                            f"The parameter '{param}' appears vulnerable to "
                            f"error-based SQL injection. The payload "
                            f"'{payload}' triggered a {db_engine} database "
                            f"error in the response."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=port_obj.host_id,
                        port_id=port_obj.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[
                            Evidence(kind="request", data=f"GET {test_url}"),
                            Evidence(kind="error_signature", data=signature),
                            Evidence(kind="db_engine", data=db_engine),
                        ],
                        remediation=(
                            "Use parameterized queries or prepared statements "
                            "instead of string concatenation. Apply input "
                            "validation and use an ORM where possible."
                        ),
                        verified=True,
                    )
                    findings.append(finding)
                    await ctx.facts.add(
                        "vuln.sqli",
                        {"param": param, "url": url, "db": db_engine,
                         "method": "error_based"},
                        self.name,
                        host_id=port_obj.host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_finding(finding)
                    return  # One finding per param is sufficient.

        # Boolean-based detection: compare response lengths.
        true_suffix, false_suffix = _SQLI_BOOLEAN_PAIR
        true_url = _inject_param(url, param, f"1{true_suffix}")
        false_url = _inject_param(url, param, f"1{false_suffix}")

        true_result = await self._fetch(ctx, session, sem, true_url)
        false_result = await self._fetch(ctx, session, sem, false_url)
        if true_result is not None and false_result is not None:
            true_len = len(true_result[2])
            false_len = len(false_result[2])
            # Significant length difference suggests boolean-based SQLi.
            if true_len > 0 and false_len > 0:
                diff_ratio = abs(true_len - false_len) / max(true_len, false_len)
                if diff_ratio > 0.15:
                    finding = Finding(
                        title=f"Possible Boolean-based SQLi via '{param}' on {url}",
                        description=(
                            f"The parameter '{param}' shows different response "
                            f"sizes for boolean true ({true_len} bytes) vs "
                            f"false ({false_len} bytes) conditions, indicating "
                            f"possible boolean-based blind SQL injection."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=port_obj.host_id,
                        port_id=port_obj.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[
                            Evidence(kind="request", data=f"TRUE: {true_url}"),
                            Evidence(kind="request", data=f"FALSE: {false_url}"),
                            Evidence(
                                kind="length_diff",
                                data=f"true={true_len}, false={false_len}, "
                                     f"diff={diff_ratio:.2%}",
                            ),
                        ],
                        remediation=(
                            "Use parameterized queries or prepared statements. "
                            "Never construct SQL by concatenating user input."
                        ),
                    )
                    findings.append(finding)
                    await ctx.facts.add(
                        "vuln.sqli",
                        {"param": param, "url": url, "method": "boolean_based"},
                        self.name,
                        host_id=port_obj.host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_finding(finding)

    # ── 2. Reflected XSS ─────────────────────────────────────────────────

    async def _test_xss(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        param: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        # Step 1: inject canary tag.
        canary_url = _inject_param(url, param, _XSS_CANARY)
        result = await self._fetch(ctx, session, sem, canary_url)
        if result is None:
            return
        _status, _headers, body = result

        if _XSS_CANARY not in body:
            return  # Not reflected — no XSS here.

        # Step 2: confirm with a script tag.
        script_url = _inject_param(url, param, _XSS_SCRIPT)
        result2 = await self._fetch(ctx, session, sem, script_url)
        if result2 is None:
            return
        _, _, body2 = result2

        confirmed = _XSS_SCRIPT in body2
        severity = Severity.HIGH
        method = "reflected_confirmed" if confirmed else "reflected_canary"
        desc_extra = (
            "The full script payload was reflected unencoded in the response."
            if confirmed
            else "An HTML tag canary was reflected unencoded, suggesting "
                 "the output is not properly sanitized."
        )

        finding = Finding(
            title=f"Reflected XSS via '{param}' on {url}",
            description=(
                f"The parameter '{param}' reflects user input into the "
                f"response body without proper encoding. {desc_extra}"
            ),
            severity=severity,
            host_id=port_obj.host_id,
            port_id=port_obj.id,
            module_name=self.name,
            attack_technique_ids=self.attack_technique_ids,
            evidence=[
                Evidence(kind="request", data=f"GET {canary_url}"),
                Evidence(kind="reflection", data=f"Canary '{_XSS_CANARY}' found in body"),
                *(
                    [Evidence(kind="confirmed", data="Script tag reflected in body")]
                    if confirmed else []
                ),
            ],
            remediation=(
                "Apply context-aware output encoding for all user-controlled "
                "data. Use Content-Security-Policy to mitigate impact. "
                "Consider using a templating engine with auto-escaping."
            ),
            verified=confirmed,
        )
        findings.append(finding)
        await ctx.facts.add(
            "vuln.xss",
            {"param": param, "url": url, "method": method},
            self.name,
            host_id=port_obj.host_id,
        )
        if ctx.db is not None:
            await ctx.db.insert_finding(finding)

    # ── 3. Local File Inclusion (LFI) ────────────────────────────────────

    async def _test_lfi(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        param: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        for payload in _LFI_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            _status, _headers, body = result

            os_target: str | None = None
            marker: str | None = None
            if _LFI_LINUX_MARKER in body:
                os_target = "Linux"
                marker = _LFI_LINUX_MARKER
            elif _LFI_WINDOWS_MARKER in body:
                os_target = "Windows"
                marker = _LFI_WINDOWS_MARKER

            if os_target and marker:
                finding = Finding(
                    title=f"Local File Inclusion via '{param}' on {url}",
                    description=(
                        f"The parameter '{param}' is vulnerable to Local "
                        f"File Inclusion. The payload '{payload}' caused the "
                        f"server to read a {os_target} system file. An "
                        f"attacker may read arbitrary files or achieve "
                        f"remote code execution via log poisoning."
                    ),
                    severity=Severity.HIGH,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request", data=f"GET {test_url}"),
                        Evidence(kind="file_content", data=f"Marker '{marker}' found"),
                        Evidence(kind="os", data=os_target),
                    ],
                    remediation=(
                        "Never use user input directly in file paths. "
                        "Use an allowlist of permitted files, strip path "
                        "traversal sequences, and chroot the application "
                        "to its web root."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.lfi",
                    {"param": param, "url": url, "os": os_target,
                     "payload": payload},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                return  # One finding per param.

    # ── 4. Open Redirect ─────────────────────────────────────────────────

    async def _test_open_redirect(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        param: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        for payload in _REDIRECT_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            status, headers, _body = result

            if status not in (301, 302, 303, 307, 308):
                continue

            location = headers.get("Location", "")
            if "evil.com" not in location.lower():
                continue

            finding = Finding(
                title=f"Open Redirect via '{param}' on {url}",
                description=(
                    f"The parameter '{param}' causes an HTTP redirect to "
                    f"an attacker-controlled domain. The payload "
                    f"'{payload}' resulted in a {status} redirect to "
                    f"'{location}'. An attacker can use this to phish "
                    f"users by redirecting them from a trusted domain."
                ),
                severity=Severity.MEDIUM,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[
                    Evidence(kind="request", data=f"GET {test_url}"),
                    Evidence(kind="redirect", data=f"{status} -> {location}"),
                ],
                remediation=(
                    "Validate redirect targets against an allowlist of "
                    "permitted domains. Use relative paths for internal "
                    "redirects and reject any absolute URLs from user input."
                ),
                verified=True,
            )
            findings.append(finding)
            await ctx.facts.add(
                "vuln.redirect",
                {"param": param, "url": url, "location": location},
                self.name,
                host_id=port_obj.host_id,
            )
            if ctx.db is not None:
                await ctx.db.insert_finding(finding)
            return  # One finding per param.

    # ── 5. Server-Side Template Injection (SSTI) ─────────────────────────

    async def _test_ssti(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        param: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        for payload, expected in _SSTI_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            _status, _headers, body = result

            # The expected computed value must appear in the body, but we
            # must also verify the raw payload is NOT present (to rule out
            # simple reflection that happens to contain the string).
            if expected in body and payload not in body:
                engine = "Jinja2/Twig" if payload.startswith("{{") else "Freemarker/Velocity"
                finding = Finding(
                    title=f"Server-Side Template Injection via '{param}' on {url}",
                    description=(
                        f"The parameter '{param}' is interpreted by a "
                        f"server-side template engine ({engine}). The "
                        f"expression '{payload}' was evaluated to "
                        f"'{expected}', confirming template injection. "
                        f"This can lead to remote code execution."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request", data=f"GET {test_url}"),
                        Evidence(kind="evaluation", data=f"'{payload}' -> '{expected}'"),
                        Evidence(kind="engine_hint", data=engine),
                    ],
                    remediation=(
                        "Never pass user input directly into template "
                        "rendering. Use a sandboxed template engine, "
                        "enforce strict input validation, and avoid "
                        "rendering user-supplied template strings."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.ssti",
                    {"param": param, "url": url, "engine": engine,
                     "payload": payload},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                return  # One finding per param.
