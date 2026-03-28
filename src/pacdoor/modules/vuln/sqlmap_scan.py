"""SQLMap integration — wraps the sqlmap binary for SQL injection testing.

When sqlmap is installed, this module provides world-class SQL injection
detection with automatic crawling, form parsing, and multi-technique
testing.  Results are mapped into pacdoor Findings with injection point
details, parameter names, techniques, and identified DBMS.

If sqlmap is not available, check() returns False and the planner falls
back to the built-in web_vulns module's basic SQLi detection.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import tempfile
from typing import TYPE_CHECKING

from pacdoor.core.models import (
    Evidence,
    Finding,
    Phase,
    Port,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Timeout per URL (seconds).
_SQLMAP_TIMEOUT = 120

# Maximum URLs to test per host (sqlmap is thorough but slow).
_MAX_URLS_PER_HOST = 10

# Ports that use HTTPS by default.
_HTTPS_PORTS: set[int] = {443, 8443}


def _sqlmap_available() -> str | None:
    """Return the path to the sqlmap binary/script, or None if not found."""
    # Check for sqlmap binary on PATH
    path = shutil.which("sqlmap")
    if path is not None:
        return path

    # Check for sqlmap as a Python module (pip install sqlmap)
    path = shutil.which("sqlmap.py")
    if path is not None:
        return path

    # Check common installation locations
    for candidate in [
        "/usr/share/sqlmap/sqlmap.py",
        "/opt/sqlmap/sqlmap.py",
        "/usr/local/bin/sqlmap",
    ]:
        if os.path.isfile(candidate):
            return candidate

    return None


class SqlmapScanModule(BaseModule):
    """SQLMap-based SQL injection scanner."""

    name = "vuln.sqlmap_scan"
    description = "SQLMap SQL injection scanner — automated detection and confirmation"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1190"]
    required_facts = ["service.http"]
    produced_facts = ["vuln.sqli.confirmed"]

    async def check(self, ctx: ModuleContext) -> bool:
        """Only run if sqlmap is installed and HTTP services exist."""
        path = _sqlmap_available()
        if path is None:
            log.debug(
                "sqlmap not found on PATH — "
                "falling back to web_vulns basic SQLi detection"
            )
            return False
        log.debug("sqlmap found at %s", path)
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        http_ports: list[Port] = await ctx.facts.get_values("service.http")
        if not http_ports:
            return []

        sqlmap_path = _sqlmap_available()
        if sqlmap_path is None:
            return []

        # Build host_id -> ip lookup.
        hosts = await ctx.facts.get_values("host")
        host_ip_map: dict[str, str] = {h.id: h.ip for h in hosts}

        # Collect URLs to test: root URL + any discovered paths.
        # Group by host_id to enforce per-host URL limit.
        host_urls: dict[str, list[tuple[str, Port]]] = {}

        for port_obj in http_ports:
            ip = host_ip_map.get(port_obj.host_id)
            if ip is None:
                ip = await self.resolve_ip(ctx, port_obj.host_id)
            if ip is None:
                continue

            scheme = "https" if port_obj.port in _HTTPS_PORTS else "http"
            base_url = f"{scheme}://{ip}:{port_obj.port}"

            urls = host_urls.setdefault(port_obj.host_id, [])
            urls.append((base_url, port_obj))

        # Also gather discovered HTTP paths from fact store.
        http_paths = await ctx.facts.get_values("http.paths")
        for path_info in http_paths:
            if not isinstance(path_info, dict):
                continue
            host_id = path_info.get("host_id", "")
            path_info.get("path", "")
            url = path_info.get("url", "")
            if url and host_id in host_urls:
                # Find a matching port_obj for evidence
                port_obj = host_urls[host_id][0][1] if host_urls.get(host_id) else None
                if port_obj is not None:
                    host_urls[host_id].append((url, port_obj))
            elif url and host_id:
                # Host has paths but no root URL registered yet — skip
                pass

        findings: list[Finding] = []

        for _host_id, url_list in host_urls.items():
            # Deduplicate and cap at _MAX_URLS_PER_HOST
            seen_urls: set[str] = set()
            unique_urls: list[tuple[str, Port]] = []
            for url, port_obj in url_list:
                if url not in seen_urls and len(unique_urls) < _MAX_URLS_PER_HOST:
                    seen_urls.add(url)
                    unique_urls.append((url, port_obj))

            for url, port_obj in unique_urls:
                await ctx.rate_limiter.acquire()
                url_findings = await self._scan_url(
                    ctx, sqlmap_path, url, port_obj,
                )
                findings.extend(url_findings)

        return findings

    async def _scan_url(
        self,
        ctx: ModuleContext,
        sqlmap_path: str,
        url: str,
        port_obj: Port,
    ) -> list[Finding]:
        """Run sqlmap against a single URL and return findings."""
        findings: list[Finding] = []

        with tempfile.TemporaryDirectory(prefix="sqlmap_") as tmpdir:
            cmd = self._build_command(sqlmap_path, url, tmpdir)

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=_SQLMAP_TIMEOUT,
                )
            except TimeoutError:
                log.debug("sqlmap_scan: timed out on %s after %ds", url, _SQLMAP_TIMEOUT)
                with contextlib.suppress(ProcessLookupError):
                    proc.terminate()
                return findings
            except OSError as exc:
                log.debug("sqlmap_scan: failed to execute sqlmap: %s", exc)
                return findings

            # Parse JSON output from sqlmap's output directory.
            findings.extend(
                await self._parse_results(ctx, tmpdir, url, port_obj)
            )

        return findings

    @staticmethod
    def _build_command(
        sqlmap_path: str,
        url: str,
        output_dir: str,
    ) -> list[str]:
        """Build the sqlmap command-line argument list."""
        cmd = [sqlmap_path]

        # If sqlmap_path is a .py file, run it with python
        if sqlmap_path.endswith(".py"):
            python_path = shutil.which("python3") or shutil.which("python")
            if python_path:
                cmd = [python_path, sqlmap_path]

        cmd.extend([
            "-u", url,
            "--batch",              # Non-interactive
            "--level=2",            # Moderate test depth
            "--risk=1",             # Low risk (no OR-based injections)
            "--timeout=10",         # Per-request timeout
            "--retries=1",          # Single retry
            f"--output-dir={output_dir}",
            "--forms",              # Auto-parse and test forms
            "--crawl=1",            # Crawl depth 1
            "--smart",              # Only test parameters that appear injectable
            "--answers=follow=Y",   # Follow redirects
        ])

        return cmd

    async def _parse_results(
        self,
        ctx: ModuleContext,
        output_dir: str,
        url: str,
        port_obj: Port,
    ) -> list[Finding]:
        """Parse sqlmap output for confirmed SQL injections."""
        findings: list[Finding] = []

        # sqlmap stores results in output_dir/target_host/
        # Look for log files and target.txt files
        for root, _dirs, files in os.walk(output_dir):
            for filename in files:
                filepath = os.path.join(root, filename)

                # Parse sqlmap's log file for injection confirmations
                if filename == "log":
                    findings.extend(
                        await self._parse_log_file(ctx, filepath, url, port_obj)
                    )

                # Parse JSON results if available (--json-output)
                if filename.endswith(".json"):
                    findings.extend(
                        await self._parse_json_file(ctx, filepath, url, port_obj)
                    )

        return findings

    async def _parse_log_file(
        self,
        ctx: ModuleContext,
        filepath: str,
        url: str,
        port_obj: Port,
    ) -> list[Finding]:
        """Parse sqlmap's text log file for confirmed injections."""
        findings: list[Finding] = []

        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return findings

        if not content.strip():
            return findings

        # sqlmap log format has sections separated by "---"
        # Look for injection confirmations
        current_param = ""
        current_place = ""
        current_type = ""
        current_title = ""
        current_dbms = ""
        injections: list[dict[str, str]] = []

        for line in content.splitlines():
            line = line.strip()

            # Parameter identification
            if line.startswith("Parameter:"):
                # "Parameter: id (GET)" or "Parameter: username (POST)"
                parts = line.replace("Parameter:", "").strip()
                paren_idx = parts.find("(")
                if paren_idx != -1:
                    current_param = parts[:paren_idx].strip()
                    current_place = parts[paren_idx + 1 : parts.find(")")].strip()
                else:
                    current_param = parts
                    current_place = "unknown"

            # Injection type
            elif line.startswith("Type:"):
                current_type = line.replace("Type:", "").strip()

            # Injection title
            elif line.startswith("Title:"):
                current_title = line.replace("Title:", "").strip()

            # DBMS identification
            elif line.startswith("back-end DBMS:"):
                current_dbms = line.replace("back-end DBMS:", "").strip()

            # Section separator — if we have accumulated injection data, store it
            elif line == "---" and current_param and current_type:
                injections.append({
                    "parameter": current_param,
                    "place": current_place,
                    "type": current_type,
                    "title": current_title,
                    "dbms": current_dbms,
                })
                current_type = ""
                current_title = ""

        # Flush last injection if separator was missing
        if current_param and current_type:
            injections.append({
                "parameter": current_param,
                "place": current_place,
                "type": current_type,
                "title": current_title,
                "dbms": current_dbms,
            })

        # Deduplicate by (param, type)
        seen: set[tuple[str, str]] = set()
        for inj in injections:
            key = (inj["parameter"], inj["type"])
            if key in seen:
                continue
            seen.add(key)

            dbms_str = f" (DBMS: {inj['dbms']})" if inj["dbms"] else ""

            finding = Finding(
                title=(
                    f"SQL Injection confirmed: {inj['parameter']} "
                    f"({inj['place']}){dbms_str}"
                ),
                description=(
                    f"sqlmap confirmed a SQL injection vulnerability in the "
                    f"'{inj['parameter']}' parameter ({inj['place']}) at {url}. "
                    f"Technique: {inj['type']}. {inj['title']}. "
                    f"This allows an attacker to read, modify, or delete "
                    f"database contents, and potentially execute system commands."
                ),
                severity=Severity.CRITICAL,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=["T1190"],
                evidence=[
                    Evidence(kind="sqli_url", data=url),
                    Evidence(kind="sqli_parameter", data=inj["parameter"]),
                    Evidence(kind="sqli_method", data=inj["place"]),
                    Evidence(kind="sqli_technique", data=inj["type"]),
                    Evidence(kind="sqli_title", data=inj["title"]),
                    Evidence(kind="sqli_dbms", data=inj.get("dbms", "unknown")),
                ],
                remediation=(
                    "Use parameterized queries (prepared statements) for all "
                    "database interactions. Never concatenate user input into "
                    "SQL strings. Implement input validation and use an ORM "
                    "where possible. Deploy a WAF as defense-in-depth."
                ),
                verified=True,
            )
            findings.append(finding)

            # Publish confirmed SQLi fact for downstream modules
            await ctx.facts.add(
                "vuln.sqli.confirmed",
                {
                    "url": url,
                    "parameter": inj["parameter"],
                    "method": inj["place"],
                    "technique": inj["type"],
                    "dbms": inj.get("dbms", ""),
                    "host_id": port_obj.host_id,
                },
                self.name,
                host_id=port_obj.host_id,
            )

            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

        return findings

    async def _parse_json_file(
        self,
        ctx: ModuleContext,
        filepath: str,
        url: str,
        port_obj: Port,
    ) -> list[Finding]:
        """Parse sqlmap's JSON output file for confirmed injections."""
        findings: list[Finding] = []

        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return findings

        if not isinstance(data, (dict, list)):
            return findings

        # Normalize to list of result objects
        results = data if isinstance(data, list) else [data]

        for result in results:
            if not isinstance(result, dict):
                continue

            # sqlmap JSON output varies by version; handle common formats
            vuln_data = result.get("data", result)
            if not isinstance(vuln_data, dict):
                continue

            param = str(vuln_data.get("parameter", vuln_data.get("param", "")))
            place = str(vuln_data.get("place", vuln_data.get("method", "unknown")))
            technique = str(vuln_data.get("type", vuln_data.get("technique", "")))
            title = str(vuln_data.get("title", ""))
            dbms = str(vuln_data.get("dbms", ""))

            if not param:
                continue

            dbms_str = f" (DBMS: {dbms})" if dbms else ""

            finding = Finding(
                title=(
                    f"SQL Injection confirmed: {param} ({place}){dbms_str}"
                ),
                description=(
                    f"sqlmap confirmed a SQL injection vulnerability in the "
                    f"'{param}' parameter ({place}) at {url}. "
                    f"Technique: {technique}. {title}. "
                    f"This allows an attacker to read, modify, or delete "
                    f"database contents, and potentially execute system commands."
                ),
                severity=Severity.CRITICAL,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=["T1190"],
                evidence=[
                    Evidence(kind="sqli_url", data=url),
                    Evidence(kind="sqli_parameter", data=param),
                    Evidence(kind="sqli_method", data=place),
                    Evidence(kind="sqli_technique", data=technique),
                    Evidence(kind="sqli_dbms", data=dbms or "unknown"),
                ],
                remediation=(
                    "Use parameterized queries (prepared statements) for all "
                    "database interactions. Never concatenate user input into "
                    "SQL strings. Implement input validation and use an ORM "
                    "where possible. Deploy a WAF as defense-in-depth."
                ),
                verified=True,
            )
            findings.append(finding)

            await ctx.facts.add(
                "vuln.sqli.confirmed",
                {
                    "url": url,
                    "parameter": param,
                    "method": place,
                    "technique": technique,
                    "dbms": dbms,
                    "host_id": port_obj.host_id,
                },
                self.name,
                host_id=port_obj.host_id,
            )

            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

        return findings
