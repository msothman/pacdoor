"""Nuclei integration — wraps the nuclei binary for template-based vulnerability scanning.

When nuclei is installed, this module provides vastly superior coverage
compared to the built-in template_scanner (6000+ community templates vs
our ~50 hand-written YAML templates).

Nuclei is invoked with JSON Lines output and results are mapped into
pacdoor Findings with proper severity, CVE references, ATT&CK technique
IDs, and curl-command evidence.

If nuclei is not installed, check() returns False and the planner falls
back to the built-in template_scanner module.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import TYPE_CHECKING, Any

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

# Timeout for a single nuclei invocation (seconds).
_NUCLEI_TIMEOUT = 600

# Default rate limit (requests per second) if not configured.
_DEFAULT_RATE_LIMIT = 150

# Maximum number of findings to ingest per target (safety cap).
_MAX_FINDINGS_PER_TARGET = 500

# Nuclei severity string -> our Severity enum.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# Nuclei classification type -> ATT&CK technique ID (best-effort mapping).
_CLASSIFICATION_TECHNIQUE_MAP: dict[str, str] = {
    "cve": "T1190",                 # Exploit Public-Facing Application
    "rce": "T1059",                 # Command and Scripting Interpreter
    "sqli": "T1190",                # Exploit Public-Facing Application
    "xss": "T1189",                 # Drive-by Compromise
    "lfi": "T1083",                 # File and Directory Discovery
    "rfi": "T1105",                 # Ingress Tool Transfer
    "ssrf": "T1090",                # Proxy
    "xxe": "T1190",                 # Exploit Public-Facing Application
    "ssti": "T1059",                # Command and Scripting Interpreter
    "idor": "T1087",                # Account Discovery
    "auth-bypass": "T1078",         # Valid Accounts
    "default-login": "T1078.001",   # Valid Accounts: Default Accounts
    "misconfig": "T1574",           # Hijack Execution Flow
    "exposure": "T1082",            # System Information Discovery
    "unauth": "T1078",              # Valid Accounts
}


def _nuclei_available() -> str | None:
    """Return the path to the nuclei binary, or None if not found."""
    return shutil.which("nuclei")


class NucleiScanModule(BaseModule):
    """Nuclei-based template vulnerability scanner."""

    name = "vuln.nuclei_scan"
    description = "Nuclei template-based vulnerability scanner (6000+ templates)"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1190"]
    required_facts = ["service.http"]
    produced_facts = ["vuln.nuclei.*"]

    async def check(self, ctx: ModuleContext) -> bool:
        """Only run if nuclei is installed and HTTP services have been discovered."""
        path = _nuclei_available()
        if path is None:
            log.debug(
                "nuclei binary not found on PATH -- "
                "falling back to built-in template_scanner"
            )
            return False
        log.debug("nuclei found at %s", path)
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        http_ports: list[Port] = await ctx.facts.get_values("service.http")
        if not http_ports:
            return []

        nuclei_path = _nuclei_available()
        if nuclei_path is None:
            return []

        # Build a host_id -> ip lookup.
        hosts = await ctx.facts.get_values("host")
        host_ip_map: dict[str, str] = {h.id: h.ip for h in hosts}

        # Deduplicate URLs: same (ip, port) should only be scanned once.
        seen_targets: set[str] = set()
        targets: list[tuple[str, Port]] = []

        for port_obj in http_ports:
            ip = host_ip_map.get(port_obj.host_id)
            if ip is None:
                ip = await self.resolve_ip(ctx, port_obj.host_id)
            if ip is None:
                continue

            scheme = "https" if port_obj.port in (443, 8443) else "http"
            url = f"{scheme}://{ip}:{port_obj.port}"

            if url not in seen_targets:
                seen_targets.add(url)
                targets.append((url, port_obj))

        findings: list[Finding] = []
        for url, port_obj in targets:
            target_findings = await self._scan_target(
                ctx, nuclei_path, url, port_obj,
            )
            findings.extend(target_findings)

        if findings:
            summary = Finding(
                title=f"Nuclei scan: {len(findings)} findings across {len(targets)} targets",
                description=(
                    "Template-based vulnerability scanning with nuclei. "
                    f"Scanned {len(targets)} HTTP target(s), "
                    f"found {len(findings)} issue(s)."
                ),
                severity=Severity.INFO,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
            )
            findings.insert(0, summary)

        return findings

    # ------------------------------------------------------------------
    # Per-target scan
    # ------------------------------------------------------------------

    async def _scan_target(
        self,
        ctx: ModuleContext,
        nuclei_path: str,
        url: str,
        port_obj: Port,
    ) -> list[Finding]:
        """Run nuclei against a single URL and return findings."""
        cmd = self._build_command(ctx, nuclei_path, url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=_NUCLEI_TIMEOUT,
            )
        except TimeoutError:
            log.error(
                "nuclei timed out after %ds scanning %s",
                _NUCLEI_TIMEOUT, url,
            )
            return [Finding(
                title=f"Nuclei timeout on {url}",
                description=f"Nuclei scan timed out after {_NUCLEI_TIMEOUT}s",
                severity=Severity.INFO,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
            )]
        except OSError as exc:
            log.error("failed to execute nuclei: %s", exc)
            return []

        # Nuclei exits 0 on success (even with findings) and 1 on error.
        # However, some versions exit 1 when there are no results. Only
        # treat as hard error when there's no stdout and stderr is noisy.
        if proc.returncode != 0 and not stdout_bytes.strip():
            stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
            # Ignore common non-error messages from nuclei's stderr.
            if stderr_text and "no results found" not in stderr_text.lower():
                log.error(
                    "nuclei exited with code %d for %s: %s",
                    proc.returncode, url, stderr_text[:500],
                )
            return []

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        return await self._parse_jsonl(ctx, stdout_text, port_obj)

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_command(
        ctx: ModuleContext,
        nuclei_path: str,
        url: str,
    ) -> list[str]:
        """Build the nuclei command-line argument list."""
        rate_limit = ctx.config.get("rate_limit", _DEFAULT_RATE_LIMIT)

        cmd = [
            nuclei_path,
            "-u", url,
            "-severity", "critical,high,medium",
            "-json",                    # JSON Lines output
            "-silent",                  # Suppress banner and progress
            "-rate-limit", str(rate_limit),
            "-no-color",                # Clean output
        ]

        return cmd

    # ------------------------------------------------------------------
    # JSON Lines parsing
    # ------------------------------------------------------------------

    async def _parse_jsonl(
        self,
        ctx: ModuleContext,
        jsonl_text: str,
        port_obj: Port,
    ) -> list[Finding]:
        """Parse nuclei JSON Lines output into pacdoor Findings."""
        findings: list[Finding] = []

        for line in jsonl_text.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                log.debug("skipping non-JSON nuclei output line: %s", line[:200])
                continue

            if not isinstance(result, dict):
                continue

            finding = self._result_to_finding(result, port_obj)
            if finding is None:
                continue

            findings.append(finding)

            # Publish fact for downstream modules.
            template_id = result.get("template-id", result.get("templateID", "unknown"))
            nuclei_severity = result.get("info", {}).get("severity", "info").lower()
            await ctx.facts.add(
                f"vuln.nuclei.{template_id}",
                {
                    "template_id": template_id,
                    "url": result.get("matched-at", result.get("matched", "")),
                    "host_id": port_obj.host_id,
                    "severity": nuclei_severity,
                    "name": result.get("info", {}).get("name", template_id),
                },
                self.name,
                host_id=port_obj.host_id,
            )

            # Persist to database.
            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                log.debug(
                    "hit max findings cap (%d) for target, stopping parse",
                    _MAX_FINDINGS_PER_TARGET,
                )
                break

        return findings

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _result_to_finding(
        result: dict[str, Any],
        port_obj: Port,
    ) -> Finding | None:
        """Convert a single nuclei JSON result object to a pacdoor Finding."""
        info: dict[str, Any] = result.get("info", {})
        if not info:
            return None

        template_id = result.get("template-id", result.get("templateID", "unknown"))
        name = info.get("name", template_id)
        description = info.get("description", f"Nuclei template {template_id} matched")
        severity_str = info.get("severity", "info").lower()
        severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)

        # CVE and CVSS from classification.
        classification: dict[str, Any] = info.get("classification", {})
        cve_id = classification.get("cve-id")
        # cve-id can be a list in some nuclei versions.
        if isinstance(cve_id, list):
            cve_id = cve_id[0] if cve_id else None
        cvss_score = classification.get("cvss-score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None
        cvss_vector = classification.get("cvss-metrics")

        # ATT&CK technique mapping.
        attack_ids = ["T1190"]  # Default: Exploit Public-Facing Application.
        # Try to infer from template tags.
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in _CLASSIFICATION_TECHNIQUE_MAP:
                mapped = _CLASSIFICATION_TECHNIQUE_MAP[tag_lower]
                if mapped not in attack_ids:
                    attack_ids.append(mapped)
                break

        # Evidence.
        evidence: list[Evidence] = []
        matched_at = result.get("matched-at", result.get("matched", ""))
        if matched_at:
            evidence.append(Evidence(kind="matched_at", data=str(matched_at)))

        curl_command = result.get("curl-command", result.get("curl_command", ""))
        if curl_command:
            evidence.append(Evidence(kind="curl_command", data=str(curl_command)[:2000]))

        # Include the request/response if available.
        request = result.get("request", "")
        if request:
            evidence.append(Evidence(kind="request", data=str(request)[:2000]))
        response = result.get("response", "")
        if response:
            evidence.append(Evidence(kind="response_snippet", data=str(response)[:2000]))

        # Extracted results (e.g., version numbers, paths).
        extracted = result.get("extracted-results", result.get("extracted_results", []))
        if extracted:
            if isinstance(extracted, list):
                extracted = "; ".join(str(e) for e in extracted[:10])
            evidence.append(Evidence(kind="extracted", data=str(extracted)[:1000]))

        # References.
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        elif not isinstance(references, list):
            references = []
        # Filter out None/empty entries.
        references = [str(r) for r in references if r]

        # Remediation.
        remediation = info.get("remediation", "")

        return Finding(
            title=f"[nuclei:{template_id}] {name}",
            description=description[:2000],
            severity=severity,
            host_id=port_obj.host_id,
            port_id=port_obj.id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cve_id=cve_id,
            attack_technique_ids=attack_ids,
            module_name="vuln.nuclei_scan",
            evidence=evidence,
            remediation=remediation,
            references=references,
            verified=True,
        )
