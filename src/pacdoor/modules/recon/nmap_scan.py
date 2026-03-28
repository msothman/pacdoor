"""Nmap integration — wraps the nmap binary for SYN scan, OS detection, and NSE scripts.

When nmap is available on the system, this module provides far superior
scanning compared to the built-in TCP connect scan:
  - SYN scan (-sS) is faster and stealthier
  - Service version detection (-sV) identifies exact product versions
  - Default NSE scripts (-sC) detect common vulnerabilities
  - OS fingerprinting (-O) with confidence levels

If nmap is not installed, check() returns False and the planner falls
back to the built-in port_scan module.  This module has HIGHER priority
than port_scan; when it runs successfully, port_scan will detect that
ports are already discovered and skip via the fact store dedup mechanism.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from pacdoor.core.models import (
    Evidence,
    Finding,
    Host,
    Phase,
    Port,
    PortState,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Timeout for a single nmap invocation (seconds).
_NMAP_TIMEOUT = 300

# Map nmap service names to our internal service fact type names.
_NMAP_SERVICE_MAP: dict[str, str] = {
    "http": "http",
    "http-proxy": "http",
    "https": "https",
    "http-alt": "http",
    "ssl/http": "https",
    "ssl/https": "https",
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "smtp",
    "smtps": "smtps",
    "domain": "dns",
    "microsoft-ds": "smb",
    "netbios-ssn": "netbios",
    "msrpc": "msrpc",
    "ms-sql-s": "mssql",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "oracle-tns": "oracle",
    "ms-wbt-server": "rdp",
    "ldap": "ldap",
    "ldaps": "ldaps",
    "vnc": "vnc",
    "redis": "redis",
    "mongod": "mongodb",
    "mongodb": "mongodb",
    "imap": "imap",
    "imaps": "imaps",
    "pop3": "pop3",
    "pop3s": "pop3s",
    "telnet": "telnet",
    "kerberos-sec": "kerberos",
    "nfs": "nfs",
    "pptp": "pptp",
    "elasticsearch": "elasticsearch",
    "wsman": "winrm",
    "wsmans": "winrm",
    "snmp": "snmp",
}

# Services that should also produce a service.http fact.
_HTTP_SERVICES = {"http", "https"}

# Ports that are implicitly HTTP even if nmap doesn't label them that way.
_HTTP_PORTS = {80, 443, 8080, 8443, 8888, 8000, 3000, 9090}

# NSE script results that warrant specific severity levels.
_CRITICAL_SCRIPTS: dict[str, tuple[Severity, str]] = {
    "smb-vuln-ms17-010": (
        Severity.CRITICAL,
        "Host is vulnerable to EternalBlue (MS17-010). "
        "Apply Microsoft security update MS17-010 immediately.",
    ),
    "smb-vuln-ms08-067": (
        Severity.CRITICAL,
        "Host is vulnerable to MS08-067 (Conficker). "
        "Apply Microsoft security update MS08-067.",
    ),
    "smb-vuln-cve-2017-7494": (
        Severity.CRITICAL,
        "Host is vulnerable to SambaCry (CVE-2017-7494). "
        "Update Samba to a patched version.",
    ),
}

_HIGH_SCRIPTS: dict[str, tuple[Severity, str]] = {
    "smb-security-mode": (
        Severity.HIGH,
        "SMB message signing is not required. "
        "Enable mandatory SMB signing to prevent relay attacks.",
    ),
}

_INFO_SCRIPTS: frozenset[str] = frozenset({
    "http-title",
    "ssh-hostkey",
    "ssl-cert",
    "ssl-date",
    "http-server-header",
    "http-robots.txt",
    "nbstat",
    "smb-os-discovery",
    "smb2-security-mode",
    "smb2-time",
    "dns-nsid",
    "ftp-anon",
})


def _nmap_available() -> str | None:
    """Return the path to the nmap binary, or None if not found."""
    return shutil.which("nmap")


def _parse_port_spec_for_nmap(spec: str | None) -> str | None:
    """Convert our --ports CLI flag value to nmap's -p format.

    Returns None to use nmap's --top-ports default.
    Supported formats mirror port_scan._parse_port_spec:
      - "top1000" / "default"  -> None (use --top-ports)
      - "all"                  -> "1-65535"
      - "22,80,443"            -> "22,80,443"
      - "1-1024"               -> "1-1024"
      - "22,80,100-200,8080"   -> "22,80,100-200,8080"
    """
    if spec is None:
        return None
    spec = spec.strip().lower()
    if spec in ("top1000", "top200", "default"):
        return None
    if spec == "all":
        return "1-65535"
    # Pass through as-is; nmap understands comma-separated and ranges.
    return spec


class NmapScanModule(BaseModule):
    """Nmap-based port scanner, service detector, and OS fingerprinter."""

    name = "recon.nmap_scan"
    description = "Nmap SYN scan with service detection, OS fingerprinting, and NSE scripts"
    phase = Phase.RECON
    attack_technique_ids = ["T1046"]
    required_facts = ["host"]
    produced_facts = ["port.open", "service.*", "os.detected", "nmap.script_result"]

    async def check(self, ctx: ModuleContext) -> bool:
        """Only run if nmap is installed and hosts have been discovered."""
        path = _nmap_available()
        if path is None:
            log.debug("nmap binary not found on PATH -- falling back to built-in port_scan")
            return False
        log.debug("nmap found at %s", path)
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        hosts: list[Host] = await ctx.facts.get_values("host")
        if not hosts:
            return []

        nmap_path = _nmap_available()
        if nmap_path is None:
            # Should not happen since check() gates us, but be safe.
            return []

        findings: list[Finding] = []
        total_open = 0

        for host in hosts:
            host_findings, open_count = await self._scan_host(
                ctx, nmap_path, host,
            )
            findings.extend(host_findings)
            total_open += open_count

        if total_open > 0:
            findings.insert(
                0,
                Finding(
                    title=f"Nmap scan: {total_open} open ports across {len(hosts)} hosts",
                    description=(
                        "SYN scan with service version detection, "
                        "OS fingerprinting, and default NSE scripts"
                    ),
                    severity=Severity.INFO,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                ),
            )

        return findings

    # ------------------------------------------------------------------
    # Per-host scan
    # ------------------------------------------------------------------

    async def _scan_host(
        self,
        ctx: ModuleContext,
        nmap_path: str,
        host: Host,
    ) -> tuple[list[Finding], int]:
        """Run nmap against a single host and ingest results."""
        findings: list[Finding] = []
        cmd = self._build_command(ctx, nmap_path, host.ip)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=_NMAP_TIMEOUT,
            )
        except TimeoutError:
            log.error(
                "nmap timed out after %ds scanning %s", _NMAP_TIMEOUT, host.ip,
            )
            findings.append(Finding(
                title=f"Nmap timeout on {host.ip}",
                description=f"Nmap scan timed out after {_NMAP_TIMEOUT}s",
                severity=Severity.INFO,
                host_id=host.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
            ))
            return findings, 0
        except OSError as exc:
            log.error("failed to execute nmap: %s", exc)
            return findings, 0

        if proc.returncode != 0:
            stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
            log.error(
                "nmap exited with code %d for %s: %s",
                proc.returncode, host.ip, stderr_text[:500],
            )
            findings.append(Finding(
                title=f"Nmap error on {host.ip}",
                description=f"nmap exited with code {proc.returncode}: {stderr_text[:300]}",
                severity=Severity.INFO,
                host_id=host.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
            ))
            return findings, 0

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        open_count, host_findings = await self._parse_xml(ctx, host, stdout_text)
        findings.extend(host_findings)
        return findings, open_count

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_command(ctx: ModuleContext, nmap_path: str, target_ip: str) -> list[str]:
        """Build the nmap command-line argument list."""
        cmd = [
            nmap_path,
            "-sS",              # SYN scan
            "-sV",              # Service version detection
            "-sC",              # Default NSE scripts
            "-O",               # OS detection
            "--open",           # Only show open ports
            "-T4",              # Aggressive timing
            "-oX", "-",         # XML output to stdout
        ]

        # Custom port specification from CLI --ports flag.
        port_spec = _parse_port_spec_for_nmap(ctx.config.get("ports"))
        if port_spec is not None:
            cmd.extend(["-p", port_spec])
        else:
            cmd.extend(["--top-ports", "1000"])

        cmd.append(target_ip)
        return cmd

    # ------------------------------------------------------------------
    # XML parsing
    # ------------------------------------------------------------------

    async def _parse_xml(
        self,
        ctx: ModuleContext,
        host: Host,
        xml_text: str,
    ) -> tuple[int, list[Finding]]:
        """Parse nmap XML output and push facts + findings into the pipeline."""
        findings: list[Finding] = []
        open_count = 0

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            log.error("failed to parse nmap XML output: %s", exc)
            return 0, findings

        for host_elem in root.findall(".//host"):
            # -- Hostnames ------------------------------------------------
            for hostname_elem in host_elem.findall(".//hostname"):
                name = hostname_elem.get("name")
                if name and not host.hostname:
                    host.hostname = name

            # -- OS detection ---------------------------------------------
            os_findings = await self._parse_os(ctx, host, host_elem)
            findings.extend(os_findings)

            # -- Ports ----------------------------------------------------
            for port_elem in host_elem.findall(".//port"):
                port_finding, is_open = await self._parse_port(ctx, host, port_elem)
                if is_open:
                    open_count += 1
                if port_finding:
                    findings.append(port_finding)

            # -- Host-level scripts (e.g. smb-os-discovery) ---------------
            for hostscript in host_elem.findall(".//hostscript/script"):
                script_finding = await self._parse_script(
                    ctx, host, hostscript, port_id=None,
                )
                if script_finding:
                    findings.append(script_finding)

        return open_count, findings

    async def _parse_port(
        self,
        ctx: ModuleContext,
        host: Host,
        port_elem: ET.Element,
    ) -> tuple[Finding | None, bool]:
        """Parse a single <port> element. Returns (optional Finding, is_open)."""
        state_elem = port_elem.find("state")
        if state_elem is None or state_elem.get("state") != "open":
            return None, False

        port_num = int(port_elem.get("portid", "0"))
        protocol = port_elem.get("protocol", "tcp")

        # Service info
        svc_elem = port_elem.find("service")
        svc_name: str | None = None
        svc_product: str | None = None
        svc_version: str | None = None
        svc_extra: str | None = None

        if svc_elem is not None:
            svc_name = svc_elem.get("name")
            svc_product = svc_elem.get("product")
            svc_version = svc_elem.get("version")
            svc_extra = svc_elem.get("extrainfo")

        # Map nmap service name to our internal name.
        internal_svc = _NMAP_SERVICE_MAP.get(svc_name, svc_name) if svc_name else None

        # Build version string from nmap's components.
        version_str = svc_version
        if svc_product and svc_version:
            version_str = f"{svc_product} {svc_version}"
        elif svc_product:
            version_str = svc_product

        banner_parts = [p for p in (svc_product, svc_version, svc_extra) if p]
        banner = " ".join(banner_parts) if banner_parts else None

        port_obj = Port(
            host_id=host.id,
            port=port_num,
            protocol=protocol,
            state=PortState.OPEN,
            service_name=internal_svc,
            service_version=version_str,
            banner=banner[:500] if banner else None,
            product=svc_product,
        )

        # Push port.open fact (dedup by host_id + port + protocol).
        await ctx.facts.add("port.open", port_obj, self.name, host_id=host.id)

        # Persist to database.
        if ctx.db is not None:
            await ctx.db.insert_port(port_obj)

        # Push service-specific facts.
        if internal_svc:
            await ctx.facts.add(
                f"service.{internal_svc}", port_obj, self.name, host_id=host.id,
            )
            # HTTP services also get a generic service.http fact.
            if internal_svc in _HTTP_SERVICES and internal_svc != "http":
                await ctx.facts.add(
                    "service.http", port_obj, self.name, host_id=host.id,
                )
        # Ports commonly serving HTTP that nmap may not label as such.
        if port_num in _HTTP_PORTS and internal_svc not in _HTTP_SERVICES:
            await ctx.facts.add(
                "service.http", port_obj, self.name, host_id=host.id,
            )

        # Parse per-port script results.
        finding: Finding | None = None
        for script_elem in port_elem.findall("script"):
            script_finding = await self._parse_script(
                ctx, host, script_elem, port_id=port_obj.id,
            )
            if script_finding:
                # Return the most severe script finding for this port.
                if finding is None or _severity_rank(script_finding.severity) > _severity_rank(finding.severity):
                    finding = script_finding

        return finding, True

    async def _parse_os(
        self,
        ctx: ModuleContext,
        host: Host,
        host_elem: ET.Element,
    ) -> list[Finding]:
        """Parse OS fingerprint from <os> element."""
        findings: list[Finding] = []
        os_elem = host_elem.find("os")
        if os_elem is None:
            return findings

        best_match: str | None = None
        best_accuracy: int = 0
        best_family: str | None = None
        best_version: str | None = None
        evidence_items: list[Evidence] = []

        for osmatch in os_elem.findall("osmatch"):
            name = osmatch.get("name", "")
            accuracy = int(osmatch.get("accuracy", "0"))
            evidence_items.append(
                Evidence(kind="nmap_osmatch", data=f"{name} ({accuracy}% confidence)")
            )

            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_match = name

                # Extract OS family and version from osclass children.
                for osclass in osmatch.findall("osclass"):
                    best_family = osclass.get("osfamily")
                    best_version = osclass.get("osgen")

        if best_match and best_accuracy > 0:
            # Update Host model.
            if best_family:
                host.os = best_family
            if best_version:
                host.os_version = best_version

            # Persist updated host.
            if ctx.db is not None:
                await ctx.db.insert_host(host)

            # Publish fact.
            await ctx.facts.add(
                "os.detected",
                {
                    "os": best_family or best_match,
                    "os_version": best_version,
                    "confidence": best_accuracy,
                    "nmap_match": best_match,
                },
                self.name,
                host_id=host.id,
            )

            findings.append(Finding(
                title=f"OS detected (nmap): {best_match} on {host.ip}",
                description=(
                    f"Nmap OS fingerprinting identified {host.ip} as "
                    f"{best_match} with {best_accuracy}% confidence."
                ),
                severity=Severity.INFO,
                host_id=host.id,
                module_name=self.name,
                attack_technique_ids=["T1082"],
                evidence=evidence_items,
            ))

            if ctx.db is not None:
                await ctx.db.insert_finding(findings[-1])

        return findings

    async def _parse_script(
        self,
        ctx: ModuleContext,
        host: Host,
        script_elem: ET.Element,
        port_id: str | None,
    ) -> Finding | None:
        """Parse a single NSE <script> element and produce a Finding if noteworthy."""
        script_id = script_elem.get("id", "")
        output = script_elem.get("output", "").strip()
        if not script_id:
            return None

        # Determine severity and remediation based on script ID.
        severity = Severity.INFO
        remediation = ""

        if script_id in _CRITICAL_SCRIPTS:
            severity, remediation = _CRITICAL_SCRIPTS[script_id]
        elif script_id in _HIGH_SCRIPTS:
            # For smb-security-mode, only flag as HIGH if signing is not required.
            if script_id == "smb-security-mode":
                if "signing" in output.lower() and "not required" not in output.lower():
                    return None  # Signing is required -- not a finding.
            severity, remediation = _HIGH_SCRIPTS[script_id]
        elif script_id in _INFO_SCRIPTS:
            severity = Severity.INFO
        else:
            # Unknown script -- still record it but only as INFO.
            severity = Severity.INFO

        evidence = [Evidence(kind="nmap_script", data=f"[{script_id}] {output[:2000]}")]

        # Extract SSL cert details if present.
        if script_id == "ssl-cert":
            for table in script_elem.findall(".//table"):
                for elem in table.findall("elem"):
                    key = elem.get("key", "")
                    val = elem.text or ""
                    if key and val:
                        evidence.append(
                            Evidence(kind="ssl_cert_field", data=f"{key}: {val}")
                        )

        # Publish script result fact.
        await ctx.facts.add(
            "nmap.script_result",
            {
                "script_id": script_id,
                "output": output[:2000],
                "host_id": host.id,
                "severity": severity.value,
            },
            self.name,
            host_id=host.id,
        )

        finding = Finding(
            title=f"[nmap:{script_id}] {host.ip}",
            description=output[:1000] if output else f"NSE script {script_id} produced output",
            severity=severity,
            host_id=host.id,
            port_id=port_id,
            module_name=self.name,
            attack_technique_ids=self.attack_technique_ids,
            evidence=evidence,
            remediation=remediation,
        )

        if ctx.db is not None:
            await ctx.db.insert_finding(finding)

        return finding


def _severity_rank(severity: Severity) -> int:
    """Numeric rank for severity comparison (higher = more severe)."""
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }.get(severity, 0)
