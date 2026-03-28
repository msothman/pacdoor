"""Version-to-CVE mapping engine.

Correlates detected service versions against a CVE database loaded from
``data/cve_map.json`` and a hardcoded list of critical, high-confidence
CVE entries for commonly seen services.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
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

_DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "cve_map.json"


# ── Version parsing & comparison ─────────────────────────────────────


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison.

    Handles formats like "2.4.41", "8.2p1", "1.18.0", "10.0".
    Non-numeric suffixes (e.g. "p1", "rc2") are stripped.
    """
    # Strip common suffixes: "8.2p1" -> "8.2", "1.0rc1" -> "1.0"
    cleaned = re.split(r"[a-zA-Z~+\-]", version_str, maxsplit=1)[0]
    parts: list[int] = []
    for segment in cleaned.split("."):
        segment = segment.strip()
        if segment.isdigit():
            parts.append(int(segment))
    return tuple(parts) if parts else (0,)


def _version_lt(a: str, b: str) -> bool:
    """Return True if version *a* is strictly less than version *b*."""
    return _parse_version(a) < _parse_version(b)


def _version_in_range(
    version: str,
    min_ver: str | None = None,
    max_ver: str | None = None,
) -> bool:
    """Check whether *version* falls within [min_ver, max_ver).

    *min_ver* is inclusive, *max_ver* is exclusive (the fix version).
    Either bound may be ``None`` to leave that side open.
    """
    parsed = _parse_version(version)
    if min_ver is not None and parsed < _parse_version(min_ver):
        return False
    return not (max_ver is not None and parsed >= _parse_version(max_ver))


# ── Hardcoded critical CVEs ──────────────────────────────────────────

# Each entry: (product_patterns, fixed_version, cve_id, cvss, description)
# product_patterns: list of lowercase substrings to match against product
_HARDCODED_CVES: list[dict[str, Any]] = [
    {
        "products": ["openssh"],
        "fixed": "8.3",
        "cve": "CVE-2020-15778",
        "cvss": 7.8,
        "description": (
            "OpenSSH < 8.3: scp client command injection via crafted "
            "filenames allows arbitrary command execution."
        ),
        "remediation": "Upgrade OpenSSH to 8.3 or later.",
    },
    {
        "products": ["openssh"],
        "fixed": "9.8",
        "cve": "CVE-2024-6387",
        "cvss": 9.8,
        "description": (
            "OpenSSH < 9.8 (regreSSHion): Race condition in signal handler "
            "allows unauthenticated remote code execution as root on "
            "glibc-based Linux systems."
        ),
        "remediation": "Upgrade OpenSSH to 9.8 or later immediately.",
    },
    {
        "products": ["apache", "httpd"],
        "fixed": "2.4.50",
        "cve": "CVE-2021-41773",
        "cvss": 9.8,
        "description": (
            "Apache HTTP Server < 2.4.50: Path traversal and remote code "
            "execution via crafted request URIs when mod_cgi is enabled."
        ),
        "remediation": "Upgrade Apache HTTP Server to 2.4.50 or later.",
    },
    {
        "products": ["nginx"],
        "fixed": "1.17.7",
        "cve": "CVE-2019-20372",
        "cvss": 5.3,
        "description": (
            "nginx < 1.17.7: HTTP request smuggling via error pages "
            "allows bypassing security restrictions."
        ),
        "remediation": "Upgrade nginx to 1.17.7 or later.",
    },
    {
        "products": ["proftpd"],
        "fixed": "1.3.6",
        "cve": "CVE-2019-12815",
        "cvss": 9.8,
        "description": (
            "ProFTPD < 1.3.6: Arbitrary file copy via mod_copy allows "
            "unauthenticated remote code execution."
        ),
        "remediation": "Upgrade ProFTPD to 1.3.6 or later.",
    },
    {
        "products": ["microsoft iis", "iis"],
        "fixed": None,  # Check exact version instead
        "match_version": "10.0",
        "cve": "CVE-2022-21907",
        "cvss": 9.8,
        "description": (
            "Microsoft IIS 10.0: HTTP Protocol Stack Remote Code Execution "
            "vulnerability in http.sys allows unauthenticated RCE."
        ),
        "remediation": (
            "Apply Microsoft security update KB5009543 or later. "
            "Disable HTTP Trailer Support as a workaround."
        ),
    },
    {
        "products": ["mysql"],
        "fixed": "8.0.32",
        "cve": "CVE-2023-21912",
        "cvss": 7.5,
        "description": (
            "MySQL < 8.0.32: Vulnerability in the MySQL Server product "
            "(component: Server: Security: Encryption). Easily exploitable "
            "vulnerability allows unauthenticated attacker to cause denial "
            "of service."
        ),
        "remediation": "Upgrade MySQL to 8.0.32 or later.",
    },
    {
        "products": ["postgresql", "postgres"],
        "fixed": "15.1",
        "cve": "CVE-2022-2625",
        "cvss": 8.0,
        "description": (
            "PostgreSQL < 15.1: Extension scripts can replace objects not "
            "belonging to the extension, allowing privilege escalation."
        ),
        "remediation": "Upgrade PostgreSQL to 15.1 or later.",
    },
]


def _severity_from_cvss(cvss: float) -> Severity:
    """Map a CVSS score to a Severity enum value."""
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ── Data file loading ────────────────────────────────────────────────


def _load_cve_map() -> dict[str, Any]:
    """Load CVE mapping data from cve_map.json.

    Expected format::

        {
            "cves": [
                {
                    "cve_id": "CVE-2021-41773",
                    "cpe": "cpe:2.3:a:apache:http_server:...",
                    "product": "apache",
                    "version_start": "2.4.0",
                    "version_end": "2.4.50",
                    "cvss": 9.8,
                    "description": "..."
                },
                ...
            ]
        }

    Returns empty dict on failure (file missing or unpopulated).
    """
    try:
        data = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        log.debug("cve_map.json not found at %s — using hardcoded CVEs only", _DATA_FILE)
    except Exception:
        log.error("Failed to parse cve_map.json at %s", _DATA_FILE)
    return {}


def _build_cpe_key(product: str, version: str) -> str:
    """Build a CPE-like identifier for matching: 'apache:2.4.41'."""
    prod = product.lower().strip()
    # Normalize common product names
    prod = prod.replace("http server", "httpd").replace("http_server", "httpd")
    return f"{prod}:{version}"


# ── Module ───────────────────────────────────────────────────────────


class CVECheckerModule(BaseModule):
    name = "vuln.cve_checker"
    description = "Correlate service versions against known CVE database"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1190"]
    required_facts = ["service.version"]
    produced_facts = ["vuln.cve"]

    async def check(self, ctx: ModuleContext) -> bool:
        """Run if we have service.version facts OR port.open facts with version info."""
        if await ctx.facts.has("service.version"):
            return True
        # Also check port.open facts that might carry version data
        ports = await ctx.facts.get_values("port.open")
        return any(
            p.product and p.service_version
            for p in ports
            if isinstance(p, Port)
        )

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        cve_map = _load_cve_map()
        findings: list[Finding] = []
        seen_cves: set[tuple[str, str]] = set()  # (host_id, cve_id) dedup

        # Gather version info from service.version facts
        version_facts = await ctx.facts.get_all("service.version")
        for fact in version_facts:
            val = fact.value
            host_id = fact.host_id or ""
            product = ""
            version = ""

            if isinstance(val, Port):
                product = val.product or ""
                version = val.service_version or ""
            elif isinstance(val, dict):
                product = val.get("product", "")
                version = val.get("version", "")
            else:
                continue

            if not product or not version:
                continue

            ip = await self.resolve_ip(ctx, host_id) if host_id else None
            ip_str = ip or "unknown"

            self._check_hardcoded(
                findings, seen_cves, host_id, ip_str, product, version
            )
            self._check_cve_map(
                cve_map, findings, seen_cves, host_id, ip_str, product, version
            )

        # Also scan port.open facts for product+version
        open_ports = await ctx.facts.get_values("port.open")
        for port in open_ports:
            if not isinstance(port, Port):
                continue
            if not port.product or not port.service_version:
                continue

            host_id = port.host_id
            ip = await self.resolve_ip(ctx, host_id) if host_id else None
            ip_str = ip or "unknown"

            self._check_hardcoded(
                findings, seen_cves, host_id, ip_str,
                port.product, port.service_version,
            )
            self._check_cve_map(
                cve_map, findings, seen_cves, host_id, ip_str,
                port.product, port.service_version,
            )

        # Push discovered CVE facts
        for finding in findings:
            if finding.cve_id:
                await ctx.facts.add(
                    f"vuln.cve.{finding.cve_id.replace('-', '_').lower()}",
                    {
                        "cve_id": finding.cve_id,
                        "cvss": finding.cvss_score,
                        "host": finding.host_id,
                        "title": finding.title,
                    },
                    self.name,
                    host_id=finding.host_id,
                )

        return findings

    def _check_hardcoded(
        self,
        findings: list[Finding],
        seen_cves: set[tuple[str, str]],
        host_id: str,
        ip: str,
        product: str,
        version: str,
    ) -> None:
        """Check service against the hardcoded critical CVE list."""
        product_lower = product.lower()

        for entry in _HARDCODED_CVES:
            # Check if product matches any of the patterns
            if not any(pat in product_lower for pat in entry["products"]):
                continue

            cve_id = entry["cve"]
            dedup_key = (host_id, cve_id)
            if dedup_key in seen_cves:
                continue

            # Special case: exact version match (e.g. IIS 10.0)
            if "match_version" in entry:
                if not version.startswith(entry["match_version"]):
                    continue
            else:
                # Standard: check if version < fixed_version
                fixed = entry["fixed"]
                if fixed is None:
                    continue
                if not _version_lt(version, fixed):
                    continue

            seen_cves.add(dedup_key)
            cvss = entry["cvss"]
            severity = _severity_from_cvss(cvss)

            findings.append(Finding(
                title=f"{cve_id}: {product} {version} on {ip}",
                description=entry["description"],
                severity=severity,
                host_id=host_id,
                cvss_score=cvss,
                cve_id=cve_id,
                module_name=self.name,
                attack_technique_ids=["T1190"],
                evidence=[Evidence(
                    kind="cve_match",
                    data=(
                        f"Product: {product}  Version: {version}  "
                        f"CVE: {cve_id}  CVSS: {cvss}  "
                        f"Fixed in: {entry.get('fixed', 'N/A')}  Host: {ip}"
                    ),
                )],
                remediation=entry["remediation"],
                references=[
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "https://attack.mitre.org/techniques/T1190/",
                ],
                verified=False,
            ))

    def _check_cve_map(
        self,
        cve_map: dict[str, Any],
        findings: list[Finding],
        seen_cves: set[tuple[str, str]],
        host_id: str,
        ip: str,
        product: str,
        version: str,
    ) -> None:
        """Check service against the cve_map.json database."""
        cve_entries = cve_map.get("cves", [])
        if not cve_entries:
            return

        product_lower = product.lower()
        cpe_key = _build_cpe_key(product, version)

        for entry in cve_entries:
            cve_id = entry.get("cve_id", "")
            if not cve_id:
                continue

            dedup_key = (host_id, cve_id)
            if dedup_key in seen_cves:
                continue

            matched = False

            # Method 1: CPE string matching
            cpe = entry.get("cpe", "").lower()
            if cpe and product_lower in cpe:
                # Check version range
                ver_start = entry.get("version_start")
                ver_end = entry.get("version_end")
                if _version_in_range(version, ver_start, ver_end):
                    matched = True

            # Method 2: Product + version substring matching
            if not matched:
                entry_product = entry.get("product", "").lower()
                if entry_product and entry_product in product_lower:
                    ver_start = entry.get("version_start")
                    ver_end = entry.get("version_end")
                    if _version_in_range(version, ver_start, ver_end):
                        matched = True

            if matched:
                seen_cves.add(dedup_key)
                cvss = float(entry.get("cvss", 0.0))
                severity = _severity_from_cvss(cvss)
                description = entry.get(
                    "description",
                    f"Vulnerability {cve_id} affects {product} {version}.",
                )

                findings.append(Finding(
                    title=f"{cve_id}: {product} {version} on {ip}",
                    description=description,
                    severity=severity,
                    host_id=host_id,
                    cvss_score=cvss,
                    cve_id=cve_id,
                    module_name=self.name,
                    attack_technique_ids=["T1190"],
                    evidence=[Evidence(
                        kind="cve_match",
                        data=(
                            f"Product: {product}  Version: {version}  "
                            f"CVE: {cve_id}  CVSS: {cvss}  "
                            f"CPE: {cpe_key}  Host: {ip}"
                        ),
                    )],
                    remediation=entry.get(
                        "remediation",
                        f"Upgrade {product} to a version that addresses {cve_id}.",
                    ),
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "https://attack.mitre.org/techniques/T1190/",
                    ],
                    verified=False,
                ))
