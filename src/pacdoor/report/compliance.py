"""Compliance mapping engine.

Maps assessment findings to compliance framework controls (PCI DSS 4.0,
NIST 800-53, CIS Controls v8).  Produces a structured ComplianceReport
that the report generator embeds in HTML / JSON / Markdown output.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────────────


class ComplianceControl(BaseModel):
    """A single control within a compliance framework."""

    framework: str
    control_id: str
    title: str
    description: str = ""


class ComplianceViolation(BaseModel):
    """A mapping between a finding and a violated compliance control."""

    finding_title: str
    finding_severity: str = "info"
    cve_id: str | None = None
    module_name: str = ""
    affected_count: int = 1
    controls: list[ComplianceControl] = Field(default_factory=list)


class ComplianceReport(BaseModel):
    """Aggregated compliance report across all findings."""

    violations: list[ComplianceViolation] = Field(default_factory=list)
    total_violations: int = 0
    frameworks_evaluated: list[str] = Field(default_factory=list)
    controls_violated: dict[str, list[str]] = Field(default_factory=dict)


# ── Framework control definitions ────────────────────────────────────

# Each framework maps a control ID to a human-readable title.
_PCI_DSS_CONTROLS: dict[str, str] = {
    "1.3": "Restrict inbound/outbound traffic to that which is necessary",
    "2.1": "Change vendor-supplied defaults before installing on network",
    "4.1": "Use strong cryptography and security protocols for transmission",
    "6.2": "Ensure all system components are protected from known vulnerabilities",
    "6.3": "Develop applications based on secure coding guidelines (patch management)",
    "8.3": "Secure all individual non-console administrative access with MFA",
}

_NIST_800_53_CONTROLS: dict[str, str] = {
    "AC-17": "Remote Access — control and monitor remote access methods",
    "IA-5": "Authenticator Management — manage information system authenticators",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-13": "Cryptographic Protection",
    "SI-2": "Flaw Remediation — identify, report, and correct system flaws",
    "SI-10": "Information Input Validation",
}

_CIS_CONTROLS: dict[str, str] = {
    "3": "Data Protection — develop processes and technical controls to protect data",
    "4": "Secure Configuration of Enterprise Assets and Software",
    "5": "Account Management — use processes and tools to manage accounts",
    "7": "Continuous Vulnerability Management",
    "9": "Email and Web Browser Protections / Network Service Management",
    "16": "Application Software Security",
}


# ── Finding-type -> control mappings ─────────────────────────────────

# Each entry: (pattern_type, regex_or_keywords) -> list of (framework, control_id)
# pattern_type: "title" matches against finding title, "module" against module name,
# "cve" is always checked.

_FINDING_CONTROL_MAP: list[tuple[str, list[tuple[str, str, str]]]] = [
    # Missing security headers
    (
        r"(?i)(missing.*header|x-content-type|x-frame-options|strict-transport"
        r"|content-security-policy|hsts|clickjack|security\s+header)",
        [
            ("pci-dss-4.0", "6.2", _PCI_DSS_CONTROLS["6.2"]),
            ("nist-800-53", "SC-8", _NIST_800_53_CONTROLS["SC-8"]),
            ("cis-controls-v8", "16", _CIS_CONTROLS["16"]),
        ],
    ),
    # Default credentials
    (
        r"(?i)(default\s+(credential|password|login|cred)|vendor.?supplied\s+default"
        r"|factory\s+default|admin[:/]admin|admin[:/]password)",
        [
            ("pci-dss-4.0", "2.1", _PCI_DSS_CONTROLS["2.1"]),
            ("nist-800-53", "IA-5", _NIST_800_53_CONTROLS["IA-5"]),
            ("cis-controls-v8", "4", _CIS_CONTROLS["4"]),
        ],
    ),
    # Unpatched CVEs (generic pattern — any finding with a CVE gets this)
    (
        r"(?i)(CVE-\d{4}-\d+|unpatched|missing\s+patch|outdated\s+version"
        r"|end.of.life|eol\b|unsupported\s+version)",
        [
            ("pci-dss-4.0", "6.3", _PCI_DSS_CONTROLS["6.3"]),
            ("nist-800-53", "SI-2", _NIST_800_53_CONTROLS["SI-2"]),
            ("cis-controls-v8", "7", _CIS_CONTROLS["7"]),
        ],
    ),
    # Weak encryption / TLS
    (
        r"(?i)(weak\s+(cipher|encrypt|tls|ssl|crypto)|sslv[23]|tlsv1\.?[01]?"
        r"|rc4|des\b|md5\s+sign|self.signed\s+cert|expired\s+cert"
        r"|weak\s+key\s+exchange|null\s+cipher)",
        [
            ("pci-dss-4.0", "4.1", _PCI_DSS_CONTROLS["4.1"]),
            ("nist-800-53", "SC-13", _NIST_800_53_CONTROLS["SC-13"]),
            ("cis-controls-v8", "3", _CIS_CONTROLS["3"]),
        ],
    ),
    # SMB signing disabled
    (
        r"(?i)(smb\s+sign|smb.*not\s+required|smb.*disabled|message\s+sign)",
        [
            ("pci-dss-4.0", "4.1", _PCI_DSS_CONTROLS["4.1"]),
            ("nist-800-53", "SC-8", _NIST_800_53_CONTROLS["SC-8"]),
        ],
    ),
    # Open services / unnecessary ports
    (
        r"(?i)(open\s+(port|service)|unnecessary\s+service|exposed\s+service"
        r"|unfiltered\s+port|publicly\s+accessible|internet.facing"
        r"|telnet\s+open|ftp\s+anonymous)",
        [
            ("pci-dss-4.0", "1.3", _PCI_DSS_CONTROLS["1.3"]),
            ("nist-800-53", "AC-17", _NIST_800_53_CONTROLS["AC-17"]),
            ("cis-controls-v8", "9", _CIS_CONTROLS["9"]),
        ],
    ),
    # SQL injection / XSS / input validation
    (
        r"(?i)(sql\s*inject|xss|cross.site\s*script|command\s*inject"
        r"|code\s*inject|ldap\s*inject|xpath\s*inject|ssti|template\s*inject"
        r"|input\s+validation|unsanitized\s+input)",
        [
            ("pci-dss-4.0", "6.2", _PCI_DSS_CONTROLS["6.2"]),
            ("nist-800-53", "SI-10", _NIST_800_53_CONTROLS["SI-10"]),
            ("cis-controls-v8", "16", _CIS_CONTROLS["16"]),
        ],
    ),
    # Credential exposure / weak passwords
    (
        r"(?i)(credential\s+expos|password\s+(expos|leak|dump|spray|brute)"
        r"|cleartext\s+(password|cred)|weak\s+password|pass.the.hash"
        r"|kerberoast|asreproast|ntlm\s+relay|credential\s+harvest"
        r"|hardcoded\s+(password|cred|secret))",
        [
            ("pci-dss-4.0", "8.3", _PCI_DSS_CONTROLS["8.3"]),
            ("nist-800-53", "IA-5", _NIST_800_53_CONTROLS["IA-5"]),
            ("cis-controls-v8", "5", _CIS_CONTROLS["5"]),
        ],
    ),
]

# Pre-compile all patterns.
_COMPILED_RULES: list[tuple[re.Pattern[str], list[tuple[str, str, str]]]] = [
    (re.compile(pattern), controls)
    for pattern, controls in _FINDING_CONTROL_MAP
]


# ── Mapper ───────────────────────────────────────────────────────────


class ComplianceMapper:
    """Maps findings to compliance framework controls.

    Supports PCI DSS 4.0, NIST 800-53, and CIS Controls v8.

    Usage::

        mapper = ComplianceMapper()
        violations = mapper.map_finding(finding_dict)
        report = mapper.map_all(findings_list)
        summary = mapper.summary_by_framework(report)
    """

    FRAMEWORKS: dict[str, dict[str, str]] = {
        "pci-dss-4.0": _PCI_DSS_CONTROLS,
        "nist-800-53": _NIST_800_53_CONTROLS,
        "cis-controls-v8": _CIS_CONTROLS,
    }

    def map_finding(self, finding: dict[str, Any]) -> list[ComplianceViolation]:
        """Map a single finding to compliance violations.

        Checks the finding title, description, CVE, and module name against
        known patterns and returns one ComplianceViolation per unique set
        of matched controls.
        """
        title = finding.get("title", "")
        description = finding.get("description", "")
        cve_id = finding.get("cve_id") or ""
        severity = finding.get("severity", "info")
        if hasattr(severity, "value"):
            severity = severity.value
        severity = str(severity).lower()
        module_name = finding.get("module_name", "")
        affected_count = finding.get("affected_count", 1)

        # Combine title + description for matching.
        search_text = f"{title} {description} {cve_id}"

        matched_controls: list[ComplianceControl] = []
        seen: set[tuple[str, str]] = set()

        for compiled_re, controls in _COMPILED_RULES:
            if compiled_re.search(search_text):
                for framework, control_id, control_title in controls:
                    key = (framework, control_id)
                    if key not in seen:
                        seen.add(key)
                        matched_controls.append(
                            ComplianceControl(
                                framework=framework,
                                control_id=control_id,
                                title=control_title,
                            )
                        )

        # If the finding has a CVE and no patterns matched, flag it under
        # the generic "unpatched CVE" controls.
        if cve_id and not matched_controls:
            for framework, control_id, control_title in _FINDING_CONTROL_MAP[2][1]:
                key = (framework, control_id)
                if key not in seen:
                    seen.add(key)
                    matched_controls.append(
                        ComplianceControl(
                            framework=framework,
                            control_id=control_id,
                            title=control_title,
                        )
                    )

        if not matched_controls:
            return []

        return [
            ComplianceViolation(
                finding_title=title,
                finding_severity=severity,
                cve_id=cve_id or None,
                module_name=module_name,
                affected_count=affected_count,
                controls=matched_controls,
            )
        ]

    def map_all(self, findings: list[dict[str, Any]]) -> ComplianceReport:
        """Map all findings and produce a consolidated ComplianceReport."""
        violations: list[ComplianceViolation] = []
        controls_violated: dict[str, set[str]] = defaultdict(set)
        frameworks_seen: set[str] = set()

        for finding in findings:
            result = self.map_finding(finding)
            violations.extend(result)
            for v in result:
                for ctrl in v.controls:
                    frameworks_seen.add(ctrl.framework)
                    controls_violated[ctrl.framework].add(ctrl.control_id)

        # Convert sets to sorted lists for deterministic output.
        controls_dict = {
            fw: sorted(cids) for fw, cids in sorted(controls_violated.items())
        }

        report = ComplianceReport(
            violations=violations,
            total_violations=len(violations),
            frameworks_evaluated=sorted(frameworks_seen) or sorted(self.FRAMEWORKS.keys()),
            controls_violated=controls_dict,
        )

        log.info(
            "Compliance mapping: %d violations across %d frameworks",
            len(violations),
            len(frameworks_seen),
        )
        return report

    def summary_by_framework(
        self, report: ComplianceReport,
    ) -> dict[str, dict[str, Any]]:
        """Summarize a compliance report grouped by framework.

        Returns a dict keyed by framework name, each containing:
          - controls_violated: list of control IDs
          - total_controls: total controls in the framework
          - violation_count: number of findings mapped
          - compliance_gap_pct: percentage of controls violated
          - details: list of {control_id, title, finding_count} dicts
        """
        summary: dict[str, dict[str, Any]] = {}

        # Count findings per (framework, control_id).
        finding_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for v in report.violations:
            for ctrl in v.controls:
                finding_counts[ctrl.framework][ctrl.control_id] += 1

        for fw_name, fw_controls in self.FRAMEWORKS.items():
            violated = report.controls_violated.get(fw_name, [])
            total = len(fw_controls)
            gap_pct = round((len(violated) / total) * 100, 1) if total > 0 else 0.0

            details: list[dict[str, Any]] = []
            for cid in violated:
                details.append({
                    "control_id": cid,
                    "title": fw_controls.get(cid, ""),
                    "finding_count": finding_counts.get(fw_name, {}).get(cid, 0),
                })

            summary[fw_name] = {
                "controls_violated": violated,
                "total_controls": total,
                "violation_count": sum(
                    finding_counts.get(fw_name, {}).values()
                ),
                "compliance_gap_pct": gap_pct,
                "details": details,
            }

        return summary
