"""Report generation -- HTML (Jinja2), JSON, Markdown, and PDF.

Integrates with FindingCorrelator to produce deduplicated/consolidated
views of findings across hosts.  The HTML report shows the consolidated
view by default (with "N hosts affected" badges), while the JSON report
includes both raw and consolidated views.

Supports:
- Screenshot embedding as base64 data URIs in HTML reports
- Diff reports comparing two scan databases (new/fixed/persistent findings)
- Executive summary with risk rating and remediation timeline
- Compliance mapping (PCI DSS, NIST 800-53, CIS Controls)
- Remediation prioritization with scored/ranked findings
- PDF output via WeasyPrint (optional dependency)
- Custom branding (logo, company name, classification marking)
"""

from __future__ import annotations

import base64
import html
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader

from pacdoor.core.correlator import FindingCorrelator
from pacdoor.core.models import DiffResult
from pacdoor.report.compliance import ComplianceMapper
from pacdoor.report.prioritizer import RemediationPrioritizer

if TYPE_CHECKING:
    from pacdoor.db.database import Database

log = logging.getLogger(__name__)

# ── ATT&CK tactic ordering (Enterprise matrix) ──────────────────────

_ATTACK_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Map technique-ID prefixes to the tactic they most commonly appear
# under.  This is a simplified mapping; a full mapping would come from
# the ATT&CK STIX data.  The scanner only emits a small set of
# technique IDs so a short lookup table is sufficient.
_TECHNIQUE_TACTIC_MAP: dict[str, str] = {
    "T1595": "Reconnaissance",
    "T1592": "Reconnaissance",
    "T1589": "Reconnaissance",
    "T1590": "Reconnaissance",
    "T1583": "Resource Development",
    "T1584": "Resource Development",
    "T1588": "Resource Development",
    "T1190": "Initial Access",
    "T1133": "Initial Access",
    "T1078": "Initial Access",
    "T1566": "Initial Access",
    "T1059": "Execution",
    "T1203": "Execution",
    "T1053": "Persistence",
    "T1505": "Persistence",
    "T1068": "Privilege Escalation",
    "T1548": "Privilege Escalation",
    "T1562": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1110": "Credential Access",
    "T1003": "Credential Access",
    "T1552": "Credential Access",
    "T1555": "Credential Access",
    "T1046": "Discovery",
    "T1018": "Discovery",
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1021": "Lateral Movement",
    "T1210": "Lateral Movement",
    "T1005": "Collection",
    "T1071": "Command and Control",
    "T1105": "Command and Control",
    "T1572": "Command and Control",
    "T1041": "Exfiltration",
    "T1486": "Impact",
    "T1489": "Impact",
    "T1498": "Impact",
}

# Severity label -> numeric score for the heatmap.
_SEVERITY_SCORE: dict[str, int] = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

# Severity ordering for sorting (highest first).
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Jinja2 template directory alongside this file.
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _esc(value: object) -> str:
    """Escape a value for safe HTML insertion."""
    return html.escape(str(value)) if value else ""


def _md_esc(value: object) -> str:
    """Escape pipe characters so Markdown table cells don't break."""
    return str(value).replace("|", "\\|") if value else ""


def _compute_duration(started: Any, completed: Any) -> str:
    """Return a human-readable duration string between two timestamps."""
    if not started or not completed:
        return "\u2014"
    try:
        if isinstance(started, str):
            started = datetime.fromisoformat(started)
        if isinstance(completed, str):
            completed = datetime.fromisoformat(completed)
        delta = completed - started
        total_secs = int(delta.total_seconds())
        if total_secs < 0:
            return "\u2014"
        if total_secs < 60:
            return f"{total_secs}s"
        minutes, secs = divmod(total_secs, 60)
        return f"{minutes}m {secs}s"
    except Exception:
        return "\u2014"


def _determine_overall_risk(severity_counts: dict[str, int]) -> str:
    """Determine the overall risk rating from severity counts."""
    if severity_counts.get("critical", 0) > 0:
        return "critical"
    if severity_counts.get("high", 0) > 0:
        return "high"
    if severity_counts.get("medium", 0) > 0:
        return "medium"
    if severity_counts.get("low", 0) > 0:
        return "low"
    return "info"


def _build_attack_matrix(
    findings: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Build the ATT&CK heatmap data from findings.

    Returns (tactics_with_data, flat_technique_list, matrix_dict) where
    ``matrix_dict`` maps tactic name -> list of {id, score} dicts.
    """
    technique_scores: dict[str, int] = {}
    for f in findings:
        technique_ids = f.get("attack_technique_ids")
        if isinstance(technique_ids, str):
            try:
                technique_ids = json.loads(technique_ids)
            except (json.JSONDecodeError, TypeError):
                technique_ids = []
        if not technique_ids:
            continue
        sev = f.get("severity", "info")
        if isinstance(sev, str):
            sev = sev.lower()
        score = _SEVERITY_SCORE.get(sev, 1)
        for tid in technique_ids:
            technique_scores[tid] = max(technique_scores.get(tid, 0), score)

    # Group by tactic.
    matrix: dict[str, list[dict[str, Any]]] = {t: [] for t in _ATTACK_TACTICS}
    flat: list[dict[str, Any]] = []

    for tid, score in sorted(technique_scores.items()):
        tactic = _TECHNIQUE_TACTIC_MAP.get(tid, "Initial Access")
        entry = {"id": tid, "score": score}
        flat.append(entry)
        if tactic in matrix:
            matrix[tactic].append(entry)

    # Only return tactics that have at least one technique.
    tactics_used = [t for t in _ATTACK_TACTICS if matrix.get(t)]
    return tactics_used, flat, matrix


class ReportGenerator:
    """Generate assessment reports in HTML, JSON, and Markdown formats."""

    def __init__(self, db: Database | None = None, output_dir: Path | None = None) -> None:
        self.db = db
        self.output_dir = output_dir or Path("./pacdoor-results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up Jinja2 environment.
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    async def generate(
        self,
        fmt: str,
        branding: dict[str, Any] | None = None,
    ) -> Path:
        """Generate a report in the given format and return its path.

        Args:
            fmt: Report format ("html", "json", "markdown", "pdf", "bloodhound").
            branding: Optional dict with keys ``logo_path``, ``company_name``,
                ``classification`` for custom report branding.
        """
        if fmt == "bloodhound":
            return await self._generate_bloodhound()
        data = await self._gather_data()
        if fmt == "html":
            return await self._generate_html(data, branding=branding)
        elif fmt == "json":
            return await self._generate_json(data)
        elif fmt == "markdown":
            return await self._generate_markdown(data)
        elif fmt == "pdf":
            return await self._generate_pdf(data, branding=branding)
        raise ValueError(f"Unknown format: {fmt}")

    async def _generate_bloodhound(self) -> Path:
        """Generate a BloodHound CE-compatible ZIP from AD enumeration data."""
        from pacdoor.report.bloodhound import generate_bloodhound_zip

        return await generate_bloodhound_zip(self.db, self.output_dir)

    # ── Data gathering ───────────────────────────────────────────────

    async def _gather_data(self) -> dict[str, Any]:
        hosts = await self.db.get_all_hosts()
        findings = await self.db.get_all_findings()

        # Pre-parse JSON string fields from the DB so downstream code
        # can treat them as native Python objects.
        for f in findings:
            for key in ("evidence", "attack_technique_ids", "refs"):
                val = f.get(key)
                if val is None:
                    f[key] = []
                elif isinstance(val, str):
                    try:
                        f[key] = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        f[key] = []
            # Normalize DB column "refs" to model field "references"
            if "refs" in f and "references" not in f:
                f["references"] = f.pop("refs")

        # Build host_id -> IP map for the correlator.
        host_ip_map: dict[str, str] = {
            h.get("id", ""): h.get("ip", h.get("id", ""))
            for h in hosts
        }

        # Correlate findings.
        correlator = FindingCorrelator(host_ip_map)
        consolidated = correlator.correlate(findings)
        correlation_stats = correlator.statistics(findings, consolidated)

        # Serialize consolidated findings for templates and JSON.
        consolidated_dicts = [cf.model_dump(mode="json") for cf in consolidated]

        # Compliance mapping.
        compliance_mapper = ComplianceMapper()
        compliance_report = compliance_mapper.map_all(consolidated_dicts)
        compliance_summary = compliance_mapper.summary_by_framework(compliance_report)

        # Remediation prioritization.
        prioritizer = RemediationPrioritizer()
        prioritized = prioritizer.prioritize(consolidated_dicts)
        prioritized_dicts = [pf.model_dump(mode="json") for pf in prioritized]

        return {
            "hosts": hosts,
            "host_ip_map": host_ip_map,
            "ports": await self.db.get_all_ports(),
            "findings": findings,
            "consolidated_findings": consolidated_dicts,
            "correlation_stats": correlation_stats,
            "credentials": await self.db.get_all_credentials(),
            "attack_paths": await self.db.get_all_attack_paths(),
            "module_runs": await self.db.get_all_module_runs(),
            "compliance_report": compliance_report.model_dump(mode="json"),
            "compliance_summary": compliance_summary,
            "prioritized_findings": prioritized_dicts,
            "stats": {
                "total_hosts": await self.db.count_hosts(),
                "total_findings": await self.db.count_findings(),
                "total_consolidated": len(consolidated),
                "findings_by_severity": await self.db.count_findings_by_severity(),
            },
        }

    # ── JSON ─────────────────────────────────────────────────────────

    async def _generate_json(self, data: dict[str, Any]) -> Path:
        host_ip_map: dict[str, str] = data.get("host_ip_map", {})
        exec_summary = self._generate_executive_summary(data)

        def _resolve(host_id: str) -> str:
            return host_ip_map.get(host_id, host_id)

        clean_hosts = [
            {
                "ip": h.get("ip", ""),
                "hostname": h.get("hostname") or "",
                "os": h.get("os") or "",
                "profile": h.get("profile", "unknown"),
                "domain": h.get("domain") or "",
            }
            for h in data.get("hosts", [])
        ]

        clean_ports = [
            {
                "host": _resolve(p.get("host_id", "")),
                "port": p.get("port"),
                "protocol": p.get("protocol", "tcp"),
                "service": p.get("service_name") or "",
                "version": p.get("service_version") or "",
            }
            for p in data.get("ports", [])
        ]

        clean_findings = [
            {
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "host": _resolve(f.get("host_id", "")),
                "module": f.get("module_name", ""),
                "cve": f.get("cve_id") or "",
                "cvss": f.get("cvss_score"),
                "description": f.get("description", ""),
                "remediation": f.get("remediation", ""),
                "status": f.get("status", "new"),
            }
            for f in data.get("findings", [])
        ]

        clean_consolidated = [
            {
                "title": cf.get("title", ""),
                "severity": cf.get("severity", "info"),
                "affected_hosts": cf.get("affected_hosts", []),
                "affected_count": cf.get("affected_count", 0),
                "module": cf.get("module_name", ""),
                "cve": cf.get("cve_id") or "",
                "cvss": cf.get("cvss_score"),
                "remediation": cf.get("remediation", ""),
                "attack_techniques": cf.get("attack_technique_ids", []),
            }
            for cf in data.get("consolidated_findings", [])
        ]

        clean_creds = [
            {
                "host": _resolve(c.get("host_id", "")),
                "username": c.get("username", ""),
                "type": c.get("cred_type", ""),
                "domain": c.get("domain") or "",
                "admin": bool(c.get("admin")),
                "source": c.get("source_module", ""),
            }
            for c in data.get("credentials", [])
        ]

        clean_paths = [
            {
                "from": _resolve(ap.get("from_host_id", "")),
                "to": _resolve(ap.get("to_host_id", "")),
                "technique": ap.get("technique_id", ""),
                "description": ap.get("description", ""),
            }
            for ap in data.get("attack_paths", [])
        ]

        output = {
            "report": "PACDOOR Scan Report",
            "version": "0.1.0",
            "generated": datetime.now(UTC).isoformat(),
            "executive_summary": exec_summary,
            "statistics": {
                "hosts": len(clean_hosts),
                "ports": len(clean_ports),
                "findings": len(clean_findings),
                "unique_findings": len(clean_consolidated),
                "credentials": len(clean_creds),
                "attack_paths": len(clean_paths),
                "by_severity": data.get("stats", {}).get("findings_by_severity", {}),
            },
            "hosts": clean_hosts,
            "ports": clean_ports,
            "findings": clean_consolidated or clean_findings,
            "credentials": clean_creds,
            "attack_paths": clean_paths,
            "compliance": data.get("compliance_summary", {}),
            "remediation_plan": data.get("prioritized_findings", []),
        }
        path = self.output_dir / "report.json"
        path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
        return path

    # ── HTML (Jinja2) ────────────────────────────────────────────────

    async def _generate_html(
        self,
        data: dict[str, Any],
        branding: dict[str, Any] | None = None,
    ) -> Path:
        from pacdoor.report.attack_map import build_navigator_layer

        attack_layer = build_navigator_layer(data["findings"])
        severity_counts: dict[str, int] = data["stats"].get("findings_by_severity", {})
        now = datetime.now(UTC)

        # Load screenshots as base64 data URIs for embedding.
        screenshots: list[dict[str, str]] = []
        screenshots_dir = self.output_dir / "screenshots"
        if screenshots_dir.exists():
            from pacdoor.modules.recon.screenshot import screenshots_to_base64
            screenshots = screenshots_to_base64(screenshots_dir)

        # Pre-compute helper data for the template.
        host_ip_map: dict[str, str] = data.get("host_ip_map", {})
        if not host_ip_map:
            host_ip_map = {
                h.get("id", ""): h.get("ip", h.get("id", ""))
                for h in data["hosts"]
            }

        host_port_counts: dict[str, int] = {}
        for p in data.get("ports", []):
            hid = p.get("host_id", "")
            host_port_counts[hid] = host_port_counts.get(hid, 0) + 1

        # Sort findings: critical first, then high, medium, low, info.
        sorted_findings = sorted(
            data["findings"],
            key=lambda f: _SEVERITY_ORDER.get(
                (f.get("severity") or "info").lower() if isinstance(f.get("severity"), str) else "info",
                99,
            ),
        )

        # Top 3 critical/high findings for executive summary.
        top_critical = [
            f for f in sorted_findings
            if (f.get("severity") or "info").lower() in ("critical", "high")
        ][:3]

        # Overall risk rating.
        overall_risk = _determine_overall_risk(severity_counts)

        # Executive summary narrative.
        executive_summary = self._generate_executive_summary(data)

        # ATT&CK heatmap data.
        attack_tactics, attack_techniques, attack_matrix = _build_attack_matrix(
            data["findings"],
        )

        # Annotate module_runs with computed duration.
        for mr in data.get("module_runs", []):
            mr["duration"] = _compute_duration(
                mr.get("started_at"), mr.get("completed_at"),
            )

        # Consolidated findings and correlation stats.
        consolidated_findings = data.get("consolidated_findings", [])
        correlation_stats = data.get("correlation_stats", {})

        # Compliance and prioritization data.
        compliance_report = data.get("compliance_report", {})
        compliance_summary = data.get("compliance_summary", {})
        prioritized_findings = data.get("prioritized_findings", [])

        # Branding: resolve logo to base64 data URI if path provided.
        branding = branding or {}
        logo_data_uri = ""
        if branding.get("logo_path"):
            logo_data_uri = self._logo_to_data_uri(branding["logo_path"])

        # Render the template.
        template = self._jinja_env.get_template("report.html.j2")
        rendered = template.render(
            scan_date=now.strftime("%Y-%m-%d"),
            generation_time=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            stats=data["stats"],
            severity_counts=severity_counts,
            overall_risk=overall_risk,
            total_ports=len(data.get("ports", [])),
            total_credentials=len(data.get("credentials", [])),
            top_critical=top_critical,
            findings=sorted_findings,
            consolidated_findings=consolidated_findings,
            correlation_stats=correlation_stats,
            hosts=data["hosts"],
            host_ip_map=host_ip_map,
            host_port_counts=host_port_counts,
            ports=data.get("ports", []),
            credentials=data.get("credentials", []),
            attack_paths=data.get("attack_paths", []),
            attack_tactics=attack_tactics,
            attack_techniques=attack_techniques,
            attack_matrix=attack_matrix,
            module_runs=data.get("module_runs", []),
            attack_layer_json=json.dumps(attack_layer, indent=2),
            screenshots=screenshots,
            executive_summary=executive_summary,
            compliance_report=compliance_report,
            compliance_summary=compliance_summary,
            prioritized_findings=prioritized_findings,
            brand_name=branding.get("company_name", ""),
            brand_logo=logo_data_uri,
            classification=branding.get("classification", ""),
        )

        path = self.output_dir / "report.html"
        path.write_text(rendered, encoding="utf-8")

        # Also save the Navigator layer separately.
        layer_path = self.output_dir / "attack_navigator_layer.json"
        layer_path.write_text(
            json.dumps(attack_layer, indent=2), encoding="utf-8",
        )

        return path

    # ── Markdown ─────────────────────────────────────────────────────

    async def _generate_markdown(self, data: dict[str, Any]) -> Path:
        severity_counts = data["stats"].get("findings_by_severity", {})
        correlation_stats = data.get("correlation_stats", {})
        consolidated = data.get("consolidated_findings", [])

        # Resolve host_ip_map for UUID -> IP translation.
        host_ip_map: dict[str, str] = data.get("host_ip_map", {})
        if not host_ip_map:
            host_ip_map = {
                h.get("id", ""): h.get("ip", h.get("id", ""))
                for h in data.get("hosts", [])
            }

        def _resolve_ip(host_id: str) -> str:
            """Resolve a host_id UUID to its IP address."""
            return host_ip_map.get(host_id, host_id) if host_id else ""

        lines = [
            "# PACDOOR Assessment Report\n",
            f"**Hosts:** {data['stats']['total_hosts']} | "
            f"**Findings:** {data['stats']['total_findings']} | "
            f"**Unique Findings:** {data['stats'].get('total_consolidated', len(consolidated))} | "
            f"**Critical:** {severity_counts.get('critical', 0)} | "
            f"**High:** {severity_counts.get('high', 0)}\n",
        ]

        # Executive summary.
        exec_summary = self._generate_executive_summary(data)
        lines.extend([
            "\n## Executive Summary\n",
            f"**Overall Risk Rating:** {exec_summary['overall_risk'].upper()}\n",
            exec_summary["narrative"],
            "",
            f"**Remediation Timeline:** {exec_summary['remediation_timeline']}\n",
        ])

        # Consolidated findings (default view).
        if consolidated:
            lines.extend([
                "\n## Consolidated Findings\n",
                "| Severity | Title | Hosts Affected | Module | CVE |",
                "|----------|-------|----------------|--------|-----|",
            ])
            for cf in consolidated:
                sev = _md_esc(cf.get("severity", ""))
                title = _md_esc(cf.get("title", ""))
                count = cf.get("affected_count", 0)
                module = _md_esc(cf.get("module_name", ""))
                cve = _md_esc(cf.get("cve_id", "") or "")
                hosts_str = f"{count} host{'s' if count != 1 else ''}"
                lines.append(f"| {sev} | {title} | {hosts_str} | {module} | {cve} |")

            # Top widespread findings.
            top = correlation_stats.get("top_widespread", [])
            if top:
                lines.extend([
                    "\n### Top 5 Most Widespread Findings\n",
                ])
                for i, tw in enumerate(top, 1):
                    lines.append(
                        f"{i}. **{_md_esc(tw.get('title', ''))}** "
                        f"({tw.get('severity', 'info')}) "
                        f"-- {tw.get('affected_count', 0)} hosts"
                    )
                lines.append("")

            # Dedup stats.
            if correlation_stats:
                lines.extend([
                    f"\n> **Dedup ratio:** {correlation_stats.get('total_raw', 0)} raw findings "
                    f"-> {correlation_stats.get('total_consolidated', 0)} unique "
                    f"({correlation_stats.get('dedup_ratio', 1.0)}x reduction)\n",
                ])

        # Remediation priority.
        prioritized = data.get("prioritized_findings", [])
        if prioritized:
            lines.extend([
                "\n## Remediation Priority\n",
                "| Rank | Score | Severity | Title | Affected | Category |",
                "|------|-------|----------|-------|----------|----------|",
            ])
            for pf in prioritized[:20]:  # Top 20 in markdown.
                lines.append(
                    f"| {pf.get('rank', '')} "
                    f"| {pf.get('score', 0):.1f} "
                    f"| {_md_esc(pf.get('severity', ''))} "
                    f"| {_md_esc(pf.get('title', ''))} "
                    f"| {pf.get('affected_count', 0)} "
                    f"| {_md_esc(pf.get('remediation_category', ''))} |"
                )

        # Compliance summary.
        compliance_summary = data.get("compliance_summary", {})
        if compliance_summary:
            lines.extend(["\n## Compliance Mapping\n"])
            for fw_name, fw_data in compliance_summary.items():
                violated = fw_data.get("controls_violated", [])
                total = fw_data.get("total_controls", 0)
                gap = fw_data.get("compliance_gap_pct", 0)
                lines.append(
                    f"### {fw_name}\n\n"
                    f"**Controls Violated:** {len(violated)}/{total} "
                    f"({gap}% gap)\n"
                )
                for detail in fw_data.get("details", []):
                    lines.append(
                        f"- **{detail['control_id']}** {detail.get('title', '')} "
                        f"({detail.get('finding_count', 0)} findings)"
                    )
                lines.append("")

        # Raw findings table.
        lines.extend([
            "\n## All Findings (Raw)\n",
            "| Severity | Title | Module | CVE |",
            "|----------|-------|--------|-----|",
        ])
        for f in data["findings"]:
            sev = _md_esc(f.get("severity", ""))
            title = _md_esc(f.get("title", ""))
            module = _md_esc(f.get("module_name", ""))
            cve = _md_esc(f.get("cve_id", "") or "")
            lines.append(f"| {sev} | {title} | {module} | {cve} |")

        # Ports table -- use host IP instead of raw host_id UUID.
        lines.extend([
            "\n## Ports\n",
            "| Host | Port | Protocol | State | Service | Version |",
            "|------|------|----------|-------|---------|---------|",
        ])
        for p in data.get("ports", []):
            host_ip = _resolve_ip(p.get("host_id", ""))
            lines.append(
                f"| {_md_esc(host_ip)} "
                f"| {_md_esc(p.get('port', ''))} "
                f"| {_md_esc(p.get('protocol', ''))} "
                f"| {_md_esc(p.get('state', ''))} "
                f"| {_md_esc(p.get('service_name', '') or '')} "
                f"| {_md_esc(p.get('service_version', '') or '')} |"
            )

        # Credentials table
        lines.extend([
            "\n## Credentials\n",
            "| Host | Username | Type | Source | Admin |",
            "|------|----------|------|--------|-------|",
        ])
        for c in data.get("credentials", []):
            lines.append(
                f"| {_md_esc(_resolve_ip(c.get('host_id', '')))} "
                f"| {_md_esc(c.get('username', ''))} "
                f"| {_md_esc(c.get('cred_type', ''))} "
                f"| {_md_esc(c.get('source_module', ''))} "
                f"| {'Yes' if c.get('admin') else 'No'} |"
            )

        # Attack paths table
        lines.extend([
            "\n## Attack Paths\n",
            "| Step | From | To | Technique | Description |",
            "|------|------|----|-----------|-------------|",
        ])
        for ap in data.get("attack_paths", []):
            lines.append(
                f"| {_md_esc(ap.get('step_order', ''))} "
                f"| {_md_esc(ap.get('from_host_id', ''))} "
                f"| {_md_esc(ap.get('to_host_id', ''))} "
                f"| {_md_esc(ap.get('technique_id', ''))} "
                f"| {_md_esc(ap.get('description', ''))} |"
            )

        path = self.output_dir / "report.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    # ── Executive Summary ──────────────────────────────────────────

    def _generate_executive_summary(self, data: dict[str, Any]) -> dict[str, Any]:
        """Generate a narrative executive summary from scan data.

        Returns a dict with keys:
          - overall_risk: "critical" | "high" | "medium" | "low" | "info"
          - narrative: multi-sentence summary string
          - key_stats: dict of important numbers
          - top_findings: top 3 most impactful findings
          - top_attack_paths: top attack path descriptions
          - critical_host_pct: percentage of hosts with critical vulns
          - remediation_timeline: recommended timeline string
        """
        severity_counts = data["stats"].get("findings_by_severity", {})
        overall_risk = _determine_overall_risk(severity_counts)
        total_hosts = data["stats"].get("total_hosts", 0)
        total_findings = data["stats"].get("total_findings", 0)
        total_consolidated = data["stats"].get("total_consolidated", 0)
        credentials = data.get("credentials", [])
        consolidated = data.get("consolidated_findings", [])
        attack_paths = data.get("attack_paths", [])

        # Determine how many hosts have at least one critical finding.
        critical_hosts: set[str] = set()
        for f in data.get("findings", []):
            sev = f.get("severity", "info")
            if hasattr(sev, "value"):
                sev = sev.value
            if str(sev).lower() == "critical" and f.get("host_id"):
                critical_hosts.add(f["host_id"])
        critical_host_pct = (
            round((len(critical_hosts) / total_hosts) * 100, 1)
            if total_hosts > 0
            else 0.0
        )

        # Top 3 most impactful findings (by severity then affected count).
        top_findings = []
        for cf in consolidated[:3]:
            top_findings.append({
                "title": cf.get("title", ""),
                "severity": str(cf.get("severity", "info")).lower(),
                "affected_count": cf.get("affected_count", 0),
                "cve_id": cf.get("cve_id"),
            })

        # Top attack paths.
        top_attack_paths = []
        seen_paths: set[str] = set()
        for ap in attack_paths:
            desc = ap.get("description", "")
            if desc and desc not in seen_paths:
                seen_paths.add(desc)
                top_attack_paths.append(desc)
            if len(top_attack_paths) >= 3:
                break

        # Build narrative.
        parts: list[str] = []
        parts.append(
            f"This assessment identified {total_findings} total findings "
            f"({total_consolidated} unique) across {total_hosts} hosts."
        )

        if severity_counts.get("critical", 0) > 0:
            parts.append(
                f"There are {severity_counts['critical']} critical-severity findings "
                f"requiring immediate attention."
            )
        if severity_counts.get("high", 0) > 0:
            parts.append(
                f"{severity_counts['high']} high-severity findings were also identified."
            )

        if critical_host_pct > 0:
            parts.append(
                f"{critical_host_pct}% of assessed hosts have at least one "
                f"critical vulnerability."
            )

        if credentials:
            admin_creds = sum(1 for c in credentials if c.get("admin"))
            parts.append(
                f"{len(credentials)} credentials were recovered "
                f"({admin_creds} with administrative privileges)."
            )

        if top_findings:
            top = top_findings[0]
            parts.append(
                f"The most impactful finding is \"{top['title']}\" "
                f"({top['severity']}) affecting {top['affected_count']} host(s)."
            )

        if top_attack_paths:
            parts.append(
                f"Attack path analysis revealed {len(attack_paths)} lateral "
                f"movement opportunities."
            )

        narrative = " ".join(parts)

        # Remediation timeline recommendation.
        if overall_risk == "critical":
            timeline = "Immediate (24-48 hours for critical findings, 1 week for high)"
        elif overall_risk == "high":
            timeline = "Urgent (1 week for high findings, 2 weeks for medium)"
        elif overall_risk == "medium":
            timeline = "Standard (2 weeks for medium findings, 1 month for low)"
        else:
            timeline = "Routine (address findings within standard patch cycle)"

        return {
            "overall_risk": overall_risk,
            "narrative": narrative,
            "key_stats": {
                "total_hosts": total_hosts,
                "total_findings": total_findings,
                "total_consolidated": total_consolidated,
                "credentials_found": len(credentials),
                "severity_counts": severity_counts,
            },
            "top_findings": top_findings,
            "top_attack_paths": top_attack_paths,
            "critical_host_pct": critical_host_pct,
            "remediation_timeline": timeline,
        }

    # ── PDF Output ───────────────────────────────────────────────

    async def _generate_pdf(
        self,
        data: dict[str, Any],
        branding: dict[str, Any] | None = None,
    ) -> Path:
        """Render the HTML report to PDF using WeasyPrint.

        Falls back to saving the HTML if WeasyPrint is not installed.
        """
        # First generate the HTML (we render PDF from it).
        html_path = await self._generate_html(data, branding=branding)
        html_content = html_path.read_text(encoding="utf-8")

        pdf_path = self.output_dir / "report.pdf"
        try:
            from weasyprint import HTML as WeasyHTML  # type: ignore[import-untyped]
            WeasyHTML(string=html_content, base_url=str(self.output_dir)).write_pdf(
                str(pdf_path),
            )
            log.info("PDF report generated: %s", pdf_path)
        except ImportError:
            log.warning(
                "weasyprint not installed -- PDF generation skipped. "
                "Install with: pip install weasyprint"
            )
            # Return the HTML path as fallback.
            return html_path
        except Exception:
            log.exception("PDF generation failed")
            return html_path

        return pdf_path

    # ── Branding helpers ─────────────────────────────────────────

    @staticmethod
    def _logo_to_data_uri(logo_path: str) -> str:
        """Convert a logo image file to a base64 data URI."""
        path = Path(logo_path)
        if not path.is_file():
            log.warning("Logo file not found: %s", logo_path)
            return ""

        suffix = path.suffix.lower()
        mime_types = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".webp": "image/webp",
        }
        mime = mime_types.get(suffix, "image/png")

        try:
            raw = path.read_bytes()
            b64 = base64.b64encode(raw).decode("ascii")
            return f"data:{mime};base64,{b64}"
        except Exception:
            log.exception("Failed to read logo file: %s", logo_path)
            return ""

    # ── Diff Report ──────────────────────────────────────────────

    async def generate_diff(self, diff: DiffResult) -> Path:
        """Generate an HTML diff report comparing two scan databases.

        Can be called without a full ReportGenerator initialization
        (no DB needed -- the diff data is already computed).
        """
        return self._generate_diff_html(diff)

    def _generate_diff_html(self, diff: DiffResult) -> Path:
        """Render the diff report as a self-contained HTML file."""
        now = datetime.now(UTC)
        stats = diff.stats

        # Severity ordering for sorting findings.
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        def _sort_findings(findings: list[dict]) -> list[dict]:
            return sorted(
                findings,
                key=lambda f: sev_order.get(
                    str(f.get("severity", "info")).lower(), 99
                ),
            )

        new_sorted = _sort_findings(diff.new_findings)
        fixed_sorted = _sort_findings(diff.fixed_findings)
        persistent_sorted = _sort_findings(diff.persistent_findings)

        # Build the HTML inline (no Jinja2 template needed for diff).
        parts: list[str] = []
        parts.append(
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            '<title>PACDOOR Scan Diff Report</title>\n'
            '<style>\n'
            '*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n'
            ':root {\n'
            '  --bg: #0a0a0a; --bg2: #111; --bg3: #1a1a1a; --border: #2a2a2a;\n'
            '  --text: #e0e0e0; --text2: #999; --accent: #00ff41;\n'
            '  --red: #dc2626; --green: #22c55e; --yellow: #eab308; --grey: #6b7280;\n'
            '  --font-mono: "JetBrains Mono", "Consolas", monospace;\n'
            '  --font-sans: "Inter", -apple-system, sans-serif;\n'
            '}\n'
            'body { font-family: var(--font-sans); background: var(--bg); color: var(--text); line-height: 1.6; }\n'
            '.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }\n'
            'h1 { font-family: var(--font-mono); color: var(--accent); letter-spacing: 3px; font-size: 2em; }\n'
            'h2 { font-family: var(--font-mono); color: var(--accent); letter-spacing: 1px; font-size: 1.2em;\n'
            '     border-bottom: 2px solid #004411; padding-bottom: 8px; margin: 32px 0 16px; }\n'
            '.header { padding: 32px 0; border-bottom: 1px solid #004411; }\n'
            '.subtitle { color: var(--text2); font-size: 0.9em; margin-top: 4px; }\n'
            '.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 24px 0; }\n'
            '.stat-card { background: #141414; border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }\n'
            '.stat-card .val { font-family: var(--font-mono); font-size: 2em; font-weight: 800; line-height: 1.1; }\n'
            '.stat-card .lbl { font-size: 0.8em; color: var(--text2); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }\n'
            '.val.green { color: var(--green); } .val.red { color: var(--red); } .val.grey { color: var(--grey); }\n'
            'table { width: 100%; border-collapse: collapse; font-size: 0.9em; }\n'
            'th { background: var(--bg3); color: #00cc33; font-family: var(--font-mono); font-size: 0.8em;\n'
            '     text-transform: uppercase; letter-spacing: 1px; padding: 10px 14px; text-align: left; border-bottom: 2px solid #333; }\n'
            'td { padding: 8px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }\n'
            'tbody tr { background: var(--bg); } tbody tr:nth-child(even) { background: var(--bg2); }\n'
            '.sev { display: inline-block; padding: 2px 8px; border-radius: 10px; font-family: var(--font-mono);\n'
            '       font-size: 0.75em; font-weight: 700; text-transform: uppercase; color: #fff; }\n'
            '.sev.critical { background: var(--red); } .sev.high { background: #ea580c; }\n'
            '.sev.medium { background: #d97706; } .sev.low { background: #65a30d; } .sev.info { background: var(--grey); }\n'
            '.tag { display: inline-block; padding: 2px 10px; border-radius: 10px; font-family: var(--font-mono);\n'
            '       font-size: 0.75em; font-weight: 700; text-transform: uppercase; }\n'
            '.tag.new { background: rgba(220, 38, 38, 0.15); color: #fca5a5; }\n'
            '.tag.fixed { background: rgba(34, 197, 94, 0.15); color: #86efac; }\n'
            '.tag.persistent { background: rgba(107, 114, 128, 0.15); color: #d1d5db; }\n'
            '.hosts-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }\n'
            '.host-chip { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px;\n'
            '             padding: 2px 8px; font-family: var(--font-mono); font-size: 0.85em; }\n'
            '.host-chip.added { border-color: var(--green); color: var(--green); }\n'
            '.host-chip.removed { border-color: var(--red); color: var(--red); }\n'
            '.empty { text-align: center; padding: 32px; color: #666; font-style: italic; }\n'
            '.tw { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }\n'
            '.footer { border-top: 1px solid var(--border); padding: 24px 0; margin-top: 48px;\n'
            '          text-align: center; color: #666; font-size: 0.85em; }\n'
            '.footer .brand { font-family: var(--font-mono); color: #004411; letter-spacing: 2px; }\n'
            '</style>\n</head>\n<body>\n'
        )

        # Header.
        parts.append(
            '<header class="header"><div class="container">\n'
            '<h1>PACDOOR</h1>\n'
            '<div class="subtitle">Scan Diff Report</div>\n'
            f'<div class="subtitle">Generated: {_esc(now.strftime("%Y-%m-%d %H:%M:%S UTC"))}</div>\n'
            '</div></header>\n'
            '<main class="container">\n'
        )

        # Stats dashboard.
        parts.append('<div class="stats-grid">\n')
        stat_cards = [
            (str(stats.get("findings_fixed", 0)), "Fixed", "green"),
            (str(stats.get("findings_new", 0)), "New", "red"),
            (str(stats.get("findings_persistent", 0)), "Persistent", "grey"),
            (str(stats.get("hosts_added", 0)), "Hosts Added", "green"),
            (str(stats.get("hosts_removed", 0)), "Hosts Removed", "red"),
            (str(stats.get("credentials_new", 0)), "New Creds", "red"),
        ]
        for val, label, color in stat_cards:
            parts.append(
                f'<div class="stat-card"><div class="val {color}">{_esc(val)}</div>'
                f'<div class="lbl">{_esc(label)}</div></div>\n'
            )
        parts.append('</div>\n')

        # Summary sentence.
        parts.append(
            f'<p style="color:var(--text2);margin-bottom:24px">'
            f'{stats.get("findings_fixed", 0)} findings fixed, '
            f'{stats.get("findings_new", 0)} new findings, '
            f'{stats.get("findings_persistent", 0)} persistent</p>\n'
        )

        # Host changes.
        if diff.new_hosts or diff.removed_hosts:
            parts.append('<h2>HOST CHANGES</h2>\n')
            if diff.new_hosts:
                parts.append('<p style="font-size:0.9em;color:var(--text2)">New hosts:</p>\n<div class="hosts-list">\n')
                for h in diff.new_hosts:
                    parts.append(f'<span class="host-chip added">+ {_esc(h)}</span>\n')
                parts.append('</div>\n')
            if diff.removed_hosts:
                parts.append('<p style="font-size:0.9em;color:var(--text2);margin-top:12px">Removed hosts:</p>\n<div class="hosts-list">\n')
                for h in diff.removed_hosts:
                    parts.append(f'<span class="host-chip removed">- {_esc(h)}</span>\n')
                parts.append('</div>\n')

        # Fixed findings (green -- remediated).
        parts.append('<h2>FIXED FINDINGS (REMEDIATED)</h2>\n')
        if fixed_sorted:
            parts.append(self._diff_findings_table(fixed_sorted, "fixed"))
        else:
            parts.append('<div class="empty">No findings were fixed between scans.</div>\n')

        # New findings (red -- regressions/new discoveries).
        parts.append('<h2>NEW FINDINGS</h2>\n')
        if new_sorted:
            parts.append(self._diff_findings_table(new_sorted, "new"))
        else:
            parts.append('<div class="empty">No new findings in the latest scan.</div>\n')

        # Persistent findings (grey -- still present).
        parts.append('<h2>PERSISTENT FINDINGS</h2>\n')
        if persistent_sorted:
            parts.append(self._diff_findings_table(persistent_sorted, "persistent"))
        else:
            parts.append('<div class="empty">No persistent findings.</div>\n')

        # New credentials.
        if diff.new_credentials:
            parts.append('<h2>NEW CREDENTIALS</h2>\n')
            parts.append(
                '<div class="tw"><table>\n<thead><tr>'
                '<th>Host</th><th>Username</th><th>Type</th><th>Source</th><th>Admin</th>'
                '</tr></thead>\n<tbody>\n'
            )
            for c in diff.new_credentials:
                admin = "Yes" if c.get("admin") else "No"
                parts.append(
                    f'<tr><td style="font-family:var(--font-mono)">{_esc(c.get("host_id", ""))}</td>'
                    f'<td style="font-family:var(--font-mono)">{_esc(c.get("username", ""))}</td>'
                    f'<td>{_esc(c.get("cred_type", ""))}</td>'
                    f'<td style="font-size:0.85em;color:var(--text2)">{_esc(c.get("source_module", ""))}</td>'
                    f'<td>{admin}</td></tr>\n'
                )
            parts.append('</tbody></table></div>\n')

        # Footer.
        parts.append(
            '</main>\n<footer class="footer"><div class="container">\n'
            '<div class="brand">PACDOOR</div>\n'
            f'<div style="margin-top:8px">Scan Diff Report &middot; {_esc(now.strftime("%Y-%m-%d %H:%M:%S UTC"))}</div>\n'
            '</div></footer>\n</body>\n</html>'
        )

        path = self.output_dir / "diff_report.html"
        path.write_text("".join(parts), encoding="utf-8")
        return path

    @staticmethod
    def _diff_findings_table(findings: list[dict], tag_type: str) -> str:
        """Render a findings table for the diff report."""
        rows: list[str] = []
        rows.append(
            '<div class="tw"><table>\n<thead><tr>'
            '<th>Status</th><th>Severity</th><th>Title</th>'
            '<th>Host</th><th>Module</th><th>CVE</th>'
            '</tr></thead>\n<tbody>\n'
        )
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            host_ip = _esc(f.get("host_ip", f.get("host_id", "")))
            title = _esc(f.get("title", ""))
            module = _esc(f.get("module_name", ""))
            cve = _esc(f.get("cve_id", "")) if f.get("cve_id") else "&mdash;"
            rows.append(
                f'<tr><td><span class="tag {tag_type}">{tag_type}</span></td>'
                f'<td><span class="sev {sev}">{sev}</span></td>'
                f'<td>{title}</td>'
                f'<td style="font-family:var(--font-mono)">{host_ip}</td>'
                f'<td style="font-size:0.85em;color:var(--text2)">{module}</td>'
                f'<td style="font-family:var(--font-mono)">{cve}</td></tr>\n'
            )
        rows.append('</tbody></table></div>\n')
        return "".join(rows)
