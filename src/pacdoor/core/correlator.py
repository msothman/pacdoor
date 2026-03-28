"""Finding deduplication and correlation engine.

When the same vulnerability exists on 50 hosts, produce 1 consolidated
finding with 50 affected hosts instead of 50 separate findings.

Correlation rules (in priority order):
  1. Same CVE ID  -> merge regardless of title
  2. Same template_id (nuclei/template scanner)  -> merge
  3. Same title + same module_name + same severity  -> merge

This dramatically reduces noise in reports for large scans where
findings like "Missing X-Content-Type-Options" appear on every host.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from pacdoor.core.models import (
    ConsolidatedFinding,
    Evidence,
    Severity,
)

log = logging.getLogger(__name__)

# Maximum number of evidence samples to keep per consolidated finding.
MAX_EVIDENCE_SAMPLES = 3

# Severity ordering for picking the "worst" severity in a group.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _normalize_severity(sev: Any) -> str:
    """Normalize severity to lowercase string."""
    if isinstance(sev, str):
        return sev.lower()
    if hasattr(sev, "value"):
        return str(sev.value).lower()
    return str(sev).lower()


def _extract_template_id(finding: dict[str, Any]) -> str | None:
    """Extract template_id from a finding's title or evidence.

    Nuclei findings have titles like "[nuclei:CVE-2021-44228] ..." and
    template scanner findings store template_id in evidence data.
    """
    title = finding.get("title", "")

    # Pattern: [nuclei:TEMPLATE_ID] ...
    match = re.match(r"^\[nuclei:([^\]]+)\]", title)
    if match:
        return f"nuclei:{match.group(1)}"

    # Pattern: [template:TEMPLATE_ID] ...
    match = re.match(r"^\[template:([^\]]+)\]", title)
    if match:
        return f"template:{match.group(1)}"

    # Check evidence for template_id
    evidence = finding.get("evidence", [])
    if isinstance(evidence, list):
        for ev in evidence:
            if isinstance(ev, dict):
                data = ev.get("data", "")
                if "template_id" in data:
                    # Try to parse "template_id: XYZ" from evidence data
                    tmatch = re.search(r"template_id[:\s]+(\S+)", data)
                    if tmatch:
                        return f"evidence:{tmatch.group(1)}"

    return None


def _resolve_host_ip(
    finding: dict[str, Any],
    host_ip_map: dict[str, str],
) -> str:
    """Resolve a finding's host_id to an IP address."""
    host_id = finding.get("host_id", "")
    if host_id and host_id in host_ip_map:
        return host_ip_map[host_id]
    # Fallback: use host_id itself (may already be an IP).
    return host_id or "unknown"


def _worst_severity(a: str, b: str) -> str:
    """Return the more severe of two severity strings."""
    if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0):
        return a
    return b


def _parse_datetime(value: Any) -> datetime:
    """Parse a datetime from various formats."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            pass
    return datetime.now(UTC)


class FindingCorrelator:
    """Correlates and deduplicates findings across hosts.

    Usage::

        correlator = FindingCorrelator(host_ip_map)
        consolidated = correlator.correlate(raw_findings)
        stats = correlator.statistics(raw_findings, consolidated)
    """

    def __init__(self, host_ip_map: dict[str, str] | None = None) -> None:
        """Initialize the correlator.

        Args:
            host_ip_map: Mapping of host UUIDs to IP addresses.
                         Used to display IPs instead of opaque UUIDs.
        """
        self._host_ip_map = host_ip_map or {}

    def correlate(
        self, findings: list[dict[str, Any]],
    ) -> list[ConsolidatedFinding]:
        """Correlate a list of raw findings into consolidated findings.

        Correlation rules applied in priority order:
          1. Same CVE ID -> merge
          2. Same template_id -> merge
          3. Same (title, module_name, severity) -> merge

        Returns a list of ConsolidatedFinding sorted by severity (worst first),
        then by affected_count (most widespread first).
        """
        if not findings:
            return []

        # Phase 1: Group by correlation key.
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        finding_to_key: dict[str, str] = {}  # finding_id -> group_key

        for f in findings:
            fid = f.get("id", "")
            key = self._correlation_key(f)
            groups[key].append(f)
            finding_to_key[fid] = key

        # Phase 2: Merge each group into a ConsolidatedFinding.
        consolidated: list[ConsolidatedFinding] = []
        for _group_key, group_findings in groups.items():
            cf = self._merge_group(group_findings)
            consolidated.append(cf)

        # Phase 3: Sort by severity (worst first), then affected count.
        consolidated.sort(
            key=lambda c: (
                -_SEVERITY_RANK.get(_normalize_severity(c.severity), 0),
                -c.affected_count,
                c.title,
            ),
        )

        log.info(
            "Correlated %d raw findings into %d consolidated findings",
            len(findings), len(consolidated),
        )
        return consolidated

    def _correlation_key(self, finding: dict[str, Any]) -> str:
        """Compute the correlation key for a finding.

        Priority: CVE > template_id > (title, module, severity).
        """
        # Rule 1: Same CVE ID.
        cve = finding.get("cve_id")
        if cve and isinstance(cve, str) and cve.strip():
            return f"cve:{cve.strip().upper()}"

        # Rule 2: Same template_id.
        template_id = _extract_template_id(finding)
        if template_id:
            return f"tpl:{template_id}"

        # Rule 3: Same title + module + severity.
        title = finding.get("title", "").strip()
        module = finding.get("module_name", "").strip()
        severity = _normalize_severity(finding.get("severity", "info"))
        return f"sig:{title}|{module}|{severity}"

    def _merge_group(
        self, group: list[dict[str, Any]],
    ) -> ConsolidatedFinding:
        """Merge a group of related findings into one ConsolidatedFinding."""
        # Use the first finding as the base for metadata.
        base = group[0]

        # Collect all affected hosts (deduplicated, ordered).
        seen_hosts: set[str] = set()
        affected_hosts: list[str] = []
        for f in group:
            host_ip = _resolve_host_ip(f, self._host_ip_map)
            if host_ip and host_ip not in seen_hosts:
                seen_hosts.add(host_ip)
                affected_hosts.append(host_ip)

        # Collect evidence samples (first N unique).
        evidence_samples: list[Evidence] = []
        for f in group:
            raw_evidence = f.get("evidence", [])
            if isinstance(raw_evidence, list):
                for ev in raw_evidence:
                    if len(evidence_samples) >= MAX_EVIDENCE_SAMPLES:
                        break
                    if isinstance(ev, dict):
                        evidence_samples.append(
                            Evidence(
                                kind=ev.get("kind", "raw"),
                                data=ev.get("data", ""),
                            )
                        )
                    elif isinstance(ev, Evidence):
                        evidence_samples.append(ev)
            if len(evidence_samples) >= MAX_EVIDENCE_SAMPLES:
                break

        # Merge attack technique IDs (deduplicated, ordered).
        seen_techniques: set[str] = set()
        technique_ids: list[str] = []
        for f in group:
            raw_techniques = f.get("attack_technique_ids", [])
            if isinstance(raw_techniques, str):
                # Handle JSON-stringified lists.
                try:
                    raw_techniques = json.loads(raw_techniques)
                except (json.JSONDecodeError, TypeError):
                    raw_techniques = [raw_techniques] if raw_techniques else []
            if isinstance(raw_techniques, list):
                for t in raw_techniques:
                    if t and t not in seen_techniques:
                        seen_techniques.add(t)
                        technique_ids.append(t)

        # Merge references.
        seen_refs: set[str] = set()
        references: list[str] = []
        for f in group:
            for ref in f.get("references") or []:
                if ref and ref not in seen_refs:
                    seen_refs.add(ref)
                    references.append(ref)

        # Pick the worst severity across the group.
        merged_severity = _normalize_severity(base.get("severity", "info"))
        for f in group[1:]:
            merged_severity = _worst_severity(
                merged_severity, _normalize_severity(f.get("severity", "info")),
            )

        # Pick the best (highest) CVSS score.
        best_cvss: float | None = None
        best_cvss_vector: str | None = None
        for f in group:
            score = f.get("cvss_score")
            if score is not None:
                try:
                    score_f = float(score)
                    if best_cvss is None or score_f > best_cvss:
                        best_cvss = score_f
                        best_cvss_vector = f.get("cvss_vector")
                except (ValueError, TypeError):
                    pass

        # Earliest discovery time.
        first_seen = _parse_datetime(base.get("discovered_at"))
        for f in group[1:]:
            t = _parse_datetime(f.get("discovered_at"))
            if t < first_seen:
                first_seen = t

        # Pick the longest remediation text.
        best_remediation = base.get("remediation", "")
        for f in group[1:]:
            r = f.get("remediation", "")
            if len(r) > len(best_remediation):
                best_remediation = r

        # Collect source finding IDs.
        source_ids = [f.get("id", "") for f in group if f.get("id")]

        # CVE: prefer the one from the base, fallback to any in group.
        cve_id = base.get("cve_id")
        if not cve_id:
            for f in group:
                if f.get("cve_id"):
                    cve_id = f["cve_id"]
                    break

        return ConsolidatedFinding(
            title=base.get("title", "Unknown Finding"),
            description=base.get("description", ""),
            severity=Severity(merged_severity),
            cvss_score=best_cvss,
            cvss_vector=best_cvss_vector,
            cve_id=cve_id,
            attack_technique_ids=technique_ids,
            module_name=base.get("module_name", ""),
            remediation=best_remediation,
            references=references,
            affected_hosts=affected_hosts,
            affected_count=len(affected_hosts),
            first_seen=first_seen,
            evidence_samples=evidence_samples,
            source_finding_ids=source_ids,
        )

    def statistics(
        self,
        raw_findings: list[dict[str, Any]],
        consolidated: list[ConsolidatedFinding],
    ) -> dict[str, Any]:
        """Compute correlation statistics.

        Returns a dict with:
          - total_raw: number of raw findings
          - total_consolidated: number after dedup
          - dedup_ratio: raw/consolidated (higher = more dedup)
          - unique_ratio: consolidated/raw (lower = more dedup)
          - top_widespread: top 5 findings by affected host count
          - severity_distribution: {severity: count} for consolidated
        """
        total_raw = len(raw_findings)
        total_consolidated = len(consolidated)

        # Dedup ratio (how much we reduced).
        if total_consolidated > 0:
            dedup_ratio = round(total_raw / total_consolidated, 2)
        else:
            dedup_ratio = 0.0

        # Unique ratio (what fraction are truly unique).
        if total_raw > 0:
            unique_ratio = round(total_consolidated / total_raw, 4)
        else:
            unique_ratio = 0.0

        # Top 5 most widespread findings.
        sorted_by_count = sorted(
            consolidated, key=lambda c: c.affected_count, reverse=True,
        )
        top_widespread = [
            {
                "title": c.title,
                "severity": _normalize_severity(c.severity),
                "affected_count": c.affected_count,
                "cve_id": c.cve_id,
                "module": c.module_name,
            }
            for c in sorted_by_count[:5]
        ]

        # Severity distribution for consolidated findings.
        severity_dist: dict[str, int] = defaultdict(int)
        for c in consolidated:
            severity_dist[_normalize_severity(c.severity)] += 1

        return {
            "total_raw": total_raw,
            "total_consolidated": total_consolidated,
            "dedup_ratio": dedup_ratio,
            "unique_ratio": unique_ratio,
            "top_widespread": top_widespread,
            "severity_distribution": dict(severity_dist),
        }
