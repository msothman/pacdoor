"""Remediation prioritization engine.

Scores and ranks consolidated findings to produce an actionable
remediation plan.  Each finding receives a priority score based on
severity, affected host count, exploitability, and estimated
remediation effort.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel

log = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────────────


class PrioritizedFinding(BaseModel):
    """A consolidated finding enriched with remediation priority data."""

    rank: int = 0
    score: float = 0.0
    title: str
    severity: str = "info"
    cve_id: str | None = None
    module_name: str = ""
    affected_count: int = 1
    exploitability: float = 1.0
    remediation_effort: float = 1.0
    remediation_category: str = "patch_required"
    description: str = ""
    remediation: str = ""


# ── Scoring constants ────────────────────────────────────────────────

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.0,
}

# Module name substrings -> remediation effort estimate.
# config change = 1 (quick), patch = 2 (moderate), architecture = 3 (heavy).
_EFFORT_MAP: list[tuple[str, float, str]] = [
    # Configuration changes (effort 1) -- quick wins.
    ("header", 1.0, "quick_win"),
    ("smb_sign", 1.0, "quick_win"),
    ("ssl", 1.0, "quick_win"),
    ("tls", 1.0, "quick_win"),
    ("cipher", 1.0, "quick_win"),
    ("default_cred", 1.0, "quick_win"),
    ("anonymous", 1.0, "quick_win"),
    ("config", 1.0, "quick_win"),
    ("policy", 1.0, "quick_win"),
    ("permission", 1.0, "quick_win"),
    # Patching (effort 2).
    ("cve", 2.0, "patch_required"),
    ("nuclei", 2.0, "patch_required"),
    ("vuln", 2.0, "patch_required"),
    ("exploit", 2.0, "patch_required"),
    ("version", 2.0, "patch_required"),
    ("patch", 2.0, "patch_required"),
    ("update", 2.0, "patch_required"),
    # Architecture changes (effort 3).
    ("network", 3.0, "architecture_change"),
    ("segment", 3.0, "architecture_change"),
    ("architecture", 3.0, "architecture_change"),
    ("redesign", 3.0, "architecture_change"),
    ("migration", 3.0, "architecture_change"),
    ("replace", 3.0, "architecture_change"),
    ("eol", 3.0, "architecture_change"),
    ("end_of_life", 3.0, "architecture_change"),
]

# Title-based effort overrides for common finding patterns.
_TITLE_EFFORT_MAP: list[tuple[str, float, str]] = [
    ("missing.*header", 1.0, "quick_win"),
    ("default.*credential", 1.0, "quick_win"),
    ("default.*password", 1.0, "quick_win"),
    ("smb.*sign", 1.0, "quick_win"),
    ("weak.*cipher", 1.0, "quick_win"),
    ("weak.*tls", 1.0, "quick_win"),
    ("self.signed", 1.0, "quick_win"),
    ("sql.*inject", 2.0, "patch_required"),
    ("xss", 2.0, "patch_required"),
    ("command.*inject", 2.0, "patch_required"),
    ("remote.*code.*exec", 2.0, "patch_required"),
    ("end.of.life", 3.0, "architecture_change"),
    ("unsupported.*version", 3.0, "architecture_change"),
]


# ── Prioritizer ──────────────────────────────────────────────────────


def _determine_exploitability(finding: dict[str, Any]) -> float:
    """Determine the exploitability multiplier for a finding.

    - 2.0 if the finding is verified/exploited (confirmed exploitable).
    - 1.5 if the finding has an associated CVE (known vulnerability).
    - 1.0 otherwise (theoretical / info-level).
    """
    if finding.get("verified"):
        return 2.0
    cve_id = finding.get("cve_id")
    if cve_id and str(cve_id).strip():
        return 1.5
    return 1.0


def _determine_effort(finding: dict[str, Any]) -> tuple[float, str]:
    """Estimate remediation effort and category from finding metadata.

    Returns (effort_score, category_label).
    """
    title = (finding.get("title") or "").lower()
    module = (finding.get("module_name") or "").lower()

    # Check title patterns first (more specific).
    import re
    for pattern, effort, category in _TITLE_EFFORT_MAP:
        if re.search(pattern, title, re.IGNORECASE):
            return effort, category

    # Check module name substrings.
    for substring, effort, category in _EFFORT_MAP:
        if substring in module:
            return effort, category

    # Default: patch-level effort.
    return 2.0, "patch_required"


class RemediationPrioritizer:
    """Scores and ranks findings for remediation prioritization.

    Priority formula::

        priority = severity_weight * affected_hosts * exploitability / remediation_effort

    Higher scores indicate findings that should be addressed first.

    Usage::

        prioritizer = RemediationPrioritizer()
        ranked = prioritizer.prioritize(consolidated_findings)
    """

    def prioritize(
        self,
        consolidated_findings: list[dict[str, Any]],
    ) -> list[PrioritizedFinding]:
        """Score and rank a list of consolidated findings.

        Args:
            consolidated_findings: List of consolidated finding dicts
                (as returned by FindingCorrelator, serialized via
                model_dump).

        Returns:
            List of PrioritizedFinding sorted by score descending (rank 1 = highest).
        """
        scored: list[PrioritizedFinding] = []

        for cf in consolidated_findings:
            severity = cf.get("severity", "info")
            if hasattr(severity, "value"):
                severity = severity.value
            severity = str(severity).lower()

            sev_weight = _SEVERITY_WEIGHT.get(severity, 0.0)

            # Skip info-level findings (score would be 0).
            if sev_weight == 0.0:
                continue

            affected = max(cf.get("affected_count", 1), 1)
            exploitability = _determine_exploitability(cf)
            effort, category = _determine_effort(cf)

            # Avoid division by zero.
            effort = max(effort, 0.1)

            score = round(sev_weight * affected * exploitability / effort, 2)

            scored.append(
                PrioritizedFinding(
                    title=cf.get("title", ""),
                    severity=severity,
                    cve_id=cf.get("cve_id"),
                    module_name=cf.get("module_name", ""),
                    affected_count=affected,
                    exploitability=exploitability,
                    remediation_effort=effort,
                    remediation_category=category,
                    score=score,
                    description=cf.get("description", ""),
                    remediation=cf.get("remediation", ""),
                )
            )

        # Sort by score descending.
        scored.sort(key=lambda p: -p.score)

        # Assign ranks.
        for i, pf in enumerate(scored, 1):
            pf.rank = i

        log.info(
            "Prioritized %d findings (top score: %.1f)",
            len(scored),
            scored[0].score if scored else 0.0,
        )
        return scored
