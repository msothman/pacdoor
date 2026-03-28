"""Adaptive strategy planner for PACDOOR's autonomous agent mode.

Analyzes scan results after each run and dynamically adjusts the scanning
strategy for subsequent runs.  Responsibilities:

  - Classify the target environment (AD-heavy, web-heavy, etc.)
  - Recommend the best scan profile for the next iteration
  - Enforce progressive safety-level escalation over time
  - Prioritize discovered hosts by attack value
  - Suggest specific modules based on findings so far

Pure logic — no I/O, no async.  Called synchronously by the scheduler
between scan runs.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from pacdoor.core.profiles import PROFILES

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment type literals
# ---------------------------------------------------------------------------

EnvironmentType = Literal[
    "ad_heavy",
    "web_heavy",
    "mixed",
    "linux_dominant",
    "flat_network",
    "segmented",
    "unknown",
]

# Safety levels in escalation order.
SAFETY_LEVELS: list[str] = ["safe", "moderate", "dangerous"]

# ---------------------------------------------------------------------------
# Recommendation model
# ---------------------------------------------------------------------------


class StrategyRecommendation(BaseModel):
    """Output of a single adaptive analysis cycle."""

    profile: str
    safety_level: str
    priority_targets: list[str] = Field(default_factory=list)
    recommended_modules: list[str] = Field(default_factory=list)
    environment_type: str = "unknown"
    rationale: str = ""


# ---------------------------------------------------------------------------
# Service-based classification signals
# ---------------------------------------------------------------------------

# Fact types (or substrings) that indicate an AD-heavy environment.
_AD_SIGNALS = {"service.ldap", "service.kerberos", "service.smb", "domain_controller"}
# Fact types that indicate a web-heavy environment.
_WEB_SIGNALS = {"service.http", "service.https", "webapp"}
# Fact types that indicate Linux hosts.
_LINUX_SIGNALS = {"service.ssh", "os.linux"}

# Map from environment classification to recommended profile.
_ENV_TO_PROFILE: dict[str, str] = {
    "ad_heavy": "ad",
    "web_heavy": "web",
    "mixed": "aggressive",
    "linux_dominant": "aggressive",
    "flat_network": "quick",
    "segmented": "aggressive",
    "unknown": "quick",
}

# ---------------------------------------------------------------------------
# Module recommendation rules
# ---------------------------------------------------------------------------

# Each entry: (trigger_key_in_facts, module_to_recommend).
# trigger_key is checked as a substring against keys in facts_summary.
_MODULE_TRIGGERS: list[tuple[str, str]] = [
    ("kerberoastable", "exploit.kerberoast"),
    ("adcs", "exploit.adcs_exploit"),
    ("delegation", "exploit.kerberos_abuse"),
    ("smb_signing_disabled", "exploit.ntlm_coerce"),
    ("domain_controller", "post.dcsync"),
    ("credential.admin", "post.lsass_dump"),
    ("credential.valid", "post.lateral_move"),
    ("service.mssql", "enum.mssql_enum"),
    ("service.http", "vuln.web_vulns"),
    ("service.smb", "vuln.smb_vulns"),
    ("gpp", "post.gpp_extract"),
    ("dpapi", "post.dpapi_extract"),
    ("dacl_abuse", "post.dacl_abuse"),
]


# ---------------------------------------------------------------------------
# Adaptive planner
# ---------------------------------------------------------------------------


class AdaptivePlanner:
    """Analyzes scan results and produces strategy recommendations.

    Parameters
    ----------
    escalation_mode:
        ``"off"`` keeps the initial safety level forever.
        ``"progressive"`` raises it over time (safe -> moderate -> dangerous).
    escalation_hours:
        Hours between each escalation step when *escalation_mode* is
        ``"progressive"``.  E.g. 3.0 means safe for 0-3 h, moderate for
        3-6 h, dangerous after 6 h.
    """

    def __init__(
        self,
        escalation_mode: str = "off",
        escalation_hours: float = 3.0,
    ) -> None:
        self._start_time: datetime = datetime.now(UTC)
        self._environment: EnvironmentType = "unknown"
        self._escalation_mode = escalation_mode
        self._escalation_hours = max(escalation_hours, 0.1)  # guard div-by-zero
        self._scan_history: list[dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        summary: dict,
        facts_summary: dict,
    ) -> StrategyRecommendation:
        """Analyze scan results and produce a strategy recommendation.

        Parameters
        ----------
        summary:
            High-level scan summary (host count, finding count, etc.).
        facts_summary:
            Mapping of fact-type prefixes to counts or lists,
            e.g. ``{"service.http": 12, "domain_controller": ["10.0.0.5"]}``.

        Returns
        -------
        StrategyRecommendation
            What to do next — profile, safety, targets, modules.
        """
        self._scan_history.append(
            {"summary": summary, "facts": facts_summary}
        )

        env = self._classify_environment(facts_summary)
        self._environment = env

        safety = self.get_current_safety()
        profile = self._pick_profile(env, safety)
        hosts = summary.get("hosts", [])
        targets = self.get_priority_targets(hosts)
        modules = self.get_recommended_modules(facts_summary)
        rationale = self._build_rationale(env, safety, targets, modules)

        return StrategyRecommendation(
            profile=profile,
            safety_level=safety,
            priority_targets=[h["ip"] for h in targets if "ip" in h],
            recommended_modules=modules,
            environment_type=env,
            rationale=rationale,
        )

    def get_current_safety(self) -> str:
        """Return the current safety level based on progressive escalation.

        With ``escalation_mode="progressive"`` and ``escalation_hours=N``:
          - Hour 0 to N   : ``"safe"``
          - Hour N to 2N  : ``"moderate"``
          - Hour 2N+      : ``"dangerous"``

        With ``escalation_mode="off"`` the level stays ``"safe"`` forever.
        """
        if self._escalation_mode != "progressive":
            return "safe"

        elapsed_hours = self._elapsed_hours()
        n = self._escalation_hours

        if elapsed_hours < n:
            return "safe"
        if elapsed_hours < 2 * n:
            return "moderate"
        return "dangerous"

    def get_priority_targets(self, hosts: list[dict]) -> list[dict]:
        """Sort hosts by attack value, highest first.

        Priority tiers (descending):
          1. Domain Controllers
          2. Hosts with admin-level credentials
          3. Hosts with known vulnerabilities
          4. Everything else
        """
        def _score(host: dict) -> int:
            score = 0
            tags = host.get("tags", [])
            if "domain_controller" in tags:
                score += 1000
            if host.get("has_admin_creds"):
                score += 500
            score += host.get("vuln_count", 0) * 10
            return score

        return sorted(hosts, key=_score, reverse=True)

    def get_recommended_modules(self, facts_summary: dict) -> list[str]:
        """Suggest specific modules based on what has been found so far.

        Scans ``facts_summary`` keys for known trigger substrings and
        collects the corresponding module recommendations.  Deduplicates
        and returns a stable-sorted list.
        """
        recommended: list[str] = []
        fact_keys = " ".join(str(k) for k in facts_summary)

        for trigger, module in _MODULE_TRIGGERS:
            if trigger in fact_keys and module not in recommended:
                recommended.append(module)

        recommended.sort()
        return recommended

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _elapsed_hours(self) -> float:
        delta = datetime.now(UTC) - self._start_time
        return delta.total_seconds() / 3600.0

    def _classify_environment(self, facts: dict) -> EnvironmentType:
        """Classify the environment based on discovered fact types."""
        ad_score = sum(1 for s in _AD_SIGNALS if s in facts)
        web_score = sum(1 for s in _WEB_SIGNALS if s in facts)
        linux_score = sum(1 for s in _LINUX_SIGNALS if s in facts)

        # Check for network segmentation (multiple subnets discovered
        # via lateral movement).
        subnets = facts.get("subnets", [])
        if isinstance(subnets, list) and len(subnets) > 1:
            return "segmented"

        # Dominant category wins; ties go to mixed.
        scores = {"ad_heavy": ad_score, "web_heavy": web_score, "linux_dominant": linux_score}
        top = max(scores.values())

        if top == 0:
            return "unknown"

        winners = [k for k, v in scores.items() if v == top]
        if len(winners) > 1:
            return "mixed"

        return winners[0]  # type: ignore[return-value]

    def _pick_profile(self, env: EnvironmentType, safety: str) -> str:
        """Choose a scan profile that exists in PROFILES.

        Falls back to ``"quick"`` if the ideal profile is missing.
        """
        ideal = _ENV_TO_PROFILE.get(env, "quick")

        if ideal not in PROFILES:
            log.warning(
                "Ideal profile %r for env %r not in PROFILES, falling back to 'quick'",
                ideal, env,
            )
            return "quick"

        # If the profile's max_safety exceeds the current allowed level,
        # pick the most capable profile that stays within bounds.
        profile_safety = PROFILES[ideal].get("max_safety", "moderate")
        if SAFETY_LEVELS.index(profile_safety) > SAFETY_LEVELS.index(safety):
            for fallback in ("quick", "stealth"):
                if fallback in PROFILES:
                    fb_safety = PROFILES[fallback].get("max_safety", "moderate")
                    if SAFETY_LEVELS.index(fb_safety) <= SAFETY_LEVELS.index(safety):
                        return fallback
            return "quick"

        return ideal

    def _build_rationale(
        self,
        env: EnvironmentType,
        safety: str,
        targets: list[dict],
        modules: list[str],
    ) -> str:
        """Build a human-readable explanation for the recommendation."""
        parts: list[str] = []
        parts.append(f"Environment classified as '{env}'.")

        if self._escalation_mode == "progressive":
            hours = f"{self._elapsed_hours():.1f}"
            parts.append(
                f"Progressive escalation active ({hours}h elapsed) — safety level: {safety}."
            )
        else:
            parts.append(f"Escalation disabled — safety level locked to {safety}.")

        if targets:
            n_dc = sum(
                1 for t in targets
                if "domain_controller" in t.get("tags", [])
            )
            if n_dc:
                parts.append(f"{n_dc} domain controller(s) prioritized.")

        if modules:
            parts.append(f"{len(modules)} module(s) recommended: {', '.join(modules)}.")

        run_count = len(self._scan_history)
        parts.append(f"Analysis based on {run_count} completed scan(s).")

        return " ".join(parts)
