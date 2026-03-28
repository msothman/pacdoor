"""YAML configuration loader for PACDOOR's autonomous agent mode.

Expected config format:

    agent:
      targets:           # required — list of IPs, CIDRs, or hostnames
        - 10.0.0.0/24
      exclude:           # optional — targets to skip
        - 10.0.0.1

      schedules:         # at least one schedule required
        - name: quick_recon
          profile: quick
          interval: 1h
          credentials:   # optional — for AD / authenticated scans
            username: scanner
            password: ScanP@ss1
            domain: CORP.LOCAL

      behavior:          # all optional, sensible defaults
        max_safety: moderate
        adaptive: true
        escalation: off
        escalation_after_hours: 3
        concurrent_scans: 1

      output:
        dir: ./pacdoor-results
        reports: [html, json]
        retain_runs: 30

      notifications:
        on_critical: true
        summary_after_each: true
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from pacdoor.core.profiles import PROFILES

# ---------------------------------------------------------------------------
# Interval parsing
# ---------------------------------------------------------------------------

_INTERVAL_RE = re.compile(r"^(\d+)\s*([smhd])$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_interval(s: str) -> int:
    """Convert a human-friendly interval string to seconds.

    Accepted formats: ``30s``, ``5m``, ``1h``, ``7d`` (case-insensitive).
    Raises ``ValueError`` for invalid or non-positive intervals.
    """
    m = _INTERVAL_RE.match(s.strip())
    if not m:
        raise ValueError(
            f"Invalid interval {s!r} — expected <number><s|m|h|d>, e.g. '1h'"
        )
    seconds = int(m.group(1)) * _UNIT_SECONDS[m.group(2).lower()]
    if seconds <= 0:
        raise ValueError(f"Interval must be positive, got {s!r}")
    return seconds


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class CredentialConfig(BaseModel):
    """Optional credentials for authenticated scans (e.g. AD)."""

    username: str
    password: str
    domain: str = ""


class ScheduleConfig(BaseModel):
    """A single recurring scan job."""

    name: str
    profile: str
    interval: str  # raw string — validated then converted at runtime
    credentials: CredentialConfig | None = None

    @field_validator("profile")
    @classmethod
    def _valid_profile(cls, v: str) -> str:
        if v not in PROFILES:
            valid = ", ".join(sorted(PROFILES))
            raise ValueError(f"Unknown profile {v!r} — choose from: {valid}")
        return v

    @field_validator("interval")
    @classmethod
    def _valid_interval(cls, v: str) -> str:
        parse_interval(v)  # raises on bad input
        return v

    @property
    def interval_seconds(self) -> int:
        """Return the interval as seconds (convenience property)."""
        return parse_interval(self.interval)


class BehaviorConfig(BaseModel):
    """Controls how the agent adapts its scanning behaviour over time."""

    max_safety: Literal["safe", "moderate", "dangerous"] = "moderate"
    adaptive: bool = True
    escalation: Literal["off", "progressive"] = "off"
    escalation_after_hours: int = Field(default=3, gt=0)
    concurrent_scans: int = Field(default=1, ge=1, le=20)


class OutputConfig(BaseModel):
    """Where and how scan results are stored."""

    dir: str = "./pacdoor-results"
    reports: list[str] = Field(default_factory=lambda: ["html", "json"])
    retain_runs: int = Field(default=30, gt=0)


class NotificationConfig(BaseModel):
    """Runtime notification preferences."""

    on_critical: bool = True
    summary_after_each: bool = True


class AgentConfig(BaseModel):
    """Top-level agent configuration — corresponds to the ``agent:`` key."""

    targets: list[str]
    exclude: list[str] = Field(default_factory=list)
    schedules: list[ScheduleConfig]
    behavior: BehaviorConfig = Field(default_factory=BehaviorConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)

    @field_validator("targets", "exclude")
    @classmethod
    def _valid_targets(cls, values: list[str]) -> list[str]:
        for v in values:
            _validate_target(v)
        return values

    @field_validator("schedules")
    @classmethod
    def _at_least_one(cls, v: list[ScheduleConfig]) -> list[ScheduleConfig]:
        if not v:
            raise ValueError("At least one schedule is required")
        return v


# ---------------------------------------------------------------------------
# Target validation helper
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)


def _validate_target(value: str) -> None:
    """Accept an IPv4/IPv6 address, CIDR network, or hostname."""
    # Try CIDR first (e.g. 10.0.0.0/24)
    try:
        ipaddress.ip_network(value, strict=False)
        return
    except ValueError:
        pass

    # Try bare IP (e.g. 10.0.0.1)
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass

    # Fall back to hostname
    if not _HOSTNAME_RE.match(value):
        raise ValueError(
            f"Invalid target {value!r} — expected IP, CIDR, or hostname"
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: Path) -> AgentConfig:
    """Read a YAML config file and return a validated ``AgentConfig``.

    Raises ``FileNotFoundError`` if *path* does not exist, ``ValueError``
    (via pydantic) if the content fails validation, or ``yaml.YAMLError``
    on malformed YAML.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    if not isinstance(raw, dict) or "agent" not in raw:
        raise ValueError("Config must contain a top-level 'agent' key")

    return AgentConfig.model_validate(raw["agent"])
