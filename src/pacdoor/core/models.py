"""Core data models used across the entire system."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _uuid() -> str:
    return uuid.uuid4().hex


# ─── Enums ───────────────────────────────────────────────────────────────


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Phase(str, enum.Enum):
    RECON = "reconnaissance"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    LATERAL_MOVE = "lateral_movement"


class PortState(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class CredentialType(str, enum.Enum):
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    SSH_KEY = "ssh_key"
    TICKET = "kerberos_ticket"
    TOKEN = "token"


class ExploitSafety(str, enum.Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    DANGEROUS = "dangerous"
    DESTRUCTIVE = "destructive"


class ModuleStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class TargetProfile(str, enum.Enum):
    WINDOWS_DC = "windows_dc"
    WINDOWS_SERVER = "windows_server"
    WINDOWS_DESKTOP = "windows_desktop"
    LINUX_SERVER = "linux_server"
    WEB_SERVER = "web_server"
    DATABASE_SERVER = "database_server"
    MAIL_SERVER = "mail_server"
    DNS_SERVER = "dns_server"
    PROXY_LB = "proxy_lb"
    IOT_EMBEDDED = "iot_embedded"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    NETWORK_DEVICE = "network_device"
    UNKNOWN = "unknown"


# ─── Core Models ─────────────────────────────────────────────────────────


class Host(BaseModel):
    id: str = Field(default_factory=_uuid)
    ip: str
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    mac: str | None = None
    domain: str | None = None
    profile: TargetProfile = TargetProfile.UNKNOWN
    alive: bool = True
    discovered_at: datetime = Field(default_factory=_utcnow)


class Port(BaseModel):
    id: str = Field(default_factory=_uuid)
    host_id: str
    port: int
    protocol: str = "tcp"
    state: PortState = PortState.OPEN
    service_name: str | None = None
    service_version: str | None = None
    banner: str | None = None
    product: str | None = None


class Credential(BaseModel):
    id: str = Field(default_factory=_uuid)
    host_id: str | None = None
    username: str
    cred_type: CredentialType
    value: str
    domain: str | None = None
    source_module: str
    valid: bool = False
    admin: bool = False
    discovered_at: datetime = Field(default_factory=_utcnow)


class Evidence(BaseModel):
    kind: str
    data: str
    timestamp: datetime = Field(default_factory=_utcnow)


class Finding(BaseModel):
    id: str = Field(default_factory=_uuid)
    title: str
    description: str
    severity: Severity
    host_id: str | None = None
    port_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_id: str | None = None
    attack_technique_ids: list[str] = Field(default_factory=list)
    module_name: str
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    verified: bool = False
    status: str = "new"
    analyst_notes: str = ""
    discovered_at: datetime = Field(default_factory=_utcnow)


class AttackPath(BaseModel):
    id: str = Field(default_factory=_uuid)
    from_host_id: str
    to_host_id: str
    technique_id: str
    credential_id: str | None = None
    description: str
    step_order: int


class ConsolidatedFinding(BaseModel):
    """A finding deduplicated across multiple hosts.

    When the same vulnerability appears on 50 hosts, this produces 1
    consolidated finding with 50 affected hosts instead of 50 separate
    Finding records.  Used by the correlator and rendered in reports.
    """

    id: str = Field(default_factory=_uuid)
    title: str
    description: str
    severity: Severity
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_id: str | None = None
    attack_technique_ids: list[str] = Field(default_factory=list)
    module_name: str
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    affected_count: int = 0
    first_seen: datetime = Field(default_factory=_utcnow)
    evidence_samples: list[Evidence] = Field(default_factory=list)
    # IDs of the original findings that were merged into this one.
    source_finding_ids: list[str] = Field(default_factory=list)


class ModuleRun(BaseModel):
    id: str = Field(default_factory=_uuid)
    module_name: str
    host_id: str | None = None
    status: ModuleStatus = ModuleStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    findings_count: int = 0


class DiffResult(BaseModel):
    """Result of comparing two scan databases.

    Produced by ``ScanDiff.compare()`` and consumed by the diff report
    generator.  Categorizes findings as new, fixed (remediated), or
    persistent (still present).
    """

    new_hosts: list[str] = Field(default_factory=list)
    removed_hosts: list[str] = Field(default_factory=list)
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    fixed_findings: list[dict[str, Any]] = Field(default_factory=list)
    persistent_findings: list[dict[str, Any]] = Field(default_factory=list)
    new_credentials: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
