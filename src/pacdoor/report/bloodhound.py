"""BloodHound CE JSON export — generate importable ZIP from AD enumeration data.

Reads the fact store and database to produce BloodHound-compatible JSON files
(computers.json, users.json, groups.json, domains.json) and packages them
into a single ZIP file that BloodHound CE can ingest directly.

The output follows the BloodHound CE "flat" JSON ingest format where each file
contains a ``meta`` header and a ``data`` array of node/edge objects.

Usage from ReportGenerator:
    from pacdoor.report.bloodhound import generate_bloodhound_zip
    zip_path = await generate_bloodhound_zip(db, output_dir)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pacdoor.db.database import Database

log = logging.getLogger(__name__)

# BloodHound CE ingest metadata version.
_BH_VERSION = 5
_BH_TYPE_MAP = {
    "computers": "computers",
    "users": "users",
    "groups": "groups",
    "domains": "domains",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_meta(obj_type: str, count: int) -> dict[str, Any]:
    """Build the ``meta`` header required by BloodHound CE ingest."""
    return {
        "methods": 0,
        "type": obj_type,
        "count": count,
        "version": _BH_VERSION,
    }


def _domain_from_dn(dn: str) -> str:
    """Extract the domain FQDN from a distinguished name.

    ``CN=User,OU=Corp,DC=corp,DC=local`` -> ``CORP.LOCAL``
    """
    parts = re.findall(r"DC=([^,]+)", dn, flags=re.IGNORECASE)
    if parts:
        return ".".join(parts).upper()
    return ""


def _sid_placeholder(domain: str, rid: int) -> str:
    """Generate a deterministic pseudo-SID for an object.

    Real SIDs come from the domain but we may not have collected them.
    We use a repeatable hash so that cross-references within the same
    export are consistent.
    """
    import hashlib
    domain_hash = hashlib.sha256(domain.upper().encode()).hexdigest()[:16]
    return f"S-1-5-21-{int(domain_hash[:8], 16)}-{int(domain_hash[8:16], 16)}-{rid}"


def _domain_sid(domain: str) -> str:
    """Deterministic base SID for a domain."""
    import hashlib
    h = hashlib.sha256(domain.upper().encode()).hexdigest()[:16]
    return f"S-1-5-21-{int(h[:8], 16)}-{int(h[8:16], 16)}"


def _uac_enabled(uac_val: Any) -> bool:
    """Return True if the account is enabled (UAC bit 0x2 NOT set)."""
    try:
        return not (int(uac_val or 0) & 0x0002)
    except (TypeError, ValueError):
        return True


# ---------------------------------------------------------------------------
# Data extraction from the database + fact store format
# ---------------------------------------------------------------------------

def _extract_domain_name(hosts: list[dict[str, Any]]) -> str:
    """Best-effort domain name extraction from host records."""
    for h in hosts:
        domain = h.get("domain")
        if domain:
            return domain.upper()
    return "UNKNOWN.LOCAL"


def _build_computers(
    hosts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    domain: str,
) -> list[dict[str, Any]]:
    """Build BloodHound computer node objects."""
    computers: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    rid_counter = 1000

    # 1. From host records that have a domain set
    for host in hosts:
        hostname = (host.get("hostname") or host.get("ip", "")).upper()
        if not hostname:
            continue

        # Ensure FQDN format
        fqdn = hostname if "." in hostname else f"{hostname}.{domain}"
        fqdn = fqdn.upper()

        if fqdn in seen_names:
            continue
        seen_names.add(fqdn)

        os_name = host.get("os") or ""
        os_version = host.get("os_version") or ""
        os_display = f"{os_name} {os_version}".strip() if os_name else ""

        computers.append({
            "Properties": {
                "name": fqdn,
                "domain": domain,
                "operatingsystem": os_display or None,
                "enabled": bool(host.get("alive", True)),
                "unconstraineddelegation": False,
                "haslaps": False,
            },
            "ObjectIdentifier": _sid_placeholder(domain, rid_counter),
            "PrimaryGroupSID": _sid_placeholder(domain, 515),  # Domain Computers
            "AllowedToDelegate": [],
            "AllowedToAct": [],
            "Sessions": {"Results": [], "Collected": True},
            "PrivilegedSessions": {"Results": [], "Collected": True},
            "RegistrySessions": {"Results": [], "Collected": True},
            "LocalAdmins": {"Results": [], "Collected": False},
            "RemoteDesktopUsers": {"Results": [], "Collected": False},
            "DcomUsers": {"Results": [], "Collected": False},
            "PSRemoteUsers": {"Results": [], "Collected": False},
            "Status": None,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        })
        rid_counter += 1

    # 2. Parse ad.computers from findings evidence
    for finding in findings:
        evidence_raw = finding.get("evidence", "")
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        else:
            continue

        for ev in evidence_list:
            if not isinstance(ev, dict):
                continue
            if ev.get("kind") != "domain_computers":
                continue
            data = ev.get("data", "")
            # Parse structured lines: "  - CN (dns_hostname) -- OS Version"
            for line in data.splitlines():
                line = line.strip()
                if not line.startswith("- "):
                    continue
                line = line[2:]
                # Extract DNS hostname from parentheses
                match = re.match(r"([^\(]+)\(([^)]+)\)", line)
                if match:
                    dns_hostname = match.group(2).strip().upper()
                    if not dns_hostname or dns_hostname in seen_names:
                        continue
                    fqdn = dns_hostname if "." in dns_hostname else f"{dns_hostname}.{domain}"
                    fqdn = fqdn.upper()
                    if fqdn in seen_names:
                        continue
                    seen_names.add(fqdn)

                    # Try to extract OS from the rest
                    remainder = line[match.end():]
                    os_display = ""
                    if remainder.startswith(" — ") or remainder.startswith(" - "):
                        os_display = remainder[3:].strip()

                    computers.append({
                        "Properties": {
                            "name": fqdn,
                            "domain": domain,
                            "operatingsystem": os_display or None,
                            "enabled": True,
                            "unconstraineddelegation": False,
                            "haslaps": False,
                        },
                        "ObjectIdentifier": _sid_placeholder(domain, rid_counter),
                        "PrimaryGroupSID": _sid_placeholder(domain, 515),
                        "AllowedToDelegate": [],
                        "AllowedToAct": [],
                        "Sessions": {"Results": [], "Collected": True},
                        "PrivilegedSessions": {"Results": [], "Collected": True},
                        "RegistrySessions": {"Results": [], "Collected": True},
                        "LocalAdmins": {"Results": [], "Collected": False},
                        "RemoteDesktopUsers": {"Results": [], "Collected": False},
                        "DcomUsers": {"Results": [], "Collected": False},
                        "PSRemoteUsers": {"Results": [], "Collected": False},
                        "Status": None,
                        "Aces": [],
                        "IsDeleted": False,
                        "IsACLProtected": False,
                    })
                    rid_counter += 1

    # Mark unconstrained delegation and LAPS from findings
    uc_hostnames: set[str] = set()
    laps_hostnames: set[str] = set()
    for finding in findings:
        evidence_raw = finding.get("evidence", "")
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        else:
            continue

        for ev in evidence_list:
            if not isinstance(ev, dict):
                continue
            kind = ev.get("kind", "")
            data = ev.get("data", "")
            if kind == "unconstrained_delegation":
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("- "):
                        match = re.search(r"\(([^)]+)\)", line)
                        if match:
                            uc_hostnames.add(match.group(1).upper())
            elif kind == "laps_exposed":
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("- "):
                        match = re.search(r"\(([^)]+)\)", line)
                        if match:
                            laps_hostnames.add(match.group(1).upper())

    for comp in computers:
        name = comp["Properties"].get("name", "").upper()
        if any(name.startswith(h) or h in name for h in uc_hostnames if h):
            comp["Properties"]["unconstraineddelegation"] = True
        if any(name.startswith(h) or h in name for h in laps_hostnames if h):
            comp["Properties"]["haslaps"] = True

    return computers


def _build_users(
    findings: list[dict[str, Any]],
    domain: str,
) -> list[dict[str, Any]]:
    """Build BloodHound user node objects from findings."""
    users: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    rid_counter = 2000

    # Collect kerberoastable usernames
    kerberoastable_users: set[str] = set()
    # Collect admin-count users
    admincount_users: set[str] = set()

    for finding in findings:
        evidence_raw = finding.get("evidence", "")
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        else:
            continue

        for ev in evidence_list:
            if not isinstance(ev, dict):
                continue
            kind = ev.get("kind", "")
            data = ev.get("data", "")

            if kind == "kerberoastable":
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("- "):
                        parts = line[2:].split(" — ", 1)
                        username = parts[0].strip()
                        if username:
                            kerberoastable_users.add(username.upper())
                            if "[adminCount=1]" in line:
                                admincount_users.add(username.upper())

            elif kind == "adminsdholder":
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("- "):
                        parts = line[2:].split(" — ", 1)
                        username = parts[0].strip()
                        if username:
                            admincount_users.add(username.upper())

    # Parse users from ldap_users evidence
    for finding in findings:
        evidence_raw = finding.get("evidence", "")
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        else:
            continue

        for ev in evidence_list:
            if not isinstance(ev, dict):
                continue
            kind = ev.get("kind", "")
            data = ev.get("data", "")

            if kind == "ldap_users":
                for line in data.splitlines():
                    line = line.strip()
                    if not line.startswith("- "):
                        continue
                    username = line[2:].strip()
                    if not username or username == "?" or username.upper() in seen_names:
                        continue
                    seen_names.add(username.upper())
                    upn = f"{username.upper()}@{domain}"
                    is_kerb = username.upper() in kerberoastable_users
                    is_admin = username.upper() in admincount_users

                    users.append({
                        "Properties": {
                            "name": upn,
                            "domain": domain,
                            "enabled": True,
                            "hasspn": is_kerb,
                            "admincount": is_admin,
                            "dontreqpreauth": False,
                            "unconstraineddelegation": False,
                            "passwordnotreqd": False,
                            "sensitive": False,
                            "serviceprincipalnames": [],
                        },
                        "ObjectIdentifier": _sid_placeholder(domain, rid_counter),
                        "PrimaryGroupSID": _sid_placeholder(domain, 513),  # Domain Users
                        "AllowedToDelegate": [],
                        "SPNTargets": [],
                        "HasSIDHistory": [],
                        "Status": None,
                        "Aces": [],
                        "IsDeleted": False,
                        "IsACLProtected": False,
                    })
                    rid_counter += 1

    # Ensure kerberoastable users that weren't in ldap_users are still present
    for username in kerberoastable_users:
        if username in seen_names:
            continue
        seen_names.add(username)
        upn = f"{username}@{domain}"
        users.append({
            "Properties": {
                "name": upn,
                "domain": domain,
                "enabled": True,
                "hasspn": True,
                "admincount": username in admincount_users,
                "dontreqpreauth": False,
                "unconstraineddelegation": False,
                "passwordnotreqd": False,
                "sensitive": False,
                "serviceprincipalnames": [],
            },
            "ObjectIdentifier": _sid_placeholder(domain, rid_counter),
            "PrimaryGroupSID": _sid_placeholder(domain, 513),
            "AllowedToDelegate": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
            "Status": None,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        })
        rid_counter += 1

    # Mark AS-REP roastable users
    asrep_users: set[str] = set()
    for finding in findings:
        evidence_raw = finding.get("evidence", "")
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        else:
            continue

        for ev in evidence_list:
            if not isinstance(ev, dict):
                continue
            if ev.get("kind") == "asrep_roastable":
                data = ev.get("data", "")
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("- "):
                        # "username (DN)" format
                        parts = line[2:].split(" (", 1)
                        username = parts[0].strip().upper()
                        if username:
                            asrep_users.add(username)

    for user in users:
        name = user["Properties"].get("name", "").split("@")[0].upper()
        if name in asrep_users:
            user["Properties"]["dontreqpreauth"] = True

    return users


def _build_groups(
    findings: list[dict[str, Any]],
    domain: str,
) -> list[dict[str, Any]]:
    """Build BloodHound group node objects from findings."""
    groups: list[dict[str, Any]] = []
    rid_counter = 3000

    # Well-known group RIDs
    well_known = {
        "DOMAIN ADMINS": 512,
        "DOMAIN USERS": 513,
        "DOMAIN COMPUTERS": 515,
        "ENTERPRISE ADMINS": 519,
    }

    # Parse privileged group membership from findings
    group_members: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        evidence_raw = finding.get("evidence", "")
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        else:
            continue

        for ev in evidence_list:
            if not isinstance(ev, dict):
                continue
            kind = ev.get("kind", "")
            data = ev.get("data", "")

            if kind == "privileged_group":
                # "Domain Admins members:\n  - user (DN)"
                header_match = re.match(r"(.+?) members:", data)
                if not header_match:
                    continue
                group_name = header_match.group(1).strip().upper()
                members = group_members.setdefault(group_name, [])

                for line in data.splitlines()[1:]:
                    line = line.strip()
                    if not line.startswith("- "):
                        continue
                    line = line[2:]
                    # "cn (DN)" format
                    parts = line.split(" (", 1)
                    cn = parts[0].strip()
                    if cn:
                        members.append({
                            "ObjectIdentifier": _sid_placeholder(domain, int(hashlib.sha256(cn.encode()).hexdigest()[:8], 16) % 90000 + 10000),
                            "ObjectType": "User",
                        })

            elif kind == "domain_admins":
                # "Domain Admin members on IP:\n  - username"
                members = group_members.setdefault("DOMAIN ADMINS", [])
                for line in data.splitlines():
                    line = line.strip()
                    if not line.startswith("- "):
                        continue
                    username = line[2:].strip()
                    if username:
                        members.append({
                            "ObjectIdentifier": _sid_placeholder(domain, int(hashlib.sha256(username.encode()).hexdigest()[:8], 16) % 90000 + 10000),
                            "ObjectType": "User",
                        })

    # Create group entries for well-known groups
    for group_name, rid in well_known.items():
        members = group_members.get(group_name, [])
        groups.append({
            "Properties": {
                "name": f"{group_name}@{domain}",
                "domain": domain,
                "highvalue": group_name in ("DOMAIN ADMINS", "ENTERPRISE ADMINS"),
                "admincount": group_name in ("DOMAIN ADMINS", "ENTERPRISE ADMINS"),
            },
            "ObjectIdentifier": _sid_placeholder(domain, rid),
            "Members": members,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        })

    # Any other groups found in evidence that aren't well-known
    for group_name, members in group_members.items():
        if group_name in well_known:
            continue
        groups.append({
            "Properties": {
                "name": f"{group_name}@{domain}",
                "domain": domain,
                "highvalue": "ADMIN" in group_name,
                "admincount": "ADMIN" in group_name,
            },
            "ObjectIdentifier": _sid_placeholder(domain, rid_counter),
            "Members": members,
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        })
        rid_counter += 1

    return groups


def _build_domains(
    findings: list[dict[str, Any]],
    domain: str,
) -> list[dict[str, Any]]:
    """Build BloodHound domain node objects."""
    domain_sid = _domain_sid(domain)

    # Extract functional level from findings if available
    functional_level = "Unknown"
    for finding in findings:
        title = finding.get("title", "")
        if "password policy" in title.lower():
            # Domain controller that returned password policy is the domain
            break

    # Build trust relationships from findings
    trusts: list[dict[str, Any]] = []
    for finding in findings:
        evidence_raw = finding.get("evidence", "")
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        else:
            continue

        for ev in evidence_list:
            if not isinstance(ev, dict):
                continue
            if ev.get("kind") != "domain_trusts":
                continue
            data = ev.get("data", "")
            for line in data.splitlines():
                line = line.strip()
                if not line.startswith("- "):
                    continue
                line = line[2:]
                # "partner -- direction (type)" format
                parts = line.split(" — ", 1)
                if not parts:
                    continue
                partner = parts[0].strip().upper()
                direction = ""
                trust_type = ""
                if len(parts) > 1:
                    rest = parts[1]
                    dir_match = re.match(r"([^(]+)\(([^)]+)\)", rest)
                    if dir_match:
                        direction = dir_match.group(1).strip()
                        trust_type = dir_match.group(2).strip()
                    else:
                        direction = rest.strip()

                is_transitive = "Bidirectional" in direction
                trust_dir_num = 0
                if "Inbound" in direction:
                    trust_dir_num = 1
                elif "Outbound" in direction:
                    trust_dir_num = 2
                elif "Bidirectional" in direction:
                    trust_dir_num = 3

                trusts.append({
                    "TargetDomainSid": _domain_sid(partner),
                    "TargetDomainName": partner,
                    "IsTransitive": is_transitive,
                    "TrustDirection": trust_dir_num,
                    "TrustType": trust_type,
                    "SidFilteringEnabled": True,
                })

    domains = [{
        "Properties": {
            "name": domain,
            "domain": domain,
            "functionallevel": functional_level,
            "highvalue": True,
        },
        "ObjectIdentifier": domain_sid,
        "ChildObjects": [],
        "Trusts": trusts,
        "Links": [],
        "Aces": [],
        "GPOChanges": {"LocalAdmins": [], "RemoteDesktopUsers": [],
                       "DcomUsers": [], "PSRemoteUsers": [],
                       "AffectedComputers": []},
        "IsDeleted": False,
        "IsACLProtected": False,
    }]

    return domains


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def generate_bloodhound_zip(
    db: Database,
    output_dir: Path,
) -> Path:
    """Generate a BloodHound CE-compatible ZIP from the assessment database.

    The ZIP contains:
      - computers.json
      - users.json
      - groups.json
      - domains.json

    Returns the path to the generated ZIP file.
    """
    hosts = await db.get_all_hosts()
    findings = await db.get_all_findings()

    domain = _extract_domain_name(hosts)

    computers = _build_computers(hosts, findings, domain)
    users = _build_users(findings, domain)
    groups = _build_groups(findings, domain)
    domains = _build_domains(findings, domain)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    zip_name = f"bloodhound_{timestamp}.zip"
    zip_path = output_dir / zip_name

    file_contents: dict[str, dict[str, Any]] = {
        "computers.json": {
            "meta": _make_meta("computers", len(computers)),
            "data": computers,
        },
        "users.json": {
            "meta": _make_meta("users", len(users)),
            "data": users,
        },
        "groups.json": {
            "meta": _make_meta("groups", len(groups)),
            "data": groups,
        },
        "domains.json": {
            "meta": _make_meta("domains", len(domains)),
            "data": domains,
        },
    }

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in file_contents.items():
            json_bytes = json.dumps(content, indent=2, default=str).encode("utf-8")
            zf.writestr(filename, json_bytes)

    total_objects = len(computers) + len(users) + len(groups) + len(domains)
    log.info(
        "BloodHound export: %d computers, %d users, %d groups, %d domains "
        "(%d total objects) -> %s",
        len(computers), len(users), len(groups), len(domains),
        total_objects, zip_path,
    )

    return zip_path
