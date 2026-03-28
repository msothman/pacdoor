"""Active Directory enumeration — BloodHound-style AD recon.

When domain credentials and an LDAP service are available, this module
performs comprehensive AD enumeration: Domain/Enterprise Admins, domain
computers, Kerberoastable SPNs, AS-REP roastable accounts, unconstrained
delegation, domain trusts, GPO/OU structure, LAPS readability,
AdminSDHolder-protected accounts, and password policy.

Discovered computers are registered as ``host`` facts so the planner can
loop them through the full ENUM -> VULN -> EXPLOIT pipeline.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
    Credential,
    CredentialType,
    Evidence,
    ExploitSafety,
    Finding,
    Host,
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Lazy import for ldap3 ─────────────────────────────────────────────────

_ldap3_available: bool | None = None


def _ensure_ldap3() -> bool:
    global _ldap3_available  # noqa: PLW0603
    if _ldap3_available is not None:
        return _ldap3_available
    try:
        import ldap3  # type: ignore[import-untyped]  # noqa: F401

        _ldap3_available = True
    except ImportError:
        log.debug("ldap3 not installed — AD enumeration unavailable")
        _ldap3_available = False
    return _ldap3_available


# ── UAC flag constants ────────────────────────────────────────────────────

_UAC_DONT_REQUIRE_PREAUTH = 0x400000  # 4194304
_UAC_TRUSTED_FOR_DELEGATION = 0x80000  # 524288
_UAC_ACCOUNTDISABLE = 0x0002


# ── Synchronous LDAP helpers (run via asyncio.to_thread) ──────────────────


def _ldap_connect(
    server_ip: str,
    domain: str,
    username: str,
    password: str,
    use_ssl: bool = False,
) -> Any | None:
    """Establish an authenticated LDAP connection.

    Returns an ldap3.Connection or None on failure.
    """
    try:
        import ldap3  # type: ignore[import-untyped]

        port = 636 if use_ssl else 389
        server = ldap3.Server(server_ip, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

        # Build bind DN: DOMAIN\\username or username@domain
        if "\\" not in username and "@" not in username:
            bind_dn = f"{domain}\\{username}"
        else:
            bind_dn = username

        conn = ldap3.Connection(
            server, user=bind_dn, password=password,
            authentication=ldap3.NTLM if "\\" in bind_dn else ldap3.SIMPLE,
            auto_bind=True,
            read_only=True,
            receive_timeout=30,
        )
        return conn
    except Exception as e:
        log.debug("LDAP bind to %s failed: %s", server_ip, e)
        return None


def _get_base_dn(domain: str) -> str:
    """Convert 'corp.local' to 'DC=corp,DC=local'."""
    return ",".join(f"DC={part}" for part in domain.split("."))


def _get_attr(entry: Any, attr: str, default: Any = None) -> Any:
    """Safely extract an attribute from an ldap3 entry."""
    try:
        val = getattr(entry, attr, default)
        if val is None:
            return default
        if hasattr(val, "value"):
            return val.value
        if hasattr(val, "values"):
            return val.values
        return val
    except Exception:
        return default


def _get_attr_list(entry: Any, attr: str) -> list[str]:
    """Extract a multi-valued attribute as a list of strings."""
    try:
        val = getattr(entry, attr, None)
        if val is None:
            return []
        if hasattr(val, "values"):
            return [str(v) for v in val.values]
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)]
    except Exception:
        return []


def _search_paged(
    conn: Any,
    base_dn: str,
    search_filter: str,
    attributes: list[str],
    size_limit: int = 0,
) -> list[Any]:
    """Perform a paged LDAP search and return all entries."""
    import ldap3  # type: ignore[import-untyped]

    entries: list[Any] = []
    try:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            paged_size=500,
            size_limit=size_limit,
        )
        entries.extend(conn.entries)

        # Handle paging via the cookie
        cookie = conn.result.get("controls", {}).get(
            "1.2.840.113556.1.4.319", {}
        ).get("value", {}).get("cookie")

        while cookie:
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=500,
                paged_cookie=cookie,
                size_limit=size_limit,
            )
            entries.extend(conn.entries)
            cookie = conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}
            ).get("value", {}).get("cookie")
    except Exception as e:
        log.debug("Paged LDAP search failed: %s", e)

    return entries


# ── Enumeration functions (all synchronous) ───────────────────────────────


def _enum_privileged_groups(
    conn: Any, base_dn: str,
) -> dict[str, list[dict[str, str]]]:
    """Enumerate Domain Admins + Enterprise Admins group members.

    Returns {"domain_admins": [...], "enterprise_admins": [...]}.
    """
    results: dict[str, list[dict[str, str]]] = {
        "domain_admins": [],
        "enterprise_admins": [],
    }

    group_map = {
        "domain_admins": "(cn=Domain Admins)",
        "enterprise_admins": "(cn=Enterprise Admins)",
    }

    for key, group_filter in group_map.items():
        try:
            entries = _search_paged(
                conn, base_dn,
                search_filter=f"(&(objectClass=group){group_filter})",
                attributes=["member", "cn", "distinguishedName"],
            )
            for entry in entries:
                members = _get_attr_list(entry, "member")
                for member_dn in members:
                    # Extract CN from the DN
                    cn = member_dn.split(",")[0].replace("CN=", "")
                    results[key].append({
                        "dn": member_dn,
                        "cn": cn,
                    })
        except Exception as e:
            log.debug("Failed to enumerate %s: %s", key, e)

    return results


def _enum_computers(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Enumerate all domain-joined computers."""
    computers: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter="(objectClass=computer)",
            attributes=[
                "cn", "dNSHostName", "operatingSystem",
                "operatingSystemVersion", "distinguishedName",
                "userAccountControl",
            ],
        )
        for entry in entries:
            uac = int(_get_attr(entry, "userAccountControl", 0) or 0)
            # Skip disabled computer accounts
            if uac & _UAC_ACCOUNTDISABLE:
                continue
            computers.append({
                "cn": str(_get_attr(entry, "cn", "")),
                "dns_hostname": str(_get_attr(entry, "dNSHostName", "")),
                "os": str(_get_attr(entry, "operatingSystem", "")),
                "os_version": str(_get_attr(entry, "operatingSystemVersion", "")),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
            })
    except Exception as e:
        log.debug("Failed to enumerate computers: %s", e)
    return computers


def _enum_kerberoastable(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Find accounts with servicePrincipalName set (Kerberoastable)."""
    accounts: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter=(
                "(&(objectClass=user)(servicePrincipalName=*)"
                "(!(objectClass=computer))"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=[
                "sAMAccountName", "servicePrincipalName",
                "memberOf", "distinguishedName", "adminCount",
            ],
        )
        for entry in entries:
            spns = _get_attr_list(entry, "servicePrincipalName")
            admin_count = int(_get_attr(entry, "adminCount", 0) or 0)
            accounts.append({
                "username": str(_get_attr(entry, "sAMAccountName", "")),
                "spns": ", ".join(spns),
                "admin_count": str(admin_count),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
            })
    except Exception as e:
        log.debug("Failed to enumerate Kerberoastable accounts: %s", e)
    return accounts


def _enum_asrep_roastable(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Find accounts with DONT_REQUIRE_PREAUTH set (AS-REP Roastable)."""
    accounts: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter=(
                "(&(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=["sAMAccountName", "distinguishedName", "memberOf"],
        )
        for entry in entries:
            accounts.append({
                "username": str(_get_attr(entry, "sAMAccountName", "")),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
            })
    except Exception as e:
        log.debug("Failed to enumerate AS-REP roastable accounts: %s", e)
    return accounts


def _enum_unconstrained_delegation(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Find computers trusted for unconstrained delegation."""
    results: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter=(
                "(&(objectClass=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=["cn", "dNSHostName", "distinguishedName"],
        )
        for entry in entries:
            results.append({
                "cn": str(_get_attr(entry, "cn", "")),
                "dns_hostname": str(_get_attr(entry, "dNSHostName", "")),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
            })
    except Exception as e:
        log.debug("Failed to enumerate unconstrained delegation: %s", e)
    return results


def _enum_domain_trusts(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Enumerate domain trusts."""
    trusts: list[dict[str, str]] = []
    trust_direction_map = {
        "0": "Disabled",
        "1": "Inbound",
        "2": "Outbound",
        "3": "Bidirectional",
    }
    trust_type_map = {
        "1": "Downlevel (Windows NT)",
        "2": "Uplevel (Active Directory)",
        "3": "MIT (Kerberos realm)",
        "4": "DCE (cross-organization)",
    }
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter="(objectClass=trustedDomain)",
            attributes=[
                "cn", "trustDirection", "trustType",
                "trustPartner", "trustAttributes",
                "distinguishedName",
            ],
        )
        for entry in entries:
            direction = str(_get_attr(entry, "trustDirection", "0"))
            trust_type = str(_get_attr(entry, "trustType", "0"))
            trusts.append({
                "partner": str(_get_attr(entry, "trustPartner", "")),
                "direction": trust_direction_map.get(direction, f"Unknown({direction})"),
                "type": trust_type_map.get(trust_type, f"Unknown({trust_type})"),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
            })
    except Exception as e:
        log.debug("Failed to enumerate domain trusts: %s", e)
    return trusts


def _enum_gpo_links(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Enumerate GPOs and their links."""
    gpos: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=[
                "displayName", "gPCFileSysPath",
                "distinguishedName", "flags",
            ],
        )
        for entry in entries:
            flags = int(_get_attr(entry, "flags", 0) or 0)
            # flags: 0=enabled, 1=user disabled, 2=computer disabled, 3=all disabled
            status = "enabled" if flags == 0 else f"partially/fully disabled (flags={flags})"
            gpos.append({
                "name": str(_get_attr(entry, "displayName", "")),
                "path": str(_get_attr(entry, "gPCFileSysPath", "")),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
                "status": status,
            })
    except Exception as e:
        log.debug("Failed to enumerate GPOs: %s", e)
    return gpos


def _enum_ou_structure(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Enumerate Organizational Units."""
    ous: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter="(objectClass=organizationalUnit)",
            attributes=["ou", "distinguishedName", "gPLink"],
        )
        for entry in entries:
            gp_link = str(_get_attr(entry, "gPLink", ""))
            ous.append({
                "name": str(_get_attr(entry, "ou", "")),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
                "gpo_linked": "yes" if gp_link else "no",
            })
    except Exception as e:
        log.debug("Failed to enumerate OUs: %s", e)
    return ous


def _enum_laps(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Check for LAPS (ms-Mcs-AdmPwd) readability on computer objects.

    If we can read ms-Mcs-AdmPwd, LAPS passwords are exposed — CRITICAL.
    """
    exposed: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter="(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
            attributes=["cn", "dNSHostName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"],
        )
        for entry in entries:
            exposed.append({
                "cn": str(_get_attr(entry, "cn", "")),
                "dns_hostname": str(_get_attr(entry, "dNSHostName", "")),
                "laps_password": str(_get_attr(entry, "ms-Mcs-AdmPwd", "")),
            })
    except Exception as e:
        log.debug("Failed to enumerate LAPS: %s", e)
    return exposed


def _enum_adminsdholder(conn: Any, base_dn: str) -> list[dict[str, str]]:
    """Enumerate AdminSDHolder-protected accounts (adminCount=1)."""
    accounts: list[dict[str, str]] = []
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter=(
                "(&(objectClass=user)(adminCount=1)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=["sAMAccountName", "distinguishedName", "memberOf"],
        )
        for entry in entries:
            groups = _get_attr_list(entry, "memberOf")
            # Extract just the CN from each group DN
            group_names = []
            for g in groups[:10]:
                cn_part = g.split(",")[0].replace("CN=", "")
                group_names.append(cn_part)
            accounts.append({
                "username": str(_get_attr(entry, "sAMAccountName", "")),
                "dn": str(_get_attr(entry, "distinguishedName", "")),
                "groups": ", ".join(group_names),
            })
    except Exception as e:
        log.debug("Failed to enumerate AdminSDHolder accounts: %s", e)
    return accounts


def _enum_password_policy(conn: Any, base_dn: str) -> dict[str, str]:
    """Retrieve domain-level password policy."""
    policy: dict[str, str] = {}
    try:
        entries = _search_paged(
            conn, base_dn,
            search_filter="(objectClass=domain)",
            attributes=[
                "minPwdLength", "maxPwdAge", "minPwdAge",
                "pwdHistoryLength", "lockoutThreshold",
                "lockoutDuration", "lockOutObservationWindow",
                "pwdProperties",
            ],
        )
        if entries:
            entry = entries[0]
            policy["min_length"] = str(_get_attr(entry, "minPwdLength", "N/A"))
            policy["max_age"] = str(_get_attr(entry, "maxPwdAge", "N/A"))
            policy["min_age"] = str(_get_attr(entry, "minPwdAge", "N/A"))
            policy["history_length"] = str(_get_attr(entry, "pwdHistoryLength", "N/A"))
            policy["lockout_threshold"] = str(_get_attr(entry, "lockoutThreshold", "N/A"))
            policy["lockout_duration"] = str(_get_attr(entry, "lockoutDuration", "N/A"))
            policy["lockout_window"] = str(_get_attr(entry, "lockOutObservationWindow", "N/A"))

            # pwdProperties bitmask: bit 0 = complexity required
            pwd_props = int(_get_attr(entry, "pwdProperties", 0) or 0)
            policy["complexity_required"] = "yes" if pwd_props & 1 else "no"
    except Exception as e:
        log.debug("Failed to enumerate password policy: %s", e)
    return policy


# ── Module ────────────────────────────────────────────────────────────────


class ADEnumModule(BaseModule):
    """Active Directory enumeration using LDAP.

    Performs BloodHound-style recon including privileged group membership,
    computer enumeration, Kerberoastable/AS-REP roastable accounts,
    unconstrained delegation, domain trusts, GPO/OU structure, LAPS
    readability, AdminSDHolder accounts, and password policy analysis.
    """

    name = "post.ad_enum"
    description = "Active Directory enumeration via LDAP (BloodHound-style recon)"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1087.002", "T1069.002", "T1482"]
    required_facts = ["credential.valid", "service.ldap"]
    produced_facts = [
        "ad.domain_admins",
        "ad.trusts",
        "ad.kerberoastable",
        "ad.computers",
    ]
    safety = ExploitSafety.MODERATE

    async def check(self, ctx: ModuleContext) -> bool:
        """Verify we have both valid credentials and an LDAP service."""
        if not _ensure_ldap3():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _ensure_ldap3():
            return findings

        # Get LDAP service endpoints.
        ldap_services = await ctx.facts.get_all("service.ldap")
        if not ldap_services:
            return findings

        # Get available credentials.
        creds = await ctx.facts.get_all("credential.valid")
        if not creds:
            return findings

        # Try each LDAP endpoint with each credential until one works.
        conn = None
        bound_host_id: str | None = None
        bound_domain: str = ""

        for ldap_fact in ldap_services:
            host_id = ldap_fact.host_id
            if host_id is None:
                continue
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue

            for cred_fact in creds:
                cred = cred_fact.value
                username = (
                    cred.username if hasattr(cred, "username")
                    else str(cred.get("username", ""))
                )
                password = (
                    cred.value if hasattr(cred, "value")
                    else str(cred.get("value", ""))
                )
                domain = (
                    cred.domain if hasattr(cred, "domain")
                    else str(cred.get("domain", ""))
                )

                if not username or not domain:
                    continue

                await ctx.rate_limiter.acquire()

                # Try SSL first, then plaintext.
                for use_ssl in (True, False):
                    conn = await asyncio.to_thread(
                        _ldap_connect, ip, domain, username, password, use_ssl,
                    )
                    if conn is not None:
                        bound_host_id = host_id
                        bound_domain = domain
                        break

                if conn is not None:
                    break

            if conn is not None:
                break

        if conn is None:
            log.debug("ad_enum: could not bind to any LDAP endpoint")
            return findings

        base_dn = _get_base_dn(bound_domain)

        try:
            # ── 1. Privileged groups ─────────────────────────────────
            priv_groups = await asyncio.to_thread(
                _enum_privileged_groups, conn, base_dn,
            )

            for group_key, group_label in [
                ("domain_admins", "Domain Admins"),
                ("enterprise_admins", "Enterprise Admins"),
            ]:
                members = priv_groups.get(group_key, [])
                if members:
                    member_lines = "\n".join(
                        f"  - {m['cn']} ({m['dn']})" for m in members
                    )
                    findings.append(Finding(
                        title=f"{group_label} group members enumerated ({len(members)})",
                        description=(
                            f"Enumerated {len(members)} member(s) of the "
                            f"{group_label} group in domain {bound_domain}. "
                            f"These accounts have the highest privileges in "
                            f"the domain and are primary targets."
                        ),
                        severity=Severity.HIGH,
                        host_id=bound_host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1069.002"],
                        evidence=[Evidence(
                            kind="privileged_group",
                            data=f"{group_label} members:\n{member_lines}",
                        )],
                        remediation=(
                            f"Minimize {group_label} membership. Use tiered "
                            "administration and Privileged Access Workstations (PAWs). "
                            "Monitor group membership changes via event ID 4728/4756."
                        ),
                    ))

                    # Store as fact.
                    await ctx.facts.add(
                        "ad.domain_admins", members, self.name,
                        host_id=bound_host_id,
                    )

            # ── 2. Domain computers ──────────────────────────────────
            computers = await asyncio.to_thread(
                _enum_computers, conn, base_dn,
            )

            if computers:
                comp_lines = "\n".join(
                    f"  - {c['cn']} ({c['dns_hostname']}) — {c['os']} {c['os_version']}"
                    for c in computers[:50]
                )
                suffix = (
                    f"\n  ... and {len(computers) - 50} more"
                    if len(computers) > 50
                    else ""
                )
                findings.append(Finding(
                    title=f"Domain computers enumerated ({len(computers)})",
                    description=(
                        f"Discovered {len(computers)} computer object(s) in "
                        f"domain {bound_domain}. These are potential lateral "
                        f"movement targets."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1087.002"],
                    evidence=[Evidence(
                        kind="domain_computers",
                        data=f"Domain computers:\n{comp_lines}{suffix}",
                    )],
                    remediation=(
                        "Remove stale computer accounts. Implement network "
                        "segmentation to limit lateral movement between systems."
                    ),
                ))

                await ctx.facts.add(
                    "ad.computers", computers, self.name,
                    host_id=bound_host_id,
                )

                # Register each computer as a potential host for the planner.
                for comp in computers:
                    hostname = comp["dns_hostname"] or comp["cn"]
                    if not hostname:
                        continue
                    new_host = Host(
                        ip=hostname,  # DNS hostname — resolver will handle it
                        hostname=hostname,
                        os=comp["os"] or None,
                        os_version=comp["os_version"] or None,
                        domain=bound_domain,
                    )
                    await ctx.facts.add(
                        "host", new_host, self.name, host_id=new_host.id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_host(new_host)

            # ── 3. Kerberoastable accounts ───────────────────────────
            kerberoastable = await asyncio.to_thread(
                _enum_kerberoastable, conn, base_dn,
            )

            if kerberoastable:
                kerb_lines = "\n".join(
                    f"  - {a['username']} — SPNs: {a['spns']}"
                    f"{' [adminCount=1]' if a['admin_count'] == '1' else ''}"
                    for a in kerberoastable
                )
                findings.append(Finding(
                    title=(
                        f"Kerberoastable accounts found ({len(kerberoastable)})"
                    ),
                    description=(
                        f"Found {len(kerberoastable)} user account(s) with "
                        f"servicePrincipalName set in domain {bound_domain}. "
                        f"These accounts are vulnerable to Kerberoasting — "
                        f"their TGS tickets can be requested and cracked offline."
                    ),
                    severity=Severity.HIGH,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1558.003"],
                    evidence=[Evidence(
                        kind="kerberoastable",
                        data=f"Kerberoastable accounts:\n{kerb_lines}",
                    )],
                    remediation=(
                        "Use Group Managed Service Accounts (gMSA) instead of "
                        "regular accounts with SPNs. For remaining service accounts, "
                        "set long (25+ char) random passwords. Monitor for "
                        "TGS-REQ events (event ID 4769) with RC4 encryption."
                    ),
                ))

                await ctx.facts.add(
                    "ad.kerberoastable", kerberoastable, self.name,
                    host_id=bound_host_id,
                )

            # ── 4. AS-REP Roastable accounts ─────────────────────────
            asrep = await asyncio.to_thread(
                _enum_asrep_roastable, conn, base_dn,
            )

            if asrep:
                asrep_lines = "\n".join(
                    f"  - {a['username']} ({a['dn']})" for a in asrep
                )
                findings.append(Finding(
                    title=f"AS-REP Roastable accounts found ({len(asrep)})",
                    description=(
                        f"Found {len(asrep)} account(s) with Kerberos "
                        f"pre-authentication disabled (DONT_REQUIRE_PREAUTH) "
                        f"in domain {bound_domain}. AS-REP responses for "
                        f"these accounts can be requested without credentials "
                        f"and cracked offline."
                    ),
                    severity=Severity.HIGH,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1558.004"],
                    evidence=[Evidence(
                        kind="asrep_roastable",
                        data=f"AS-REP Roastable accounts:\n{asrep_lines}",
                    )],
                    remediation=(
                        "Enable Kerberos pre-authentication for all accounts. "
                        "Remove the DONT_REQUIRE_PREAUTH flag via: "
                        "Set-ADAccountControl -DoesNotRequirePreAuth $false"
                    ),
                ))

            # ── 5. Unconstrained delegation ──────────────────────────
            unconstrained = await asyncio.to_thread(
                _enum_unconstrained_delegation, conn, base_dn,
            )

            if unconstrained:
                uc_lines = "\n".join(
                    f"  - {u['cn']} ({u['dns_hostname']})" for u in unconstrained
                )
                findings.append(Finding(
                    title=(
                        f"Unconstrained delegation computers "
                        f"found ({len(unconstrained)})"
                    ),
                    description=(
                        f"Found {len(unconstrained)} computer(s) trusted for "
                        f"unconstrained Kerberos delegation in domain "
                        f"{bound_domain}. These machines cache TGTs of users "
                        f"who authenticate to them, enabling credential theft "
                        f"and privilege escalation."
                    ),
                    severity=Severity.HIGH,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1558.001"],
                    evidence=[Evidence(
                        kind="unconstrained_delegation",
                        data=f"Unconstrained delegation computers:\n{uc_lines}",
                    )],
                    remediation=(
                        "Replace unconstrained delegation with constrained "
                        "delegation or resource-based constrained delegation. "
                        "Add sensitive accounts to the 'Protected Users' group "
                        "and enable 'Account is sensitive and cannot be delegated'."
                    ),
                ))

            # ── 6. Domain trusts ─────────────────────────────────────
            trusts = await asyncio.to_thread(
                _enum_domain_trusts, conn, base_dn,
            )

            if trusts:
                trust_lines = "\n".join(
                    f"  - {t['partner']} — {t['direction']} ({t['type']})"
                    for t in trusts
                )
                findings.append(Finding(
                    title=f"Domain trusts discovered ({len(trusts)})",
                    description=(
                        f"Discovered {len(trusts)} domain trust(s) from "
                        f"{bound_domain}. Trust relationships expand the "
                        f"attack surface and may enable cross-domain privilege "
                        f"escalation via SID history, trust key extraction, "
                        f"or cross-forest Kerberoasting."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1482"],
                    evidence=[Evidence(
                        kind="domain_trusts",
                        data=f"Domain trusts:\n{trust_lines}",
                    )],
                    remediation=(
                        "Audit and minimize domain trusts. Enable SID filtering "
                        "on all external trusts. Use selective authentication "
                        "instead of forest-wide trust where possible."
                    ),
                ))

                await ctx.facts.add(
                    "ad.trusts", trusts, self.name,
                    host_id=bound_host_id,
                )

            # ── 7. GPO links and OU structure ────────────────────────
            gpos = await asyncio.to_thread(_enum_gpo_links, conn, base_dn)
            ous = await asyncio.to_thread(_enum_ou_structure, conn, base_dn)

            if gpos:
                gpo_lines = "\n".join(
                    f"  - {g['name']} [{g['status']}] ({g['dn']})"
                    for g in gpos[:30]
                )
                suffix = (
                    f"\n  ... and {len(gpos) - 30} more"
                    if len(gpos) > 30
                    else ""
                )
                findings.append(Finding(
                    title=f"Group Policy Objects enumerated ({len(gpos)})",
                    description=(
                        f"Enumerated {len(gpos)} GPO(s) in domain "
                        f"{bound_domain}. GPOs control security settings, "
                        f"software deployment, and user configuration across "
                        f"the domain. Writable GPOs can be abused for "
                        f"domain-wide code execution."
                    ),
                    severity=Severity.INFO,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1484.001"],
                    evidence=[Evidence(
                        kind="gpo_enum",
                        data=f"GPOs:\n{gpo_lines}{suffix}",
                    )],
                    remediation=(
                        "Restrict GPO edit permissions. Monitor for unexpected "
                        "GPO modifications via event ID 5136."
                    ),
                ))

            if ous:
                ou_lines = "\n".join(
                    f"  - {o['name']} (GPO linked: {o['gpo_linked']})"
                    for o in ous[:30]
                )
                suffix = (
                    f"\n  ... and {len(ous) - 30} more"
                    if len(ous) > 30
                    else ""
                )
                findings.append(Finding(
                    title=f"Organizational Units enumerated ({len(ous)})",
                    description=(
                        f"Enumerated {len(ous)} OU(s) in domain "
                        f"{bound_domain}. OU structure reveals the "
                        f"organizational hierarchy and delegation model."
                    ),
                    severity=Severity.INFO,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1087.002"],
                    evidence=[Evidence(
                        kind="ou_enum",
                        data=f"Organizational Units:\n{ou_lines}{suffix}",
                    )],
                    remediation=(
                        "Review OU delegation permissions. Ensure "
                        "least-privilege OU administration."
                    ),
                ))

            # ── 8. LAPS readability ──────────────────────────────────
            laps_exposed = await asyncio.to_thread(
                _enum_laps, conn, base_dn,
            )

            if laps_exposed:
                laps_lines = "\n".join(
                    f"  - {entry['cn']} ({entry['dns_hostname']}): {entry['laps_password']}"
                    for entry in laps_exposed[:20]
                )
                suffix = (
                    f"\n  ... and {len(laps_exposed) - 20} more"
                    if len(laps_exposed) > 20
                    else ""
                )
                findings.append(Finding(
                    title=(
                        f"LAPS passwords readable ({len(laps_exposed)} computers)"
                    ),
                    description=(
                        f"Successfully read ms-Mcs-AdmPwd (LAPS local admin "
                        f"password) from {len(laps_exposed)} computer object(s) "
                        f"in domain {bound_domain}. This grants local admin "
                        f"access to these machines."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1003.003"],
                    evidence=[Evidence(
                        kind="laps_exposed",
                        data=f"LAPS passwords:\n{laps_lines}{suffix}",
                    )],
                    remediation=(
                        "Restrict read access to ms-Mcs-AdmPwd to only "
                        "authorized admin groups. Audit LAPS ACLs with "
                        "Find-AdmPwdExtendedRights. Migrate to Windows LAPS "
                        "with encrypted password storage."
                    ),
                ))

                # Register each LAPS password as an admin credential.
                for laps_entry in laps_exposed:
                    hostname = laps_entry["dns_hostname"] or laps_entry["cn"]
                    laps_cred = Credential(
                        host_id=bound_host_id,
                        username="Administrator",
                        cred_type=CredentialType.PASSWORD,
                        value=laps_entry["laps_password"],
                        domain=bound_domain,
                        source_module=self.name,
                        valid=True,
                        admin=True,
                    )
                    await ctx.facts.add(
                        "credential.admin", laps_cred, self.name,
                        host_id=bound_host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_credential(laps_cred)

            # ── 9. AdminSDHolder-protected accounts ──────────────────
            adminsdholder = await asyncio.to_thread(
                _enum_adminsdholder, conn, base_dn,
            )

            if adminsdholder:
                ash_lines = "\n".join(
                    f"  - {a['username']} — Groups: {a['groups']}"
                    for a in adminsdholder[:30]
                )
                suffix = (
                    f"\n  ... and {len(adminsdholder) - 30} more"
                    if len(adminsdholder) > 30
                    else ""
                )
                findings.append(Finding(
                    title=(
                        f"AdminSDHolder-protected accounts "
                        f"({len(adminsdholder)})"
                    ),
                    description=(
                        f"Found {len(adminsdholder)} account(s) protected by "
                        f"AdminSDHolder (adminCount=1) in domain "
                        f"{bound_domain}. These accounts have their ACLs "
                        f"overwritten hourly by the SDProp process. Stale "
                        f"adminCount flags on non-privileged accounts may "
                        f"indicate prior compromise or misconfiguration."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1087.002"],
                    evidence=[Evidence(
                        kind="adminsdholder",
                        data=(
                            f"AdminSDHolder-protected accounts:"
                            f"\n{ash_lines}{suffix}"
                        ),
                    )],
                    remediation=(
                        "Audit accounts with adminCount=1 and remove stale "
                        "entries. Ensure AdminSDHolder ACL is not modified. "
                        "Monitor for adminCount changes on unexpected accounts."
                    ),
                ))

            # ── 10. Password policy ──────────────────────────────────
            pwd_policy = await asyncio.to_thread(
                _enum_password_policy, conn, base_dn,
            )

            if pwd_policy:
                policy_lines = "\n".join(
                    f"  - {k}: {v}" for k, v in pwd_policy.items()
                )

                # Determine severity based on policy weaknesses.
                pwd_severity = Severity.INFO
                weaknesses: list[str] = []

                min_len = pwd_policy.get("min_length", "0")
                try:
                    if int(min_len) < 8:
                        weaknesses.append(
                            f"minimum length is {min_len} (should be >= 14)"
                        )
                        pwd_severity = Severity.MEDIUM
                except ValueError:
                    pass

                lockout = pwd_policy.get("lockout_threshold", "0")
                try:
                    if int(lockout) == 0:
                        weaknesses.append("no account lockout policy")
                        pwd_severity = Severity.MEDIUM
                except ValueError:
                    pass

                if pwd_policy.get("complexity_required") == "no":
                    weaknesses.append("password complexity not required")
                    pwd_severity = Severity.MEDIUM

                weakness_note = ""
                if weaknesses:
                    weakness_note = (
                        " Weaknesses found: " + "; ".join(weaknesses) + "."
                    )

                findings.append(Finding(
                    title="Domain password policy analyzed",
                    description=(
                        f"Retrieved password policy for domain "
                        f"{bound_domain}.{weakness_note}"
                    ),
                    severity=pwd_severity,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1201"],
                    evidence=[Evidence(
                        kind="password_policy",
                        data=f"Password policy:\n{policy_lines}",
                    )],
                    remediation=(
                        "Enforce minimum password length of 14+ characters. "
                        "Enable account lockout (5-10 attempts). Require "
                        "password complexity. Consider using Fine-Grained "
                        "Password Policies (PSOs) for privileged accounts."
                    ),
                ))

        finally:
            # Close the LDAP connection.
            with contextlib.suppress(Exception):
                await asyncio.to_thread(conn.unbind)

        # Persist all findings to the database.
        if ctx.db is not None:
            for finding in findings:
                await ctx.db.insert_finding(finding)

        return findings
