"""LDAP enumeration — anonymous bind, users, SPNs, AS-REP roastable, password policy."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
    Evidence,
    Finding,
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Lazy-imported at first use so the module can still be loaded (and
# gracefully skipped) when ldap3 is not installed.
_ldap3_available: bool | None = None
_ldap3: Any = None


def _ensure_ldap3() -> bool:
    """Try to import ldap3; cache the result."""
    global _ldap3_available, _ldap3  # noqa: PLW0603
    if _ldap3_available is not None:
        return _ldap3_available
    try:
        import ldap3 as _lib  # type: ignore[import-untyped]

        _ldap3 = _lib
        _ldap3_available = True
    except ImportError:
        log.warning("ldap3 not installed — ldap_enum module will be skipped")
        _ldap3_available = False
    return _ldap3_available


# ── Helpers (all synchronous — run via asyncio.to_thread) ────────────


def _connect_and_bind(
    ip: str,
    port: int = 389,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    timeout: int = 10,
) -> tuple[Any, bool]:
    """Connect to LDAP and attempt a bind.

    Returns (connection, success).  ``connection`` may be None on failure.
    If *username* is None an anonymous bind is attempted.
    """
    if _ldap3 is None:
        return None, False
    try:
        server = _ldap3.Server(ip, port=port, get_info=_ldap3.ALL, connect_timeout=timeout)
        if username is not None:
            bind_dn = username
            if domain and "\\" not in username and "@" not in username:
                bind_dn = f"{domain}\\{username}"
            conn = _ldap3.Connection(
                server,
                user=bind_dn,
                password=password or "",
                authentication=_ldap3.NTLM if domain else _ldap3.SIMPLE,
                auto_bind=False,
                receive_timeout=timeout,
            )
        else:
            conn = _ldap3.Connection(
                server,
                auto_bind=False,
                receive_timeout=timeout,
            )
        conn.open()
        bound = conn.bind()
        return conn, bound
    except Exception:
        return None, False


def _get_base_dn(conn: Any) -> str | None:
    """Extract the default naming context (base DN) from rootDSE."""
    try:
        server_info = conn.server.info
        if server_info is None:
            return None
        # defaultNamingContext is stored as a list in ldap3
        ctx = server_info.other.get("defaultNamingContext")
        if ctx:
            return ctx[0] if isinstance(ctx, list) else ctx
        # Fallback: parse from namingContexts
        ncs = server_info.naming_contexts
        if ncs:
            for nc in ncs:
                if "DC=" in nc.upper():
                    return nc
            return ncs[0]
    except Exception:
        pass
    return None


def _search(
    conn: Any,
    base_dn: str,
    search_filter: str,
    attributes: list[str],
    size_limit: int = 1000,
) -> list[dict[str, Any]]:
    """Perform an LDAP search and return a list of entry dicts."""
    results: list[dict[str, Any]] = []
    try:
        conn.search(
            base_dn,
            search_filter,
            attributes=attributes,
            size_limit=size_limit,
        )
        for entry in conn.entries:
            record: dict[str, Any] = {"dn": str(entry.entry_dn)}
            for attr_name in attributes:
                try:
                    val = entry[attr_name].value
                    if isinstance(val, list):
                        record[attr_name] = [str(v) for v in val]
                    elif val is not None:
                        record[attr_name] = str(val)
                    else:
                        record[attr_name] = None
                except Exception:
                    record[attr_name] = None
            results.append(record)
    except Exception:
        pass
    return results


def _enumerate_users(conn: Any, base_dn: str) -> list[dict[str, Any]]:
    """Enumerate user accounts."""
    return _search(
        conn,
        base_dn,
        "(&(objectCategory=person)(objectClass=user))",
        ["sAMAccountName", "description", "memberOf", "userAccountControl"],
    )


def _enumerate_spns(conn: Any, base_dn: str) -> list[dict[str, Any]]:
    """Find Kerberoastable accounts (users with servicePrincipalName set)."""
    return _search(
        conn,
        base_dn,
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
        ["sAMAccountName", "servicePrincipalName", "memberOf"],
    )


def _enumerate_asrep(conn: Any, base_dn: str) -> list[dict[str, Any]]:
    """Find AS-REP roastable accounts (DONT_REQUIRE_PREAUTH flag set)."""
    return _search(
        conn,
        base_dn,
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        ["sAMAccountName", "memberOf"],
    )


def _enumerate_domain_admins(conn: Any, base_dn: str) -> list[dict[str, Any]]:
    """Enumerate members of the Domain Admins group."""
    return _search(
        conn,
        base_dn,
        "(&(objectCategory=person)(objectClass=user)"
        "(memberOf=CN=Domain Admins,CN=Users," + base_dn + "))",
        ["sAMAccountName"],
    )


def _get_password_policy(conn: Any, base_dn: str) -> dict[str, Any]:
    """Retrieve domain password policy attributes."""
    policy: dict[str, Any] = {}
    try:
        conn.search(
            base_dn,
            "(objectClass=domain)",
            attributes=[
                "minPwdLength",
                "lockoutThreshold",
                "lockoutDuration",
                "maxPwdAge",
                "minPwdAge",
                "pwdHistoryLength",
                "pwdProperties",
            ],
            search_scope="BASE",
        )
        if conn.entries:
            entry = conn.entries[0]
            for attr in [
                "minPwdLength", "lockoutThreshold", "lockoutDuration",
                "maxPwdAge", "minPwdAge", "pwdHistoryLength", "pwdProperties",
            ]:
                try:
                    val = entry[attr].value
                    policy[attr] = str(val) if val is not None else None
                except Exception:
                    policy[attr] = None
    except Exception:
        pass
    return policy


def _disconnect(conn: Any) -> None:
    """Safely close the LDAP connection."""
    with contextlib.suppress(Exception):
        conn.unbind()


# Password-like patterns in description fields
_PASSWORD_PATTERN = re.compile(
    r"(password|passwd|pwd|pass)\s*[:=]\s*\S+",
    re.IGNORECASE,
)


# ── Module ───────────────────────────────────────────────────────────


class LDAPEnumModule(BaseModule):
    name = "enum.ldap_enum"
    description = "LDAP enumeration — anonymous bind, users, SPNs, password policy"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1087.002", "T1069.002"]
    required_facts = ["service.ldap"]
    produced_facts = [
        "ldap.anonymous_bind",
        "ldap.users",
        "ldap.spns",
    ]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _ensure_ldap3():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        if not _ensure_ldap3():
            return []

        findings: list[Finding] = []

        ldap_facts = await ctx.facts.get_all("service.ldap")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in ldap_facts:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 389
            targets.append((host_id, ip, port_num))

        for host_id, ip, port_num in targets:
            await self._enumerate_host(ctx, findings, host_id, ip, port_num)

        return findings

    async def _enumerate_host(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Run full LDAP enumeration on a single host."""


        # ── 1. Try anonymous bind ────────────────────────────────────
        conn, bound = await asyncio.to_thread(_connect_and_bind, ip, port)
        if conn is not None and bound:
            await ctx.facts.add(
                "ldap.anonymous_bind",
                {"host": ip, "port": port},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"LDAP anonymous bind allowed on {ip}",
                description=(
                    f"Host {ip}:{port} permits anonymous LDAP binding. "
                    "This exposes directory information including user accounts, "
                    "group memberships, and organizational structure to unauthenticated "
                    "attackers."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1087.002"],
                evidence=[Evidence(
                    kind="anonymous_bind",
                    data=f"Anonymous LDAP bind succeeded on {ip}:{port}",
                )],
                remediation=(
                    "Disable anonymous LDAP binds: set dsHeuristics attribute "
                    "7th character to 0, and configure 'Network access: Restrict "
                    "anonymous access to Named Pipes and Shares' in Group Policy."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1087/002/",
                ],
            ))

            await self._do_enumeration(ctx, findings, host_id, ip, port, conn, "anonymous bind")
            await asyncio.to_thread(_disconnect, conn)
        elif conn is not None:
            await asyncio.to_thread(_disconnect, conn)

        # ── 2. Authenticated bind (if creds supplied) ────────────────
        creds = ctx.user_creds
        if creds.username is not None and (
            creds.password is not None or creds.ntlm_hash is not None
        ):
            conn, bound = await asyncio.to_thread(
                _connect_and_bind,
                ip,
                port,
                username=creds.username,
                password=creds.password or creds.ntlm_hash or "",
                domain=creds.domain,
            )
            if conn is not None and bound:
                await self._do_enumeration(
                    ctx, findings, host_id, ip, port, conn,
                    f"{creds.domain or '.'}\\{creds.username}",
                )
                await asyncio.to_thread(_disconnect, conn)
            elif conn is not None:
                await asyncio.to_thread(_disconnect, conn)

    async def _do_enumeration(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        conn: Any,
        auth: str,
    ) -> None:
        """Perform LDAP enumeration using an established connection."""

        base_dn = await asyncio.to_thread(_get_base_dn, conn)
        if base_dn is None:
            log.debug("ldap_enum: could not determine base DN for %s", ip)
            return

        # ── Users ────────────────────────────────────────────────────
        users = await asyncio.to_thread(_enumerate_users, conn, base_dn)
        if users:
            await ctx.facts.add(
                "ldap.users",
                {"host": ip, "base_dn": base_dn, "users": users, "auth": auth},
                self.name,
                host_id=host_id,
            )

            user_lines = "\n".join(
                f"  - {u.get('sAMAccountName', '?')}"
                for u in users[:50]  # cap evidence length
            )
            suffix = f"\n  ... and {len(users) - 50} more" if len(users) > 50 else ""
            findings.append(Finding(
                title=f"LDAP user enumeration on {ip} ({auth})",
                description=(
                    f"Enumerated {len(users)} user account(s) via LDAP on "
                    f"{ip}:{port} authenticated as {auth}."
                ),
                severity=Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1087.002"],
                evidence=[Evidence(
                    kind="ldap_users",
                    data=f"Users ({len(users)}) from {ip} ({auth}):\n{user_lines}{suffix}",
                )],
                remediation=(
                    "Restrict anonymous LDAP queries and audit which accounts "
                    "have unnecessary directory read permissions."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1087/002/",
                ],
            ))

            # Check descriptions for embedded passwords
            for user in users:
                desc = user.get("description")
                if desc and _PASSWORD_PATTERN.search(desc):
                    sam = user.get("sAMAccountName", "unknown")
                    findings.append(Finding(
                        title=f"Password in description for '{sam}' on {ip}",
                        description=(
                            f"The LDAP description field for user '{sam}' on {ip} "
                            "contains what appears to be a password. This is a common "
                            "misconfiguration that exposes credentials to any "
                            "authenticated user."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1087.002"],
                        evidence=[Evidence(
                            kind="password_in_description",
                            data=f"User: {sam}  Description: {desc}",
                        )],
                        remediation=(
                            f"Remove the password from the description field of "
                            f"account '{sam}' immediately and rotate the credential."
                        ),
                    ))

        # ── Kerberoastable accounts (SPNs) ───────────────────────────
        spn_users = await asyncio.to_thread(_enumerate_spns, conn, base_dn)
        if spn_users:
            await ctx.facts.add(
                "ldap.spns",
                {"host": ip, "spn_users": spn_users, "auth": auth},
                self.name,
                host_id=host_id,
            )

            spn_lines = "\n".join(
                f"  - {u.get('sAMAccountName', '?')} -> {u.get('servicePrincipalName', '?')}"
                for u in spn_users
            )
            findings.append(Finding(
                title=f"Kerberoastable accounts found on {ip} ({auth})",
                description=(
                    f"Found {len(spn_users)} user account(s) with "
                    "servicePrincipalName set on {ip}. These accounts are "
                    "vulnerable to Kerberoasting — an attacker can request "
                    "TGS tickets and crack them offline to recover passwords."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1558.003"],
                evidence=[Evidence(
                    kind="kerberoastable",
                    data=f"Kerberoastable accounts on {ip}:\n{spn_lines}",
                )],
                remediation=(
                    "Use Group Managed Service Accounts (gMSA) instead of "
                    "regular user accounts for services. Where SPNs on user "
                    "accounts are unavoidable, ensure passwords are 25+ characters "
                    "and rotated regularly."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1558/003/",
                ],
            ))

        # ── AS-REP roastable accounts ────────────────────────────────
        asrep_users = await asyncio.to_thread(_enumerate_asrep, conn, base_dn)
        if asrep_users:
            asrep_lines = "\n".join(
                f"  - {u.get('sAMAccountName', '?')}"
                for u in asrep_users
            )
            findings.append(Finding(
                title=f"AS-REP roastable accounts found on {ip} ({auth})",
                description=(
                    f"Found {len(asrep_users)} account(s) with Kerberos "
                    "pre-authentication disabled on {ip}. An attacker can "
                    "request AS-REP tickets for these accounts and crack "
                    "them offline without any authentication."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1558.004"],
                evidence=[Evidence(
                    kind="asrep_roastable",
                    data=f"AS-REP roastable accounts on {ip}:\n{asrep_lines}",
                )],
                remediation=(
                    "Enable Kerberos pre-authentication for all user accounts "
                    "unless there is a documented business requirement. Review "
                    "accounts with 'Do not require Kerberos preauthentication' "
                    "checked in AD Users and Computers."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1558/004/",
                ],
            ))

        # ── Domain Admins ────────────────────────────────────────────
        domain_admins = await asyncio.to_thread(
            _enumerate_domain_admins, conn, base_dn,
        )
        if domain_admins:
            da_lines = "\n".join(
                f"  - {u.get('sAMAccountName', '?')}"
                for u in domain_admins
            )
            findings.append(Finding(
                title=f"Domain Admin accounts enumerated on {ip} ({auth})",
                description=(
                    f"Enumerated {len(domain_admins)} Domain Admin account(s) "
                    f"via LDAP on {ip}. This information aids privilege "
                    "escalation and targeted attacks."
                ),
                severity=Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1069.002"],
                evidence=[Evidence(
                    kind="domain_admins",
                    data=f"Domain Admin members on {ip}:\n{da_lines}",
                )],
                remediation=(
                    "Minimize the number of Domain Admin accounts. Use tiered "
                    "administration and restrict LDAP query permissions."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1069/002/",
                ],
            ))

        # ── Password policy ──────────────────────────────────────────
        policy = await asyncio.to_thread(_get_password_policy, conn, base_dn)
        if policy:
            policy_lines = "\n".join(
                f"  {k}: {v}" for k, v in policy.items() if v is not None
            )
            if policy_lines:
                min_len_str = policy.get("minPwdLength")
                lockout_str = policy.get("lockoutThreshold")

                weak = False
                issues: list[str] = []
                if min_len_str is not None:
                    try:
                        min_len = int(min_len_str)
                        if min_len < 8:
                            weak = True
                            issues.append(f"minimum password length is {min_len} (< 8)")
                    except ValueError:
                        pass
                if lockout_str is not None:
                    try:
                        lockout = int(lockout_str)
                        if lockout == 0:
                            weak = True
                            issues.append("no account lockout threshold (brute-force possible)")
                    except ValueError:
                        pass

                severity = Severity.MEDIUM if weak else Severity.INFO
                title_suffix = " (WEAK)" if weak else ""
                desc_suffix = (
                    " Issues: " + "; ".join(issues) + "."
                    if issues
                    else ""
                )

                findings.append(Finding(
                    title=f"Password policy retrieved from {ip}{title_suffix} ({auth})",
                    description=(
                        f"Retrieved domain password policy from {ip} via "
                        f"LDAP as {auth}.{desc_suffix}"
                    ),
                    severity=severity,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1087.002"],
                    evidence=[Evidence(
                        kind="password_policy",
                        data=f"Password policy on {ip}:\n{policy_lines}",
                    )],
                    remediation=(
                        "Enforce a minimum password length of at least 14 characters, "
                        "enable account lockout after 5 failed attempts, and consider "
                        "implementing fine-grained password policies for privileged accounts."
                    ),
                ))
