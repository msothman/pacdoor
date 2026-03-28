"""SMB enumeration — shares, signing, null sessions, user accounts."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from pacdoor.core.models import (
    Credential,
    CredentialType,
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
# gracefully skipped) when impacket is not installed.
_impacket_available: bool | None = None
SMBConnection: type | None = None
SAMR: type | None = None
TRANSPORT: type | None = None


def _ensure_impacket() -> bool:
    """Try to import impacket; cache the result."""
    global _impacket_available, SMBConnection, SAMR, TRANSPORT  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        from impacket.dcerpc.v5 import samr as _samr  # type: ignore[import-untyped]
        from impacket.dcerpc.v5 import transport as _transport
        from impacket.smbconnection import SMBConnection as _Conn  # type: ignore[import-untyped]

        SMBConnection = _Conn
        SAMR = _samr
        TRANSPORT = _transport
        _impacket_available = True
    except ImportError:
        log.warning("impacket not installed — smb_enum module will be skipped")
        _impacket_available = False
    return _impacket_available


# ── Helpers (all synchronous — run via asyncio.to_thread) ────────────


def _connect_smb(ip: str, port: int = 445, timeout: int = 10) -> object | None:
    """Create an SMBConnection and negotiate. Returns None on failure."""
    if SMBConnection is None:
        return None
    try:
        conn = SMBConnection(ip, ip, sess_port=port)
        conn.negotiateSession()
        return conn
    except Exception:
        return None


def _check_signing(conn: object) -> bool:
    """Return True if signing is *not* required (i.e. disabled/optional)."""
    try:
        return not conn.isSigningRequired()  # type: ignore[union-attr]
    except Exception:
        return False


def _null_session_login(conn: object) -> bool:
    """Attempt a null session (empty credentials). Returns True on success."""
    try:
        conn.login("", "")  # type: ignore[union-attr]
        return True
    except Exception:
        return False


def _authenticated_login(
    conn: object,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str | None = None,
) -> bool:
    """Attempt an authenticated login. Supports password or NTLM hash."""
    try:
        if ntlm_hash:
            lm, nt = "", ntlm_hash
            if ":" in ntlm_hash:
                lm, nt = ntlm_hash.split(":", 1)
            conn.login(username, "", domain, lmhash=lm, nthash=nt)  # type: ignore[union-attr]
        else:
            conn.login(username, password, domain)  # type: ignore[union-attr]
        return True
    except Exception:
        return False


def _list_shares(conn: object) -> list[dict[str, str]]:
    """Enumerate shares and their permissions."""
    shares: list[dict[str, str]] = []
    try:
        raw_shares = conn.listShares()  # type: ignore[union-attr]
    except Exception:
        return shares

    for share_info in raw_shares:
        name = share_info["shi1_netname"][:-1]  # strip null terminator
        remark = share_info["shi1_remark"][:-1]
        readable = False
        writable = False

        # Probe read access
        try:
            conn.listPath(name, "\\*")  # type: ignore[union-attr]
            readable = True
        except Exception:
            pass

        # Probe write access
        try:
            conn.createDirectory(name, "\\__pacdoor_probe__")  # type: ignore[union-attr]
            conn.deleteDirectory(name, "\\__pacdoor_probe__")  # type: ignore[union-attr]
            writable = True
        except Exception:
            pass

        perms: list[str] = []
        if readable:
            perms.append("READ")
        if writable:
            perms.append("WRITE")

        shares.append({
            "name": name,
            "remark": remark,
            "permissions": ", ".join(perms) if perms else "NO ACCESS",
        })
    return shares


def _enumerate_users_samr(ip: str, port: int = 445) -> list[str]:
    """Use SAMR over DCE/RPC to enumerate domain/local users."""
    if SAMR is None or TRANSPORT is None:
        return []
    users: list[str] = []
    try:
        rpctransport = TRANSPORT.SMBTransport(ip, port, r"\samr", "", "")
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(SAMR.MSRPC_UUID_SAMR)

        resp = SAMR.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = SAMR.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]

        for domain_info in domains:
            domain_name = domain_info["Name"]
            resp = SAMR.hSamrLookupDomainInSamServer(
                dce, server_handle, domain_name
            )
            domain_sid = resp["DomainId"]
            resp = SAMR.hSamrOpenDomain(
                dce, server_handle, domainId=domain_sid
            )
            domain_handle = resp["DomainHandle"]

            status = 0x8000001A  # STATUS_MORE_ENTRIES — enter loop
            enum_ctx = 0
            while status == 0x8000001A:
                try:
                    resp = SAMR.hSamrEnumerateUsersInDomain(
                        dce, domain_handle, enumerationContext=enum_ctx
                    )
                    status = resp["ErrorCode"]
                    enum_ctx = resp["EnumerationContext"]
                    for user in resp["Buffer"]["Buffer"]:
                        users.append(user["Name"])
                except Exception:
                    break

        dce.disconnect()
    except Exception:
        pass
    return users


def _disconnect(conn: object) -> None:
    """Safely close the SMB connection."""
    with contextlib.suppress(Exception):
        conn.close()  # type: ignore[union-attr]


# ── Module ───────────────────────────────────────────────────────────


class SMBEnumModule(BaseModule):
    name = "enum.smb_enum"
    description = "SMB enumeration — signing, null sessions, shares, users"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1135", "T1087"]
    required_facts = ["service.smb"]
    produced_facts = [
        "smb.shares",
        "smb.signing_disabled",
        "smb.null_session",
        "credential.valid",
    ]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _ensure_impacket():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        if not _ensure_impacket():
            return []

        findings: list[Finding] = []

        # Gather all hosts that have SMB exposed
        smb_ports = await ctx.facts.get_all("service.smb")
        # Deduplicate by host_id
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []  # (host_id, ip, port)

        for fact in smb_ports:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 445
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
        """Run full SMB enumeration on a single host."""

        # ── 1. Connect and check signing ─────────────────────────────
        conn = await asyncio.to_thread(_connect_smb, ip, port)
        if conn is None:
            log.debug("smb_enum: could not connect to %s:%d", ip, port)
            return

        signing_disabled = await asyncio.to_thread(_check_signing, conn)
        if signing_disabled:
            await ctx.facts.add(
                "smb.signing_disabled",
                {"host": ip, "port": port},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"SMB signing not required on {ip}",
                description=(
                    f"SMB signing is not enforced on {ip}:{port}. This allows "
                    "relay attacks (e.g. ntlmrelayx) where an attacker can "
                    "forward captured NTLM authentications to this host."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1557"],
                evidence=[Evidence(
                    kind="smb_signing",
                    data=f"SMB signing required: False (host={ip}, port={port})",
                )],
                remediation=(
                    "Enable and require SMB signing via Group Policy: "
                    "Computer Configuration > Policies > Windows Settings > "
                    "Security Settings > Local Policies > Security Options > "
                    "'Microsoft network server: Digitally sign communications (always)' = Enabled"
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
            ))

        # ── 2. Null session ──────────────────────────────────────────
        # Need a fresh connection for login attempts
        await asyncio.to_thread(_disconnect, conn)
        conn = await asyncio.to_thread(_connect_smb, ip, port)
        if conn is None:
            return

        null_session = await asyncio.to_thread(_null_session_login, conn)
        if null_session:
            await ctx.facts.add(
                "smb.null_session",
                {"host": ip, "port": port},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"SMB null session allowed on {ip}",
                description=(
                    f"Host {ip}:{port} permits null session authentication "
                    "(empty username and password). This may expose share "
                    "listings, user accounts, and other sensitive information."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1135"],
                evidence=[Evidence(
                    kind="null_session",
                    data=f"Null session login succeeded on {ip}:{port}",
                )],
                remediation=(
                    "Disable null sessions: set "
                    "'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous' "
                    "to 2 and remove 'ANONYMOUS LOGON' from 'Access this computer "
                    "from the network' policy."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1135/",
                ],
            ))

            # Enumerate shares under null session
            shares = await asyncio.to_thread(_list_shares, conn)
            await self._process_shares(
                ctx, findings, host_id, ip, port, shares, auth="null session"
            )

            # Enumerate users via SAMR
            users = await asyncio.to_thread(_enumerate_users_samr, ip, port)
            if users:
                evidence_data = "\n".join(f"  - {u}" for u in users)
                findings.append(Finding(
                    title=f"User enumeration via null session on {ip}",
                    description=(
                        f"Enumerated {len(users)} user account(s) through "
                        f"SAMR over null session on {ip}:{port}."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1087"],
                    evidence=[Evidence(
                        kind="user_enum",
                        data=f"Users found via SAMR:\n{evidence_data}",
                    )],
                    remediation=(
                        "Restrict anonymous enumeration via Group Policy: "
                        "'Network access: Do not allow anonymous enumeration "
                        "of SAM accounts' = Enabled"
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1087/",
                    ],
                ))

            await asyncio.to_thread(_disconnect, conn)
        else:
            await asyncio.to_thread(_disconnect, conn)

        # ── 3. Authenticated enumeration (if creds supplied) ─────────
        creds = ctx.user_creds
        if creds.username is not None and (
            creds.password is not None or creds.ntlm_hash is not None
        ):
            conn = await asyncio.to_thread(_connect_smb, ip, port)
            if conn is None:
                return

            authed = await asyncio.to_thread(
                _authenticated_login,
                conn,
                creds.username,
                creds.password or "",
                creds.domain or "",
                creds.ntlm_hash,
            )
            if authed:
                # Record the valid credential
                cred = Credential(
                    host_id=host_id,
                    username=creds.username,
                    cred_type=(
                        CredentialType.NTLM_HASH
                        if creds.ntlm_hash
                        else CredentialType.PASSWORD
                    ),
                    value=creds.ntlm_hash or creds.password or "",
                    domain=creds.domain,
                    source_module=self.name,
                    valid=True,
                )
                await ctx.facts.add(
                    "credential.valid", cred, self.name, host_id=host_id
                )
                if ctx.db is not None:
                    await ctx.db.insert_credential(cred)

                findings.append(Finding(
                    title=f"Valid SMB credentials on {ip}",
                    description=(
                        f"Authenticated to {ip}:{port} as "
                        f"'{creds.domain or '.'}\\{creds.username}'."
                    ),
                    severity=Severity.HIGH,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1135"],
                    evidence=[Evidence(
                        kind="smb_auth",
                        data=(
                            f"Authenticated login succeeded: "
                            f"{creds.domain or '.'}\\{creds.username} @ {ip}:{port}"
                        ),
                    )],
                ))

                shares = await asyncio.to_thread(_list_shares, conn)
                await self._process_shares(
                    ctx,
                    findings,
                    host_id,
                    ip,
                    port,
                    shares,
                    auth=f"{creds.domain or '.'}\\{creds.username}",
                )

            await asyncio.to_thread(_disconnect, conn)

    async def _process_shares(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        shares: list[dict[str, str]],
        auth: str,
    ) -> None:
        """Record share enumeration results as facts and findings."""
        if not shares:
            return

        await ctx.facts.add(
            "smb.shares",
            {"host": ip, "port": port, "shares": shares, "auth": auth},
            self.name,
            host_id=host_id,
        )

        share_lines = "\n".join(
            f"  {s['name']:30s} [{s['permissions']}]  {s['remark']}"
            for s in shares
        )
        findings.append(Finding(
            title=f"SMB shares enumerated on {ip} ({auth})",
            description=(
                f"Discovered {len(shares)} share(s) on {ip}:{port} "
                f"authenticated as {auth}."
            ),
            severity=Severity.INFO,
            host_id=host_id,
            module_name=self.name,
            attack_technique_ids=["T1135"],
            evidence=[Evidence(
                kind="smb_shares",
                data=f"Shares on {ip} ({auth}):\n{share_lines}",
            )],
        ))

        # Writable non-default shares are noteworthy
        default_shares = {"IPC$", "ADMIN$", "C$", "D$", "PRINT$"}
        for share in shares:
            if "WRITE" in share["permissions"] and share["name"] not in default_shares:
                findings.append(Finding(
                    title=f"Writable SMB share '{share['name']}' on {ip}",
                    description=(
                        f"Share '{share['name']}' on {ip}:{port} is writable "
                        f"by {auth}. This could allow malware deployment, "
                        "data exfiltration staging, or lateral movement."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1135"],
                    evidence=[Evidence(
                        kind="writable_share",
                        data=(
                            f"Share: {share['name']}  Perms: {share['permissions']}  "
                            f"Auth: {auth}  Host: {ip}:{port}"
                        ),
                    )],
                    remediation=(
                        f"Review permissions on share '{share['name']}' and "
                        "restrict write access to authorized users only."
                    ),
                ))
