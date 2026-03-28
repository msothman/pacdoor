"""MSSQL enumeration — version, databases, xp_cmdshell, linked servers."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from typing import TYPE_CHECKING

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
# gracefully skipped) when impacket is not installed.
_impacket_available: bool | None = None
_MSSQL: type | None = None


def _ensure_impacket() -> bool:
    """Try to import impacket.tds; cache the result."""
    global _impacket_available, _MSSQL  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        from impacket import tds as _tds  # type: ignore[import-untyped]

        _MSSQL = _tds.MSSQL
        _impacket_available = True
    except ImportError:
        log.warning("impacket not installed — mssql_enum module will be skipped")
        _impacket_available = False
    return _impacket_available


# ── Helpers (all synchronous — run via asyncio.to_thread) ────────────


def _connect_mssql(ip: str, port: int = 1433, timeout: int = 10) -> object | None:
    """Create an MSSQL connection via impacket. Returns None on failure."""
    if _MSSQL is None:
        return None
    try:
        ms = _MSSQL(ip, port)
        ms.connect()
        return ms
    except Exception:
        return None


def _login(
    ms: object,
    username: str,
    password: str,
    domain: str = "",
) -> bool:
    """Attempt SQL authentication. Returns True on success."""
    try:
        return ms.login(database="master", loginData={  # type: ignore[union-attr]
            "UserName": username,
            "Password": password,
            "Domain": domain,
        })
    except Exception:
        # Fallback: some impacket versions use positional args
        pass
    try:
        return ms.login(  # type: ignore[union-attr]
            database="master",
            username=username,
            password=password,
            domain=domain,
        )
    except Exception:
        return False


def _get_version(ms: object) -> str | None:
    """Retrieve SQL Server version string."""
    try:
        ms.sql_query("SELECT @@version")  # type: ignore[union-attr]
        rows = ms.printRows()  # type: ignore[union-attr]
        if isinstance(rows, str) and rows.strip():
            return rows.strip()
        # Some impacket versions return rows differently
        ms.sql_query("SELECT SERVERPROPERTY('productversion')")  # type: ignore[union-attr]
        rows = ms.printRows()  # type: ignore[union-attr]
        if isinstance(rows, str) and rows.strip():
            return rows.strip()
    except Exception:
        pass
    return None


def _enum_databases(ms: object) -> list[str]:
    """List all databases on the server."""
    databases: list[str] = []
    try:
        ms.sql_query("SELECT name FROM sys.databases")  # type: ignore[union-attr]
        rows = ms.printRows()  # type: ignore[union-attr]
        if isinstance(rows, str):
            for line in rows.strip().splitlines():
                name = line.strip()
                if name and name != "name":
                    databases.append(name)
    except Exception:
        pass
    return databases


def _check_xp_cmdshell(ms: object) -> bool:
    """Return True if xp_cmdshell is enabled."""
    try:
        ms.sql_query(  # type: ignore[union-attr]
            "SELECT CONVERT(INT, ISNULL(value, value_in_use)) "
            "FROM sys.configurations WHERE name = 'xp_cmdshell'"
        )
        rows = ms.printRows()  # type: ignore[union-attr]
        if isinstance(rows, str) and "1" in rows:
            return True
    except Exception:
        pass
    return False


def _check_linked_servers(ms: object) -> list[str]:
    """Return names of linked servers."""
    servers: list[str] = []
    try:
        ms.sql_query("EXEC sp_linkedservers")  # type: ignore[union-attr]
        rows = ms.printRows()  # type: ignore[union-attr]
        if isinstance(rows, str):
            for line in rows.strip().splitlines():
                name = line.strip()
                if name and name.lower() not in ("srv_name", ""):
                    servers.append(name)
    except Exception:
        pass
    return servers


def _disconnect(ms: object) -> None:
    """Safely close the MSSQL connection."""
    with contextlib.suppress(Exception):
        ms.disconnect()  # type: ignore[union-attr]


def _sql_browser_query(ip: str, timeout: int = 5) -> dict[str, str] | None:
    """Query SQL Browser service on UDP 1434 for instance discovery.

    Returns a dict of instance info fields or None on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # 0x02 = CLNT_UCAST_EX — request all instances
        sock.sendto(b"\x02", (ip, 1434))
        data, _ = sock.recvfrom(4096)
        sock.close()

        if not data or len(data) < 3:
            return None

        # Response starts with 0x05 + 2-byte length, then semicolon-delimited pairs
        payload = data[3:].decode("ascii", errors="replace")
        tokens = payload.rstrip("\x00").split(";")
        info: dict[str, str] = {}
        for i in range(0, len(tokens) - 1, 2):
            key = tokens[i].strip()
            val = tokens[i + 1].strip()
            if key:
                info[key] = val
        return info if info else None
    except Exception:
        return None


# ── Module ───────────────────────────────────────────────────────────


class MSSQLEnumModule(BaseModule):
    name = "enum.mssql_enum"
    description = "MSSQL enumeration — version, databases, xp_cmdshell, linked servers"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046", "T1505.001"]
    required_facts = ["service.mssql"]
    produced_facts = ["mssql.version", "mssql.databases"]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _ensure_impacket():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        if not _ensure_impacket():
            return []

        findings: list[Finding] = []

        mssql_services = await ctx.facts.get_all("service.mssql")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in mssql_services:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 1433
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
        """Run full MSSQL enumeration on a single host."""

        # ── 1. SQL Browser instance discovery (UDP 1434) ─────────
        browser_info = await asyncio.to_thread(_sql_browser_query, ip)
        if browser_info:
            info_lines = "\n".join(f"  {k}: {v}" for k, v in browser_info.items())
            findings.append(Finding(
                title=f"SQL Browser service responding on {ip}:1434/udp",
                description=(
                    f"SQL Server Browser service on {ip} disclosed instance "
                    "information via UDP 1434. This reveals server names, "
                    "instance names, versions, and listening ports."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="sql_browser",
                    data=f"SQL Browser response from {ip}:\n{info_lines}",
                )],
                remediation=(
                    "Disable SQL Server Browser service if not required. "
                    "If needed, restrict UDP 1434 access via firewall rules."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 2. Connect to MSSQL ──────────────────────────────────
        ms = await asyncio.to_thread(_connect_mssql, ip, port)
        if ms is None:
            log.debug("mssql_enum: could not connect to %s:%d", ip, port)
            return

        # ── 3. Authenticated enumeration (if creds supplied) ─────
        creds = ctx.user_creds
        if creds.username is None or (
            creds.password is None and creds.ntlm_hash is None
        ):
            await asyncio.to_thread(_disconnect, ms)
            return

        authed = await asyncio.to_thread(
            _login, ms, creds.username, creds.password or "", creds.domain or ""
        )
        if not authed:
            log.debug(
                "mssql_enum: authentication failed for %s on %s:%d",
                creds.username, ip, port,
            )
            await asyncio.to_thread(_disconnect, ms)
            return

        # ── 3a. Version ──────────────────────────────────────────
        version = await asyncio.to_thread(_get_version, ms)
        if version:
            await ctx.facts.add(
                "mssql.version",
                {"host": ip, "port": port, "version": version},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"MSSQL version identified on {ip}",
                description=(
                    f"SQL Server on {ip}:{port} identified. Version information "
                    "can be used to check for known vulnerabilities."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mssql_version",
                    data=f"MSSQL version on {ip}:{port}:\n  {version}",
                )],
                remediation=(
                    "Keep SQL Server updated with the latest cumulative updates "
                    "and security patches."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 3b. Databases ────────────────────────────────────────
        databases = await asyncio.to_thread(_enum_databases, ms)
        if databases:
            await ctx.facts.add(
                "mssql.databases",
                {"host": ip, "port": port, "databases": databases},
                self.name,
                host_id=host_id,
            )
            db_lines = "\n".join(f"  - {db}" for db in databases)
            findings.append(Finding(
                title=f"MSSQL databases enumerated on {ip}",
                description=(
                    f"Enumerated {len(databases)} database(s) on {ip}:{port} "
                    f"as '{creds.domain or '.'}\\{creds.username}'."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mssql_databases",
                    data=f"Databases on {ip}:{port}:\n{db_lines}",
                )],
            ))

        # ── 3c. xp_cmdshell ──────────────────────────────────────
        xp_enabled = await asyncio.to_thread(_check_xp_cmdshell, ms)
        if xp_enabled:
            findings.append(Finding(
                title=f"xp_cmdshell enabled on {ip}",
                description=(
                    f"xp_cmdshell is enabled on {ip}:{port}. This stored procedure "
                    "allows execution of arbitrary operating system commands directly "
                    "from SQL queries, enabling full system compromise."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1505.001"],
                evidence=[Evidence(
                    kind="xp_cmdshell",
                    data=f"xp_cmdshell is ENABLED on {ip}:{port}",
                )],
                remediation=(
                    "Disable xp_cmdshell: "
                    "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; "
                    "Also disable 'show advanced options' if not needed."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1505/001/",
                ],
            ))

        # ── 3d. Linked servers ────────────────────────────────────
        linked = await asyncio.to_thread(_check_linked_servers, ms)
        if linked:
            link_lines = "\n".join(f"  - {s}" for s in linked)
            findings.append(Finding(
                title=f"Linked servers found on {ip}",
                description=(
                    f"Discovered {len(linked)} linked server(s) on {ip}:{port}. "
                    "Linked servers can be abused for lateral movement by "
                    "executing queries on remote SQL Server instances."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="linked_servers",
                    data=f"Linked servers on {ip}:{port}:\n{link_lines}",
                )],
                remediation=(
                    "Remove unnecessary linked servers: EXEC sp_dropserver 'name'; "
                    "For required links, restrict permissions to least privilege."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        await asyncio.to_thread(_disconnect, ms)
