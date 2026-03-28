"""Redis enumeration — auth check, INFO, writable config, modules."""

from __future__ import annotations

import asyncio
import contextlib
import logging
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

_CRLF = b"\r\n"
_DEFAULT_TIMEOUT = 10


# ── Raw RESP protocol helpers ────────────────────────────────────────
#
# Redis uses the RESP (REdis Serialization Protocol) over plain TCP.
# We use raw asyncio streams to avoid any external dependency.


async def _open_connection(
    ip: str, port: int, timeout: float = _DEFAULT_TIMEOUT
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Open an asyncio TCP connection to Redis."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        return reader, writer
    except Exception:
        return None


async def _send_command(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *args: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> str | None:
    """Send a RESP command and read the full response.

    Handles simple strings (+), errors (-), integers (:),
    bulk strings ($), and multi-bulk (*) at the top level.
    """
    # Build RESP array
    parts = [f"*{len(args)}".encode()]
    for arg in args:
        encoded = arg.encode()
        parts.append(f"${len(encoded)}".encode())
        parts.append(encoded)
    writer.write(_CRLF.join(parts) + _CRLF)
    await writer.drain()

    try:
        return await asyncio.wait_for(_read_response(reader), timeout=timeout)
    except Exception:
        return None


async def _read_response(reader: asyncio.StreamReader) -> str | None:
    """Read a single RESP response."""
    line = await reader.readline()
    if not line:
        return None

    line = line.rstrip(b"\r\n")
    prefix = chr(line[0]) if line else ""
    body = line[1:].decode("utf-8", errors="replace")

    if prefix == "+":
        return body
    if prefix == "-":
        return f"ERR:{body}"
    if prefix == ":":
        return body
    if prefix == "$":
        length = int(body)
        if length == -1:
            return None
        data = await reader.readexactly(length + 2)  # +2 for trailing \r\n
        return data[:-2].decode("utf-8", errors="replace")
    if prefix == "*":
        count = int(body)
        if count == -1:
            return None
        parts: list[str] = []
        for _ in range(count):
            part = await _read_response(reader)
            parts.append(part if part is not None else "(nil)")
        return "\n".join(parts)

    return body


def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Safely close an asyncio StreamWriter."""
    with contextlib.suppress(Exception):
        writer.close()


def _parse_info(info_text: str) -> dict[str, str]:
    """Parse Redis INFO output into a flat dict."""
    result: dict[str, str] = {}
    for line in info_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip()] = val.strip()
    return result


# ── Module ───────────────────────────────────────────────────────────


class RedisEnumModule(BaseModule):
    name = "enum.redis_enum"
    description = "Redis enumeration — auth check, INFO, writable config, modules"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046"]
    required_facts = ["service.redis"]
    produced_facts = ["redis.noauth", "redis.info", "redis.writable"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        redis_services = await ctx.facts.get_all("service.redis")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in redis_services:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 6379
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
        """Run full Redis enumeration on a single host."""

        pair = await _open_connection(ip, port)
        if pair is None:
            log.debug("redis_enum: could not connect to %s:%d", ip, port)
            return

        reader, writer = pair
        authenticated = False

        # ── 1. PING — check if auth is required ─────────────────
        resp = await _send_command(reader, writer, "PING")
        if resp == "PONG":
            # No authentication required — critical finding
            authenticated = True
            await ctx.facts.add(
                "redis.noauth",
                {"host": ip, "port": port},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"Redis requires no authentication on {ip}",
                description=(
                    f"Redis on {ip}:{port} responds to commands without "
                    "authentication. Any network-reachable client can read "
                    "and write data, execute Lua scripts, and potentially "
                    "achieve remote code execution via CONFIG SET or MODULE LOAD."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="redis_noauth",
                    data=f"PING → PONG (no auth required) on {ip}:{port}",
                )],
                remediation=(
                    "Set a strong password with 'requirepass' in redis.conf. "
                    "Use ACLs (Redis 6+) for fine-grained access control. "
                    "Bind to localhost or use firewall rules to restrict access."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                    "https://redis.io/docs/management/security/",
                ],
            ))
        elif resp and resp.startswith("ERR:"):
            # Auth required — try with provided creds
            creds = ctx.user_creds
            if creds.password is not None:
                auth_resp = await _send_command(
                    reader, writer, "AUTH", creds.password
                )
                if auth_resp == "OK":
                    authenticated = True
                elif creds.username is not None:
                    # Redis 6+ ACL auth: AUTH username password
                    auth_resp = await _send_command(
                        reader, writer, "AUTH", creds.username, creds.password
                    )
                    if auth_resp == "OK":
                        authenticated = True

            if not authenticated:
                log.debug(
                    "redis_enum: authentication required on %s:%d, no valid creds",
                    ip, port,
                )
                _close_writer(writer)
                return

        if not authenticated:
            _close_writer(writer)
            return

        # ── 2. INFO — version, OS, memory, keyspace ─────────────
        info_raw = await _send_command(reader, writer, "INFO")
        if info_raw and not info_raw.startswith("ERR:"):
            info = _parse_info(info_raw)

            await ctx.facts.add(
                "redis.info",
                {"host": ip, "port": port, "info": info},
                self.name,
                host_id=host_id,
            )

            version = info.get("redis_version", "unknown")
            os_info = info.get("os", "unknown")
            mem_used = info.get("used_memory_human", "unknown")

            # Collect keyspace summary
            keyspace_entries: list[str] = []
            for key, val in info.items():
                if key.startswith("db"):
                    keyspace_entries.append(f"  {key}: {val}")
            keyspace_summary = (
                "\n".join(keyspace_entries) if keyspace_entries else "  (empty)"
            )

            findings.append(Finding(
                title=f"Redis server info disclosed on {ip}",
                description=(
                    f"Redis {version} on {ip}:{port} running on {os_info}. "
                    f"Memory usage: {mem_used}."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="redis_info",
                    data=(
                        f"Redis INFO on {ip}:{port}:\n"
                        f"  Version: {version}\n"
                        f"  OS: {os_info}\n"
                        f"  Memory: {mem_used}\n"
                        f"  Keyspace:\n{keyspace_summary}"
                    ),
                )],
                remediation=(
                    "Rename or disable the INFO command via 'rename-command' "
                    "in redis.conf to prevent information disclosure."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 3. CONFIG GET dir / dbfilename — writable check ──────
        writable = False
        config_details: list[str] = []

        dir_resp = await _send_command(reader, writer, "CONFIG", "GET", "dir")
        if dir_resp and not dir_resp.startswith("ERR:"):
            config_details.append(f"dir = {dir_resp}")
            writable = True

        dbfile_resp = await _send_command(
            reader, writer, "CONFIG", "GET", "dbfilename"
        )
        if dbfile_resp and not dbfile_resp.startswith("ERR:"):
            config_details.append(f"dbfilename = {dbfile_resp}")
            writable = True

        if writable:
            await ctx.facts.add(
                "redis.writable",
                {"host": ip, "port": port, "config": config_details},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"Redis CONFIG writable on {ip}",
                description=(
                    f"Redis on {ip}:{port} allows CONFIG GET/SET operations. "
                    "An attacker can change the dump file path to write "
                    "arbitrary files (e.g. crontab, SSH authorized_keys, "
                    "webshell) achieving remote code execution."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="redis_writable",
                    data=(
                        f"CONFIG accessible on {ip}:{port}:\n"
                        + "\n".join(f"  {d}" for d in config_details)
                    ),
                )],
                remediation=(
                    "Rename or disable CONFIG command: "
                    "'rename-command CONFIG \"\"' in redis.conf. "
                    "Run Redis as a non-root user with restricted filesystem "
                    "permissions."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                    "https://redis.io/docs/management/security/",
                ],
            ))

        # ── 4. MODULE LIST — check for loaded modules ────────────
        module_resp = await _send_command(reader, writer, "MODULE", "LIST")
        if module_resp and not module_resp.startswith("ERR:") and module_resp.strip():
            findings.append(Finding(
                title=f"Redis modules loaded on {ip}",
                description=(
                    f"Redis on {ip}:{port} has loadable modules enabled. "
                    "Modules can execute arbitrary native code within the "
                    "Redis process, potentially enabling RCE."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="redis_modules",
                    data=f"Loaded modules on {ip}:{port}:\n  {module_resp}",
                )],
                remediation=(
                    "Disable module loading if not required. "
                    "Set 'enable-module-command no' in Redis 7+ config."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        _close_writer(writer)
