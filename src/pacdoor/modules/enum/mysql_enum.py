"""MySQL enumeration — version, databases, privileges via raw handshake."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
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


# ── MySQL wire protocol helpers ──────────────────────────────────────
#
# The MySQL handshake is a simple binary protocol.  After TCP connect the
# server sends an Initial Handshake Packet (protocol 10) that contains
# the server version *before* any authentication occurs.  We parse only
# this packet for unauthenticated enumeration.
#
# Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/
#            page_protocol_connection_phase_packets_protocol_handshake_v10.html


def _parse_handshake(data: bytes) -> dict[str, Any] | None:
    """Parse a MySQL Initial Handshake Packet (protocol version 10).

    Returns a dict with version, server_charset, auth_plugin, capabilities
    or None if the packet cannot be parsed.
    """
    if len(data) < 5:
        return None

    # First 4 bytes: 3-byte payload length + 1-byte sequence id
    payload_len = struct.unpack("<I", data[:3] + b"\x00")[0]
    data[3]
    payload = data[4 : 4 + payload_len]

    if len(payload) < 1:
        return None

    protocol_version = payload[0]
    if protocol_version == 0xFF:
        # Error packet — connection refused
        return None

    # Protocol version 10 (the standard)
    if protocol_version != 10:
        return {"protocol_version": protocol_version, "version": None}

    # Server version: null-terminated string starting at byte 1
    nul_pos = payload.find(b"\x00", 1)
    if nul_pos == -1:
        return None
    version = payload[1:nul_pos].decode("ascii", errors="replace")

    result: dict[str, Any] = {
        "protocol_version": protocol_version,
        "version": version,
    }

    # After version: 4-byte connection_id + 8-byte auth_plugin_data_part_1
    # + 1 filler + 2 capability_flags_lower + 1 charset + 2 status
    # + 2 capability_flags_upper + 1 auth_plugin_data_len + 10 reserved
    pos = nul_pos + 1
    if len(payload) < pos + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10:
        return result

    pos += 4 + 8 + 1  # connection_id + auth_data_1 + filler
    cap_lower = struct.unpack("<H", payload[pos : pos + 2])[0]
    pos += 2
    charset = payload[pos]
    result["server_charset"] = charset
    pos += 1
    pos += 2  # status_flags
    cap_upper = struct.unpack("<H", payload[pos : pos + 2])[0]
    pos += 2
    capabilities = cap_lower | (cap_upper << 16)
    result["capabilities"] = capabilities

    auth_data_len = payload[pos]
    pos += 1
    pos += 10  # reserved

    # auth_plugin_data_part_2 (variable length)
    if capabilities & 0x00080000:  # CLIENT_SECURE_CONNECTION
        part2_len = max(13, auth_data_len - 8)
        pos += part2_len

    # auth_plugin_name (null-terminated)
    if capabilities & 0x00080000:  # CLIENT_PLUGIN_AUTH
        plugin_nul = payload.find(b"\x00", pos)
        if plugin_nul != -1:
            result["auth_plugin"] = payload[pos:plugin_nul].decode(
                "ascii", errors="replace"
            )

    return result


def _connect_and_read_handshake(
    ip: str, port: int = 3306, timeout: int = 10
) -> bytes | None:
    """Open a raw TCP socket and read the MySQL server greeting."""
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        data = sock.recv(4096)
        sock.close()
        return data if data else None
    except Exception:
        return None


def _mysql_auth_and_query(
    ip: str,
    port: int,
    username: str,
    password: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Connect via pymysql (if available) for authenticated enumeration.

    Returns a dict with databases, file_priv, udf info.
    Falls back to mysql.connector, then returns empty on ImportError.
    """
    result: dict[str, Any] = {
        "databases": [],
        "file_priv": False,
        "has_udf": False,
    }

    conn = None
    cursor = None

    # Try pymysql first, then mysql.connector
    for connect_fn in (_try_pymysql, _try_mysql_connector):
        conn_and_cursor = connect_fn(ip, port, username, password, timeout)
        if conn_and_cursor is not None:
            conn, cursor = conn_and_cursor
            break

    if conn is None or cursor is None:
        return result

    try:
        # Enumerate databases
        cursor.execute("SHOW DATABASES")
        result["databases"] = [row[0] for row in cursor.fetchall()]

        # Check FILE privilege
        try:
            cursor.execute(
                "SELECT privilege_type FROM information_schema.user_privileges "
                "WHERE grantee LIKE %s AND privilege_type = 'FILE'",
                (f"%{username}%",),
            )
            result["file_priv"] = cursor.fetchone() is not None
        except Exception:
            pass

        # Check for UDF
        try:
            cursor.execute("SELECT name, dl FROM mysql.func")
            udf_rows = cursor.fetchall()
            if udf_rows:
                result["has_udf"] = True
                result["udf_list"] = [
                    {"name": r[0], "library": r[1]} for r in udf_rows
                ]
        except Exception:
            pass

    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            cursor.close()
        with contextlib.suppress(Exception):
            conn.close()

    return result


def _try_pymysql(
    ip: str, port: int, username: str, password: str, timeout: int
) -> tuple[Any, Any] | None:
    try:
        import pymysql  # type: ignore[import-untyped]

        conn = pymysql.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout,
        )
        return conn, conn.cursor()
    except ImportError:
        return None
    except Exception:
        return None


def _try_mysql_connector(
    ip: str, port: int, username: str, password: str, timeout: int
) -> tuple[Any, Any] | None:
    try:
        import mysql.connector  # type: ignore[import-untyped]

        conn = mysql.connector.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connection_timeout=timeout,
        )
        return conn, conn.cursor()
    except ImportError:
        return None
    except Exception:
        return None


# ── Module ───────────────────────────────────────────────────────────


class MySQLEnumModule(BaseModule):
    name = "enum.mysql_enum"
    description = "MySQL enumeration — version, databases, privileges"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046"]
    required_facts = ["service.mysql"]
    produced_facts = ["mysql.version", "mysql.databases"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        mysql_services = await ctx.facts.get_all("service.mysql")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in mysql_services:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 3306
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
        """Run full MySQL enumeration on a single host."""

        # ── 1. Unauthenticated handshake — version extraction ────
        raw = await asyncio.to_thread(_connect_and_read_handshake, ip, port)
        if raw is None:
            log.debug("mysql_enum: could not connect to %s:%d", ip, port)
            return

        handshake = _parse_handshake(raw)
        if handshake is None:
            log.debug("mysql_enum: failed to parse handshake from %s:%d", ip, port)
            return

        version = handshake.get("version")
        auth_plugin = handshake.get("auth_plugin", "")

        if version:
            await ctx.facts.add(
                "mysql.version",
                {"host": ip, "port": port, "version": version},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"MySQL version disclosed on {ip}",
                description=(
                    f"MySQL server on {ip}:{port} disclosed version '{version}' "
                    "in the initial handshake before authentication. Version "
                    "information aids in identifying known vulnerabilities."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mysql_version",
                    data=f"MySQL version on {ip}:{port}: {version}",
                )],
                remediation=(
                    "Keep MySQL updated to the latest stable release. "
                    "Consider using a connection proxy to suppress version "
                    "disclosure in the handshake."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 2. Check for old/weak authentication plugin ──────────
        old_auth_plugins = {"mysql_old_password", "mysql_clear_password"}
        if auth_plugin in old_auth_plugins:
            findings.append(Finding(
                title=f"Weak MySQL authentication on {ip}",
                description=(
                    f"MySQL on {ip}:{port} uses the '{auth_plugin}' "
                    "authentication plugin which is cryptographically weak. "
                    "Credentials can be captured or cracked trivially."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mysql_weak_auth",
                    data=(
                        f"Authentication plugin: {auth_plugin} on {ip}:{port}"
                    ),
                )],
                remediation=(
                    "Upgrade to caching_sha2_password or mysql_native_password "
                    "authentication. Set default_authentication_plugin in my.cnf."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 3. Authenticated enumeration (if creds supplied) ─────
        creds = ctx.user_creds
        if creds.username is None or creds.password is None:
            return

        auth_result = await asyncio.to_thread(
            _mysql_auth_and_query,
            ip,
            port,
            creds.username,
            creds.password,
        )

        databases = auth_result.get("databases", [])
        if databases:
            await ctx.facts.add(
                "mysql.databases",
                {"host": ip, "port": port, "databases": databases},
                self.name,
                host_id=host_id,
            )
            db_lines = "\n".join(f"  - {db}" for db in databases)
            findings.append(Finding(
                title=f"MySQL databases enumerated on {ip}",
                description=(
                    f"Enumerated {len(databases)} database(s) on {ip}:{port} "
                    f"as '{creds.username}'."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mysql_databases",
                    data=f"Databases on {ip}:{port}:\n{db_lines}",
                )],
            ))

        # FILE privilege check
        if auth_result.get("file_priv"):
            findings.append(Finding(
                title=f"MySQL FILE privilege granted on {ip}",
                description=(
                    f"User '{creds.username}' on {ip}:{port} has the FILE "
                    "privilege. This allows reading arbitrary files from the "
                    "server filesystem via LOAD_FILE() and writing files via "
                    "SELECT INTO OUTFILE, enabling data exfiltration or webshell "
                    "deployment."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mysql_file_priv",
                    data=(
                        f"FILE privilege granted to '{creds.username}' "
                        f"on {ip}:{port}"
                    ),
                )],
                remediation=(
                    "Revoke FILE privilege: REVOKE FILE ON *.* FROM 'user'@'host'; "
                    "Set --secure-file-priv to restrict file operations to a "
                    "specific directory."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # UDF check
        if auth_result.get("has_udf"):
            udf_list = auth_result.get("udf_list", [])
            udf_lines = "\n".join(
                f"  - {u['name']} ({u['library']})" for u in udf_list
            )
            findings.append(Finding(
                title=f"MySQL UDF functions detected on {ip}",
                description=(
                    f"User-defined functions found on {ip}:{port}. UDFs loaded "
                    "from shared libraries can execute arbitrary system commands, "
                    "often used for privilege escalation or persistence."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mysql_udf",
                    data=f"UDF functions on {ip}:{port}:\n{udf_lines}",
                )],
                remediation=(
                    "Audit and remove unauthorized UDFs: DROP FUNCTION name; "
                    "Restrict plugin_dir permissions and monitor for unauthorized "
                    "shared library additions."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))
