"""Default credential checker — tries well-known default passwords on discovered services."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
    Credential,
    CredentialType,
    Evidence,
    Finding,
    Phase,
    Port,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "default_creds.json"

# Port -> service key mapping for credential lookups
_PORT_SERVICE: dict[int, str] = {
    22: "ssh",
    21: "ftp",
    3306: "mysql",
    1433: "mssql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
}

# Ports that trigger HTTP admin panel checks
_HTTP_PORTS: set[int] = {80, 443, 8080, 8443, 8000, 8888, 3000, 9090, 8081}


def _load_cred_db() -> dict[str, Any]:
    """Load the default credentials JSON. Returns empty dict on failure."""
    try:
        return json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        log.error("Failed to load default credentials from %s", _DATA_FILE)
        return {}


# ── Per-service checkers (all synchronous) ───────────────────────────


def _check_ssh(ip: str, port: int, username: str, password: str) -> bool:
    """Try SSH login via paramiko."""
    try:
        import paramiko  # type: ignore[import-untyped]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip,
            port=port,
            username=username,
            password=password,
            timeout=8,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=8,
            auth_timeout=8,
        )
        client.close()
        return True
    except ImportError:
        log.debug("paramiko not installed — skipping SSH credential check")
        return False
    except Exception:
        return False


def _check_ftp(ip: str, port: int, username: str, password: str) -> bool:
    """Try FTP login via raw socket commands."""
    import socket

    try:
        sock = socket.create_connection((ip, port), timeout=8)
        banner = sock.recv(1024)  # noqa: F841 — consume banner
        sock.sendall(f"USER {username}\r\n".encode())
        resp = sock.recv(1024).decode(errors="replace")
        if resp.startswith("331") or resp.startswith("230"):
            sock.sendall(f"PASS {password}\r\n".encode())
            resp = sock.recv(1024).decode(errors="replace")
            sock.sendall(b"QUIT\r\n")
            sock.close()
            return resp.startswith("230")
        sock.close()
    except Exception:
        pass
    return False


def _check_mysql(ip: str, port: int, username: str, password: str) -> bool:
    """Try MySQL login. Uses pymysql if available, else raw socket probe."""
    try:
        import pymysql  # type: ignore[import-untyped]

        conn = pymysql.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=8,
        )
        conn.close()
        return True
    except ImportError:
        pass
    except Exception:
        return False

    # Fallback: raw socket — send a native auth packet.
    # This is best-effort; a proper driver is preferred.
    import socket
    import struct

    try:
        sock = socket.create_connection((ip, port), timeout=8)
        # Read server greeting
        header = sock.recv(4)
        if len(header) < 4:
            sock.close()
            return False
        pkt_len = struct.unpack("<I", header[:3] + b"\x00")[0]
        _greeting = sock.recv(pkt_len)
        sock.close()
        # Cannot complete handshake without proper auth plugin support.
        # Return False — this path only confirms the port is MySQL.
        return False
    except Exception:
        return False


def _check_mssql(ip: str, port: int, username: str, password: str) -> bool:
    """Try MSSQL login via impacket's TDS client."""
    try:
        from impacket.tds import MSSQL as TDSClient  # type: ignore[import-untyped]

        client = TDSClient(ip, port)
        client.connect()
        result = client.login(None, username, password)
        client.disconnect()
        return result
    except ImportError:
        log.debug("impacket not installed — skipping MSSQL credential check")
        return False
    except Exception:
        return False


def _check_postgresql(ip: str, port: int, username: str, password: str) -> bool:
    """Try PostgreSQL login via psycopg2 or pg8000."""
    # Try psycopg2 first
    try:
        import psycopg2  # type: ignore[import-untyped]

        conn = psycopg2.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=8,
            dbname="postgres",
        )
        conn.close()
        return True
    except ImportError:
        pass
    except Exception:
        return False

    # Fallback: pg8000
    try:
        import pg8000  # type: ignore[import-untyped]

        conn = pg8000.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            timeout=8,
            database="postgres",
        )
        conn.close()
        return True
    except ImportError:
        pass
    except Exception:
        pass
    return False


def _check_redis(ip: str, port: int, _username: str, password: str) -> tuple[bool, bool]:
    """Check Redis auth. Returns (success, no_auth_required).

    If password is empty, we just PING. A PONG without AUTH means no-auth.
    """
    import socket

    try:
        sock = socket.create_connection((ip, port), timeout=8)

        if not password:
            # Probe for no-auth
            sock.sendall(b"PING\r\n")
            resp = sock.recv(1024).decode(errors="replace")
            sock.close()
            if "+PONG" in resp:
                return (True, True)
            return (False, False)

        # Try AUTH with password
        sock.sendall(f"AUTH {password}\r\n".encode())
        resp = sock.recv(1024).decode(errors="replace")
        sock.close()
        return ("+OK" in resp, False)
    except Exception:
        return (False, False)


def _check_mongodb(ip: str, port: int, username: str, password: str) -> tuple[bool, bool]:
    """Check MongoDB. Returns (success, no_auth_required).

    Empty creds -> probe for unauthenticated access.
    """
    try:
        import pymongo  # type: ignore[import-untyped]

        if not username and not password:
            client = pymongo.MongoClient(
                ip, port, serverSelectionTimeoutMS=8000, connectTimeoutMS=8000,
            )
            # Try listing databases — succeeds only without auth
            dbs = client.list_database_names()
            client.close()
            return (bool(dbs), True)

        uri = f"mongodb://{username}:{password}@{ip}:{port}/admin"
        client = pymongo.MongoClient(
            uri, serverSelectionTimeoutMS=8000, connectTimeoutMS=8000
        )
        client.admin.command("ping")
        client.close()
        return (True, False)
    except ImportError:
        log.debug("pymongo not installed — skipping MongoDB credential check")
        return (False, False)
    except Exception:
        return (False, False)


def _check_http_basic(
    ip: str, port: int, path: str, username: str, password: str, use_ssl: bool,
) -> bool:
    """Try HTTP Basic auth against an admin panel."""
    import base64
    import http.client

    try:
        if use_ssl:
            import ssl

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=8, context=context)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=8)

        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        conn.close()
        # 200/301/302 (not 401/403) = success
        return resp.status not in (401, 403, 404)
    except Exception:
        return False


# ── Dispatcher ───────────────────────────────────────────────────────


_SERVICE_CHECKERS = {
    "ssh": _check_ssh,
    "ftp": _check_ftp,
    "mysql": _check_mysql,
    "mssql": _check_mssql,
    "postgresql": _check_postgresql,
}


# ── Module ───────────────────────────────────────────────────────────


class DefaultCredsModule(BaseModule):
    name = "vuln.default_creds"
    description = "Try default/vendor credentials on discovered services"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1078", "T1110"]
    required_facts = ["port.open"]
    produced_facts = ["credential.valid", "credential.admin"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        cred_db = _load_cred_db()
        if not cred_db:
            return []

        findings: list[Finding] = []
        open_ports = await ctx.facts.get_values("port.open")

        # Group ports by host
        host_ports: dict[str, list[Port]] = {}
        for port in open_ports:
            host_ports.setdefault(port.host_id, []).append(port)

        for host_id, ports in host_ports.items():
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue

            for port in ports:
                await self._check_port(
                    ctx, cred_db, findings, host_id, ip, port
                )

        return findings

    async def _check_port(
        self,
        ctx: ModuleContext,
        cred_db: dict[str, Any],
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: Port,
    ) -> None:
        """Dispatch credential checks for a single port."""
        port_num = port.port

        # ── Standard services (SSH, FTP, MySQL, MSSQL, PostgreSQL) ───
        svc_key = _PORT_SERVICE.get(port_num)
        if svc_key and svc_key in _SERVICE_CHECKERS and svc_key in cred_db:
            checker = _SERVICE_CHECKERS[svc_key]
            creds_list = cred_db[svc_key].get("credentials", [])
            for entry in creds_list:
                await ctx.rate_limiter.acquire()
                user = entry["username"]
                pw = entry["password"]
                success = await asyncio.to_thread(checker, ip, port_num, user, pw)
                if success:
                    await self._record_valid_cred(
                        ctx, findings, host_id, ip, port_num, svc_key, user, pw
                    )
                    # Stop trying more creds for this service once we
                    # find one — avoid unnecessary login noise.
                    break

        # ── Redis ────────────────────────────────────────────────────
        if port_num == 6379 and "redis" in cred_db:
            creds_list = cred_db["redis"].get("credentials", [])
            for entry in creds_list:
                await ctx.rate_limiter.acquire()
                pw = entry["password"]
                success, no_auth = await asyncio.to_thread(
                    _check_redis, ip, port_num, "", pw
                )
                if no_auth:
                    await self._record_no_auth(
                        ctx, findings, host_id, ip, port_num, "redis"
                    )
                    break
                if success:
                    await self._record_valid_cred(
                        ctx, findings, host_id, ip, port_num, "redis", "default", pw
                    )
                    break

        # ── MongoDB ──────────────────────────────────────────────────
        if port_num == 27017 and "mongodb" in cred_db:
            creds_list = cred_db["mongodb"].get("credentials", [])
            for entry in creds_list:
                await ctx.rate_limiter.acquire()
                user = entry["username"]
                pw = entry["password"]
                success, no_auth = await asyncio.to_thread(
                    _check_mongodb, ip, port_num, user, pw
                )
                if no_auth:
                    await self._record_no_auth(
                        ctx, findings, host_id, ip, port_num, "mongodb"
                    )
                    break
                if success:
                    await self._record_valid_cred(
                        ctx, findings, host_id, ip, port_num, "mongodb", user, pw
                    )
                    break

        # ── HTTP admin panels ────────────────────────────────────────
        if port_num in _HTTP_PORTS and "http_admin" in cred_db:
            use_ssl = port_num in (443, 8443)
            panels = cred_db["http_admin"].get("panels", [])
            for panel in panels:
                path = panel["path"]
                product = panel.get("product", "HTTP")
                for entry in panel.get("credentials", []):
                    await ctx.rate_limiter.acquire()
                    user = entry["username"]
                    pw = entry["password"]
                    success = await asyncio.to_thread(
                        _check_http_basic, ip, port_num, path, user, pw, use_ssl
                    )
                    if success:
                        await self._record_valid_cred(
                            ctx,
                            findings,
                            host_id,
                            ip,
                            port_num,
                            f"http ({product})",
                            user,
                            pw,
                            is_admin=True,
                            panel_path=path,
                        )
                        break  # found creds for this panel, move on

    async def _record_valid_cred(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        service: str,
        username: str,
        password: str,
        is_admin: bool = False,
        panel_path: str | None = None,
    ) -> None:
        """Store a valid credential as a Fact, persist to DB, create Finding."""
        # Well-known admin usernames
        admin_users = {"root", "sa", "admin", "administrator", "postgres"}
        is_admin = is_admin or username.lower() in admin_users

        cred = Credential(
            host_id=host_id,
            username=username,
            cred_type=CredentialType.PASSWORD,
            value=password,
            source_module=self.name,
            valid=True,
            admin=is_admin,
        )

        fact_type = "credential.admin" if is_admin else "credential.valid"
        await ctx.facts.add(fact_type, cred, self.name, host_id=host_id)
        # Also always add as credential.valid for modules that only require that
        if is_admin:
            await ctx.facts.add("credential.valid", cred, self.name, host_id=host_id)

        if ctx.db is not None:
            await ctx.db.insert_credential(cred)

        sev = Severity.CRITICAL if is_admin else Severity.HIGH
        location = f"{ip}:{port} ({service})"
        if panel_path:
            location = f"{ip}:{port}{panel_path} ({service})"

        desc = (
            f"Default credentials '{username}:{password}' accepted on "
            f"{location}."
        )
        if is_admin:
            desc += " This grants administrative access."

        findings.append(Finding(
            title=f"Default {'admin ' if is_admin else ''}credentials on {ip}:{port} ({service})",
            description=desc,
            severity=sev,
            host_id=host_id,
            module_name=self.name,
            attack_technique_ids=["T1078"],
            evidence=[Evidence(
                kind="default_credential",
                data=(
                    f"Service: {service}  Host: {ip}:{port}  "
                    f"User: {username}  Pass: {password}  Admin: {is_admin}"
                ),
            )],
            remediation=(
                f"Change the default password for '{username}' on the "
                f"{service} service at {ip}:{port}. Use a strong, unique password."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1078/",
                "https://attack.mitre.org/techniques/T1110/",
            ],
        ))

    async def _record_no_auth(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        service: str,
    ) -> None:
        """Record that a service requires no authentication at all.

        Creates a proper Credential object (not a raw dict) so that
        downstream modules expecting Credential attributes work correctly.
        """
        cred = Credential(
            host_id=host_id,
            username="(no-auth)",
            cred_type=CredentialType.PASSWORD,
            value="",
            source_module=self.name,
            valid=True,
            admin=True,
        )
        await ctx.facts.add(
            "credential.admin", cred, self.name, host_id=host_id,
        )
        await ctx.facts.add(
            "credential.valid", cred, self.name, host_id=host_id,
        )
        if ctx.db is not None:
            await ctx.db.insert_credential(cred)

        findings.append(Finding(
            title=f"{service.upper()} requires no authentication on {ip}:{port}",
            description=(
                f"The {service} service on {ip}:{port} is accessible without "
                "any authentication. Anyone with network access can read and "
                "modify data."
            ),
            severity=Severity.CRITICAL,
            host_id=host_id,
            module_name=self.name,
            attack_technique_ids=["T1078"],
            evidence=[Evidence(
                kind="no_auth",
                data=f"Service: {service}  Host: {ip}:{port}  Authentication: NONE",
            )],
            remediation=(
                f"Enable authentication on the {service} service at {ip}:{port}. "
                f"Bind to localhost if remote access is not required."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1078/",
            ],
        ))
