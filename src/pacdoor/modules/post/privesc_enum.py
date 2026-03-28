"""Privilege escalation enumeration on compromised hosts (Windows + Linux)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
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
        log.debug("impacket not installed — Windows privesc checks unavailable")
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
        log.debug("paramiko not installed — Linux privesc checks unavailable")
        _paramiko_available = False
    return _paramiko_available


# ── Windows helpers (impacket — synchronous) ─────────────────────────


def _win_connect(
    ip: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str | None = None,
    port: int = 445,
) -> Any | None:
    """Establish an authenticated SMB connection for remote enumeration."""
    try:
        from impacket.smbconnection import SMBConnection  # type: ignore[import-untyped]

        conn = SMBConnection(ip, ip, sess_port=port)
        conn.negotiateSession()
        if ntlm_hash:
            lm, nt = "", ntlm_hash
            if ":" in ntlm_hash:
                lm, nt = ntlm_hash.split(":", 1)
            conn.login(username, "", domain, lmhash=lm, nthash=nt)
        else:
            conn.login(username, password, domain)
        return conn
    except Exception:
        return None


def _win_exec_cmd(ip: str, username: str, password: str, domain: str, command: str, ntlm_hash: str | None = None) -> str:
    """Execute a command via impacket's smbexec/wmiexec-style approach.

    Falls back to reading command output from a remote share.
    """
    try:
        from impacket.dcerpc.v5 import scmr
        from impacket.dcerpc.v5 import transport as _transport  # type: ignore[import-untyped]

        string_binding = f"ncacn_np:{ip}[\\pipe\\svcctl]"
        rpctransport = _transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_credentials(username, password, domain, ntlm_hash or "", "")
        rpctransport.set_dport(445)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        resp = scmr.hROpenSCManagerW(dce)
        sc_handle = resp["lpScHandle"]

        # Use cmd.exe to redirect output to a temp file, then read it
        output_file = "C:\\Windows\\Temp\\__pacdoor_pe.tmp"
        service_cmd = f"cmd.exe /c {command} > {output_file} 2>&1"
        service_name = "__pacdoor_pe_svc"

        try:
            resp = scmr.hRCreateServiceW(
                dce, sc_handle, service_name, service_name,
                lpBinaryPathName=service_cmd,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            svc_handle = resp["lpServiceHandle"]
            with contextlib.suppress(Exception):
                scmr.hRStartServiceW(dce, svc_handle)
            scmr.hRDeleteService(dce, svc_handle)
            scmr.hRCloseServiceHandle(dce, svc_handle)
        except Exception:
            pass

        scmr.hRCloseServiceHandle(dce, sc_handle)
        dce.disconnect()

        # Read the output file via SMB
        import time
        time.sleep(2)  # Give command time to complete

        from io import BytesIO

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

        output_buf = BytesIO()
        try:
            conn.getFile("C$", "Windows\\Temp\\__pacdoor_pe.tmp", output_buf.write)
            conn.deleteFile("C$", "Windows\\Temp\\__pacdoor_pe.tmp")
        except Exception:
            pass
        conn.close()
        return output_buf.getvalue().decode("utf-8", errors="replace")
    except Exception as e:
        log.debug("win_exec_cmd failed: %s", e)
        return ""


def _win_check_unquoted_service_paths(output: str) -> list[str]:
    """Parse sc query output to find unquoted service paths with spaces."""
    paths: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if "BINARY_PATH_NAME" in line.upper() or "PATHNAME" in line.upper():
            _, _, path = line.partition(":")
            path = path.strip()
            # Unquoted if contains spaces and not quoted
            if " " in path and not path.startswith('"') and "\\Windows\\" not in path:
                paths.append(path)
    return paths


def _win_check_always_install_elevated(output: str) -> bool:
    """Check if AlwaysInstallElevated is set."""
    return "0x1" in output


def _win_check_token_privileges(output: str) -> list[str]:
    """Find dangerous token privileges."""
    dangerous = {"SeImpersonatePrivilege", "SeDebugPrivilege", "SeAssignPrimaryTokenPrivilege",
                 "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeLoadDriverPrivilege"}
    found: list[str] = []
    for line in output.splitlines():
        for priv in dangerous:
            if priv in line and "Enabled" in line:
                found.append(priv)
    return found


# ── Linux helpers (paramiko — synchronous) ───────────────────────────


def _linux_connect(
    ip: str,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    timeout: int = 10,
) -> Any | None:
    """Establish an SSH connection for remote enumeration."""
    try:
        import paramiko  # type: ignore[import-untyped]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path:
            client.connect(ip, port=port, username=username, key_filename=key_path, timeout=timeout)
        else:
            client.connect(ip, port=port, username=username, password=password, timeout=timeout)
        return client
    except Exception:
        return None


def _linux_exec(client: Any, command: str, timeout: int = 15) -> str:
    """Execute a command via SSH and return stdout."""
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _linux_check_sudo(client: Any) -> list[str]:
    """Check what commands the user can sudo."""
    output = _linux_exec(client, "sudo -l 2>/dev/null")
    entries: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line and ("NOPASSWD" in line or "ALL" in line or "/" in line):
            entries.append(line)
    return entries


def _linux_find_suid(client: Any) -> list[str]:
    """Find SUID binaries that may be exploitable."""
    output = _linux_exec(client, "find / -perm -4000 -type f 2>/dev/null")
    # Filter out standard system SUID binaries
    standard_suid = {
        "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/mount",
        "/usr/bin/umount", "/usr/bin/ping", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/sbin/unix_chkpwd",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    }
    interesting: list[str] = []
    for line in output.splitlines():
        path = line.strip()
        if path and path not in standard_suid:
            interesting.append(path)
    return interesting


def _linux_check_writable_passwd(client: Any) -> bool:
    """Check if /etc/passwd is writable."""
    output = _linux_exec(client, "test -w /etc/passwd && echo WRITABLE")
    return "WRITABLE" in output


def _linux_check_kernel(client: Any) -> str:
    """Get kernel version for known exploit matching."""
    return _linux_exec(client, "uname -r").strip()


def _linux_check_writable_cron(client: Any) -> list[str]:
    """Find cron jobs pointing to writable scripts."""
    writable: list[str] = []
    # Check system crontab and cron directories
    cron_output = _linux_exec(
        client,
        "cat /etc/crontab 2>/dev/null; "
        "ls /etc/cron.d/ 2>/dev/null | xargs -I{} cat /etc/cron.d/{} 2>/dev/null; "
        "crontab -l 2>/dev/null"
    )
    for line in cron_output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Look for paths in cron entries
        parts = line.split()
        for part in parts:
            if part.startswith("/"):
                # Check if the script/path is writable
                check = _linux_exec(client, f"test -w '{part}' && echo WRITABLE")
                if "WRITABLE" in check:
                    writable.append(f"{part} (from cron: {line[:80]})")
                break
    return writable


def _linux_disconnect(client: Any) -> None:
    """Close SSH connection."""
    with contextlib.suppress(Exception):
        client.close()


# ── Module ───────────────────────────────────────────────────────────


class PrivescEnumModule(BaseModule):
    name = "post.privesc_enum"
    description = "Privilege escalation enumeration on compromised hosts"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1078", "T1068"]
    required_facts = ["credential.admin"]
    produced_facts = [
        "post.privesc_paths",
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
                await self._enumerate_windows(
                    ctx, findings, host_id, ip, cred,
                )

            if has_ssh and _ensure_paramiko():
                await self._enumerate_linux(
                    ctx, findings, host_id, ip, cred,
                )

        return findings

    async def _enumerate_windows(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        cred: Any,
    ) -> None:
        """Check Windows privesc vectors via SMB/RPC."""

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

        privesc_paths: list[dict[str, str]] = []

        # ── Unquoted service paths ───────────────────────────────────
        output = await asyncio.to_thread(
            _win_exec_cmd, ip, username, password, domain or "",
            'wmic service get name,pathname /format:csv',
            ntlm_hash,
        )
        unquoted = _win_check_unquoted_service_paths(output)
        if unquoted:
            path_lines = "\n".join(f"  - {p}" for p in unquoted)
            privesc_paths.append({"type": "unquoted_service_path", "count": str(len(unquoted))})
            findings.append(Finding(
                title=f"Unquoted service paths on {ip}",
                description=(
                    f"Found {len(unquoted)} service(s) with unquoted binary paths "
                    f"containing spaces on {ip}. An attacker with write access to "
                    "the path can place a malicious executable that will be run "
                    "with the service's privileges."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1574.009"],
                evidence=[Evidence(
                    kind="unquoted_service_path",
                    data=f"Unquoted service paths on {ip}:\n{path_lines}",
                )],
                remediation=(
                    "Quote the binary path in each affected service registration: "
                    "sc config <service> binPath= '\"C:\\Path With Spaces\\svc.exe\"'."
                ),
            ))

        # ── AlwaysInstallElevated ────────────────────────────────────
        for hive in ["HKLM", "HKCU"]:
            output = await asyncio.to_thread(
                _win_exec_cmd, ip, username, password, domain or "",
                f'reg query {hive}\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer '
                '/v AlwaysInstallElevated 2>nul',
                ntlm_hash,
            )
            if _win_check_always_install_elevated(output):
                privesc_paths.append({"type": "always_install_elevated", "hive": hive})
                findings.append(Finding(
                    title=f"AlwaysInstallElevated enabled ({hive}) on {ip}",
                    description=(
                        f"The AlwaysInstallElevated policy is enabled in {hive} "
                        f"on {ip}. Any user can install MSI packages with SYSTEM "
                        "privileges, allowing trivial privilege escalation."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1068"],
                    evidence=[Evidence(
                        kind="always_install_elevated",
                        data=f"AlwaysInstallElevated=1 in {hive} on {ip}",
                    )],
                    remediation=(
                        "Disable AlwaysInstallElevated in Group Policy: "
                        "Computer/User Configuration > Administrative Templates > "
                        "Windows Components > Windows Installer > "
                        "'Always install with elevated privileges' = Disabled."
                    ),
                ))
                break  # Only report once

        # ── Scheduled tasks running as SYSTEM ────────────────────────
        output = await asyncio.to_thread(
            _win_exec_cmd, ip, username, password, domain or "",
            'schtasks /query /fo csv /v 2>nul',
            ntlm_hash,
        )
        system_tasks: list[str] = []
        for line in output.splitlines():
            if "SYSTEM" in line.upper() and "Disabled" not in line:
                parts = line.split(",")
                if parts:
                    task_name = parts[0].strip('"')
                    if task_name and task_name != "TaskName":
                        system_tasks.append(task_name)
        if system_tasks:
            task_lines = "\n".join(f"  - {t}" for t in system_tasks[:20])
            suffix = f"\n  ... and {len(system_tasks) - 20} more" if len(system_tasks) > 20 else ""
            privesc_paths.append({"type": "system_scheduled_tasks", "count": str(len(system_tasks))})
            findings.append(Finding(
                title=f"Scheduled tasks running as SYSTEM on {ip}",
                description=(
                    f"Found {len(system_tasks)} scheduled task(s) running as SYSTEM "
                    f"on {ip}. If any task references a writable binary or script, "
                    "it can be hijacked for privilege escalation."
                ),
                severity=Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1053.005"],
                evidence=[Evidence(
                    kind="system_tasks",
                    data=f"SYSTEM scheduled tasks on {ip}:\n{task_lines}{suffix}",
                )],
                remediation=(
                    "Review scheduled tasks running as SYSTEM and ensure their "
                    "binaries are in protected paths with restrictive ACLs."
                ),
            ))

        # ── Token privileges ─────────────────────────────────────────
        output = await asyncio.to_thread(
            _win_exec_cmd, ip, username, password, domain or "",
            'whoami /priv',
            ntlm_hash,
        )
        dangerous_privs = _win_check_token_privileges(output)
        if dangerous_privs:
            priv_lines = "\n".join(f"  - {p}" for p in dangerous_privs)
            privesc_paths.append({"type": "dangerous_privileges", "privs": dangerous_privs})
            findings.append(Finding(
                title=f"Dangerous token privileges on {ip}",
                description=(
                    f"The authenticated user on {ip} holds {len(dangerous_privs)} "
                    "dangerous privilege(s) that can be exploited for privilege "
                    "escalation (e.g. potato attacks via SeImpersonate)."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1134.001"],
                evidence=[Evidence(
                    kind="token_privileges",
                    data=f"Dangerous privileges on {ip}:\n{priv_lines}",
                )],
                remediation=(
                    "Review and remove unnecessary privileges from service accounts. "
                    "SeImpersonate and SeDebug should only be granted to accounts "
                    "that require them."
                ),
            ))

        # Store all discovered privesc paths
        if privesc_paths:
            await ctx.facts.add(
                "post.privesc_paths",
                {"host": ip, "os": "windows", "paths": privesc_paths},
                self.name,
                host_id=host_id,
            )

    async def _enumerate_linux(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        cred: Any,
    ) -> None:
        """Check Linux privesc vectors via SSH."""

        username = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
        password = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))

        client = await asyncio.to_thread(_linux_connect, ip, username, password)
        if client is None:
            log.debug("privesc_enum: could not SSH to %s as %s", ip, username)
            return

        privesc_paths: list[dict[str, str]] = []

        try:
            # ── sudo -l ──────────────────────────────────────────────
            sudo_entries = await asyncio.to_thread(_linux_check_sudo, client)
            if sudo_entries:
                entry_lines = "\n".join(f"  - {e}" for e in sudo_entries)
                privesc_paths.append({"type": "sudo", "count": str(len(sudo_entries))})
                findings.append(Finding(
                    title=f"Sudo privileges for '{username}' on {ip}",
                    description=(
                        f"User '{username}' on {ip} can run {len(sudo_entries)} "
                        "command(s) via sudo. NOPASSWD entries and overly broad "
                        "sudo rules may allow privilege escalation."
                    ),
                    severity=Severity.HIGH if any("NOPASSWD" in e for e in sudo_entries) else Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1548.003"],
                    evidence=[Evidence(
                        kind="sudo_privs",
                        data=f"Sudo entries for {username} on {ip}:\n{entry_lines}",
                    )],
                    remediation=(
                        "Review and restrict sudo rules in /etc/sudoers. Remove "
                        "NOPASSWD entries where possible and avoid granting sudo "
                        "access to interpreters (python, bash, vi, etc.)."
                    ),
                ))

            # ── SUID binaries ────────────────────────────────────────
            suid_bins = await asyncio.to_thread(_linux_find_suid, client)
            if suid_bins:
                suid_lines = "\n".join(f"  - {s}" for s in suid_bins[:30])
                suffix = f"\n  ... and {len(suid_bins) - 30} more" if len(suid_bins) > 30 else ""
                privesc_paths.append({"type": "suid_binaries", "count": str(len(suid_bins))})
                findings.append(Finding(
                    title=f"Non-standard SUID binaries on {ip}",
                    description=(
                        f"Found {len(suid_bins)} non-standard SUID binary(ies) on {ip}. "
                        "SUID binaries run with the owner's privileges and may be "
                        "exploitable for privilege escalation (check GTFOBins)."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1548.001"],
                    evidence=[Evidence(
                        kind="suid_binaries",
                        data=f"Non-standard SUID binaries on {ip}:\n{suid_lines}{suffix}",
                    )],
                    remediation=(
                        "Remove the SUID bit from binaries that do not require it: "
                        "'chmod u-s <path>'. Audit SUID binaries regularly."
                    ),
                    references=[
                        "https://gtfobins.github.io/",
                    ],
                ))

            # ── Writable /etc/passwd ─────────────────────────────────
            writable_passwd = await asyncio.to_thread(
                _linux_check_writable_passwd, client,
            )
            if writable_passwd:
                privesc_paths.append({"type": "writable_passwd"})
                findings.append(Finding(
                    title=f"Writable /etc/passwd on {ip}",
                    description=(
                        f"/etc/passwd is writable by user '{username}' on {ip}. "
                        "An attacker can add a root-level account directly."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1068"],
                    evidence=[Evidence(
                        kind="writable_passwd",
                        data=f"/etc/passwd is writable on {ip}",
                    )],
                    remediation="Fix permissions: 'chmod 644 /etc/passwd' and 'chown root:root /etc/passwd'.",
                ))

            # ── Kernel version ───────────────────────────────────────
            kernel = await asyncio.to_thread(_linux_check_kernel, client)
            if kernel:
                # Flag very old kernels as potentially exploitable
                severity = Severity.INFO
                # Simple heuristic: kernels before 5.x are more likely to have unpatched CVEs
                try:
                    major = int(kernel.split(".")[0])
                    if major < 4:
                        severity = Severity.HIGH
                    elif major < 5:
                        severity = Severity.MEDIUM
                except ValueError:
                    pass

                privesc_paths.append({"type": "kernel_version", "version": kernel})
                findings.append(Finding(
                    title=f"Kernel version {kernel} on {ip}",
                    description=(
                        f"Host {ip} is running Linux kernel {kernel}. "
                        "Check for known kernel exploits matching this version "
                        "(e.g. DirtyPipe, DirtyCow, Overlayfs)."
                    ),
                    severity=severity,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1068"],
                    evidence=[Evidence(
                        kind="kernel_version",
                        data=f"Kernel: {kernel} on {ip}",
                    )],
                    remediation="Keep the kernel up to date with 'apt upgrade' or 'yum update'.",
                ))

            # ── Writable cron scripts ────────────────────────────────
            writable_cron = await asyncio.to_thread(
                _linux_check_writable_cron, client,
            )
            if writable_cron:
                cron_lines = "\n".join(f"  - {c}" for c in writable_cron)
                privesc_paths.append({"type": "writable_cron", "count": str(len(writable_cron))})
                findings.append(Finding(
                    title=f"Writable cron job scripts on {ip}",
                    description=(
                        f"Found {len(writable_cron)} cron job(s) on {ip} that "
                        "reference writable scripts. An attacker can modify these "
                        "scripts to execute arbitrary commands as the cron job owner "
                        "(often root)."
                    ),
                    severity=Severity.HIGH,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1053.003"],
                    evidence=[Evidence(
                        kind="writable_cron",
                        data=f"Writable cron scripts on {ip}:\n{cron_lines}",
                    )],
                    remediation=(
                        "Fix permissions on cron scripts so only root can write to them. "
                        "Audit /etc/crontab and /etc/cron.d/ regularly."
                    ),
                ))

            # Store all discovered privesc paths
            if privesc_paths:
                await ctx.facts.add(
                    "post.privesc_paths",
                    {"host": ip, "os": "linux", "paths": privesc_paths},
                    self.name,
                    host_id=host_id,
                )
        finally:
            await asyncio.to_thread(_linux_disconnect, client)
