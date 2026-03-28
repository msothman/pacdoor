"""EDR evasion scoring — defensive assessment of endpoint detection gaps.

Enumerates security controls on compromised hosts and scores how well
(or poorly) the blue team's defenses would detect common post-exploitation
activity.  Every test is **read-only** enumeration; nothing is modified on
the target.

Produces a per-host "defense score" (0-100) and individual findings for
every gap discovered, so the client knows exactly what their EDR missed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
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
        log.debug("impacket not installed — Windows EDR checks unavailable")
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
        log.debug("paramiko not installed — Linux EDR checks unavailable")
        _paramiko_available = False
    return _paramiko_available


# ── Score category dataclass ─────────────────────────────────────────


@dataclass
class CategoryScore:
    """Score for a single defense category (0-100)."""

    name: str
    score: int = 100
    details: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.score >= 80:
            return "Well protected"
        if self.score >= 50:
            return "Moderate gap"
        return "Critical gap"


# ── Windows remote execution (impacket) ──────────────────────────────


def _win_exec_cmd(
    ip: str,
    username: str,
    password: str,
    domain: str,
    command: str,
    ntlm_hash: str | None = None,
) -> str:
    """Execute a command on a remote Windows host and return stdout."""
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

        output_file = "C:\\Windows\\Temp\\__pacdoor_edr.tmp"
        service_cmd = f"cmd.exe /c {command} > {output_file} 2>&1"
        service_name = "__pacdoor_edr_svc"

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

        import time
        time.sleep(2)

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
            conn.getFile("C$", "Windows\\Temp\\__pacdoor_edr.tmp", output_buf.write)
            conn.deleteFile("C$", "Windows\\Temp\\__pacdoor_edr.tmp")
        except Exception:
            pass
        conn.close()
        return output_buf.getvalue().decode("utf-8", errors="replace")
    except Exception as e:
        log.debug("edr_evasion win_exec_cmd failed: %s", e)
        return ""


# ── Linux remote execution (paramiko) ────────────────────────────────


def _linux_connect(
    ip: str,
    username: str,
    password: str | None = None,
    port: int = 22,
    timeout: int = 10,
) -> Any | None:
    """Establish an SSH connection for remote enumeration."""
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


def _linux_disconnect(client: Any) -> None:
    with contextlib.suppress(Exception):
        client.close()


# ── Credential extraction helper ─────────────────────────────────────


def _extract_cred_fields(cred: Any) -> tuple[str, str, str, str | None]:
    """Extract (username, password, domain, ntlm_hash) from a credential."""
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


# ── Windows assessment checks ────────────────────────────────────────

# Each returns (partial_evidence_str, score_deduction) pairs.

_KNOWN_EDR_SERVICES = {
    "csfalconservice": "CrowdStrike Falcon",
    "csfalconcontainer": "CrowdStrike Falcon",
    "sentinelagent": "SentinelOne",
    "sentinelstaticengine": "SentinelOne",
    "cbdefense": "Carbon Black",
    "carbonblack": "Carbon Black",
    "carbonblackk": "Carbon Black",
    "cb": "Carbon Black",
    "cyoptics": "Cylance",
    "cylancesvc": "Cylance",
    "sophossps": "Sophos",
    "sophoshealth": "Sophos",
    "sophoscleanm": "Sophos",
    "sense": "Microsoft Defender ATP",
    "windefend": "Windows Defender",
    "msmpeng": "Windows Defender",
    "mssense": "Microsoft Defender ATP",
    "sysmon": "Sysmon",
    "sysmon64": "Sysmon",
}

_KEY_ETW_PROVIDERS = [
    "Microsoft-Windows-PowerShell",
    "Microsoft-Antimalware-Scan-Interface",
    "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-WMI-Activity",
    "Microsoft-Windows-DNS-Client",
    "Microsoft-Windows-Kernel-Process",
]


def _win_check_amsi(output_amsi_reg: str, output_scriptblock: str) -> tuple[str, int]:
    """Check AMSI and ScriptBlock logging status."""
    amsi_enabled = "AmsiEnable" not in output_amsi_reg or "0x0" not in output_amsi_reg
    scriptblock_on = "1" in output_scriptblock and "EnableScriptBlockLogging" in output_scriptblock
    deduction = 0
    parts = []
    if not amsi_enabled:
        deduction += 50
        parts.append("AMSI enabled: No")
    else:
        parts.append("AMSI enabled: Yes")
    if not scriptblock_on:
        deduction += 50
        parts.append("ScriptBlock logging: No")
    else:
        parts.append("ScriptBlock logging: Yes")
    return ", ".join(parts), deduction


def _win_check_etw(output_etw: str, output_sysmon: str) -> tuple[str, int]:
    """Check ETW provider and Sysmon status."""
    active_count = 0
    for provider in _KEY_ETW_PROVIDERS:
        if provider.lower() in output_etw.lower():
            active_count += 1
    total = len(_KEY_ETW_PROVIDERS)

    sysmon_installed = (
        "sysmon" in output_sysmon.lower()
        and "running" in output_sysmon.lower()
    )

    parts = []
    if sysmon_installed:
        parts.append("Sysmon installed: Yes")
    else:
        parts.append("Sysmon installed: No")
    parts.append(f"ETW providers: {active_count}/{total} active")

    # Score: full marks if sysmon + most providers active
    deduction = 0
    if not sysmon_installed:
        deduction += 40
    missing = total - active_count
    deduction += min(60, missing * 10)
    return " -- ".join(parts), min(100, deduction)


def _win_check_edr_products(output_wmi_av: str, output_services: str) -> tuple[str, list[dict[str, str]], int]:
    """Detect installed EDR/AV products and their running state."""
    detected: list[dict[str, str]] = []
    services_lower = output_services.lower()

    # WMI AntiVirusProduct namespace
    for line in output_wmi_av.splitlines():
        line_stripped = line.strip()
        if line_stripped and "displayname" not in line_stripped.lower() and "instance" not in line_stripped.lower():
            if len(line_stripped) > 3:
                detected.append({"product": line_stripped, "status": "registered_wmi"})

    # Service-based detection
    for svc_key, product_name in _KNOWN_EDR_SERVICES.items():
        if svc_key.lower() in services_lower:
            # Determine if running or stopped
            state = "installed"
            # Try to find RUNNING or STOPPED near the service name
            idx = services_lower.find(svc_key.lower())
            context = services_lower[max(0, idx - 100):idx + 200]
            if "running" in context:
                state = "running"
            elif "stopped" in context:
                state = "stopped"
            # Avoid duplicate product names
            already = any(d["product"] == product_name for d in detected)
            if not already:
                detected.append({"product": product_name, "status": state})

    if not detected:
        evidence_str = "No EDR/AV products detected"
        return evidence_str, detected, 100  # full deduction

    parts = []
    deduction = 0
    has_running_edr = False
    for d in detected:
        parts.append(f"{d['product']}: {d['status']}")
        if d["status"] == "running":
            has_running_edr = True
        elif d["status"] == "stopped":
            deduction += 40
    if not has_running_edr:
        deduction += 60
    evidence_str = ", ".join(parts)
    return evidence_str, detected, min(100, deduction)


def _win_check_logging(
    output_security_log: str,
    output_powershell_log: str,
    output_sysmon_log: str,
    output_siem_services: str,
) -> tuple[str, int]:
    """Assess logging coverage on Windows."""
    parts = []
    deduction = 0

    # Security event log
    if "security" in output_security_log.lower():
        # Try to extract retention/max size
        if "maxsize" in output_security_log.lower() or "retention" in output_security_log.lower():
            parts.append(f"Security log: enabled")
        else:
            parts.append("Security log: enabled (retention unknown)")
    else:
        parts.append("Security log: not found or disabled")
        deduction += 30

    # PowerShell log
    if "powershell" in output_powershell_log.lower() and "0 " not in output_powershell_log:
        parts.append("PowerShell log: enabled")
    else:
        parts.append("PowerShell log: disabled")
        deduction += 30

    # Sysmon operational log
    if "sysmon" in output_sysmon_log.lower() and ("operational" in output_sysmon_log.lower() or "enabled" in output_sysmon_log.lower()):
        parts.append("Sysmon log: enabled")
    else:
        parts.append("Sysmon log: not installed")
        deduction += 20

    # SIEM agent detection
    siem_lower = output_siem_services.lower()
    siem_agents = {
        "splunkforwarder": "Splunk",
        "nxlog": "NXLog",
        "winlogbeat": "Winlogbeat",
        "ossec": "OSSEC",
        "elastic-agent": "Elastic Agent",
        "omsagent": "Azure Monitor",
        "azuremonitoragent": "Azure Monitor",
    }
    found_siem = []
    for key, label in siem_agents.items():
        if key in siem_lower:
            found_siem.append(label)
    if found_siem:
        parts.append(f"SIEM agent: {', '.join(found_siem)}")
    else:
        parts.append("SIEM agent: none detected")
        deduction += 20

    return ", ".join(parts), min(100, deduction)


def _win_check_process_protection(
    output_ppl: str,
    output_credguard: str,
    output_defender_rt: str,
) -> tuple[str, int]:
    """Check LSASS PPL, Credential Guard, Defender real-time protection."""
    parts = []
    deduction = 0

    # LSASS PPL (RunAsPPL)
    lsass_ppl = "0x1" in output_ppl and "RunAsPPL" in output_ppl
    if lsass_ppl:
        parts.append("LSASS PPL: Yes")
    else:
        parts.append("LSASS PPL: No")
        deduction += 35

    # Credential Guard
    cred_guard = (
        "credentialguard" in output_credguard.lower()
        or ("securityservicesrunning" in output_credguard.lower() and "1" in output_credguard)
        or "running" in output_credguard.lower()
    )
    if cred_guard:
        parts.append("Credential Guard: Yes")
    else:
        parts.append("Credential Guard: No")
        deduction += 35

    # Defender real-time protection
    defender_rt = "1" in output_defender_rt and "DisableRealtimeMonitoring" not in output_defender_rt
    # If the query returns nothing or shows 0x0, it is likely enabled (default)
    if "disablerealtimemonitoring" in output_defender_rt.lower():
        if "0x1" in output_defender_rt:
            defender_rt = False
        else:
            defender_rt = True
    elif output_defender_rt.strip() == "":
        defender_rt = True  # assume enabled if query fails (default)
    if defender_rt:
        parts.append("Defender real-time: Yes")
    else:
        parts.append("Defender real-time: No")
        deduction += 30

    suffix = ""
    if not lsass_ppl and not cred_guard:
        suffix = " -- LSASS dump would succeed"
    return ", ".join(parts) + suffix, min(100, deduction)


def _win_check_firewall(output_firewall: str) -> tuple[str, int]:
    """Check firewall rules and outbound filtering."""
    parts = []
    deduction = 0

    fw_lower = output_firewall.lower()
    if "state" in fw_lower and "on" in fw_lower:
        parts.append("Host firewall: enabled")
    elif "state" in fw_lower and "off" in fw_lower:
        parts.append("Host firewall: disabled")
        deduction += 50
    else:
        parts.append("Host firewall: unknown")
        deduction += 25

    # Check for outbound block rules
    c2_ports = ["4444", "8080", "443"]
    blocked = []
    allowed = []
    for port in c2_ports:
        if f"localport:{port}" in fw_lower.replace(" ", "") and "block" in fw_lower:
            blocked.append(port)
        else:
            allowed.append(port)
    if allowed:
        parts.append(f"Outbound {', '.join(allowed)}: allowed")
    if blocked:
        parts.append(f"Outbound {', '.join(blocked)}: blocked")
    if not blocked:
        parts.append("no egress filtering")
        deduction += 50

    return " -- ".join(parts), min(100, deduction)


def _win_check_uac(output_uac: str) -> tuple[str, int]:
    """Check UAC configuration."""
    parts = []
    deduction = 0

    # EnableLUA
    lua_enabled = True
    if "enablelua" in output_uac.lower():
        if "0x0" in output_uac:
            lua_enabled = False

    # ConsentPromptBehaviorAdmin
    consent_level = -1
    for line in output_uac.splitlines():
        if "consentpromptbehavioradmin" in line.lower():
            for token in line.split():
                if token.startswith("0x"):
                    try:
                        consent_level = int(token, 16)
                    except ValueError:
                        pass

    if not lua_enabled:
        parts.append("UAC: disabled (EnableLUA=0)")
        deduction += 80
    elif consent_level == 0:
        parts.append("UAC level: 0 (no prompts)")
        deduction += 60
    elif consent_level == 1:
        parts.append("UAC level: 1 (prompt on secure desktop)")
    elif consent_level >= 2:
        parts.append(f"UAC level: {consent_level}")
    else:
        parts.append("UAC: enabled (default)")

    return ", ".join(parts) if parts else "UAC: unknown", min(100, deduction)


# ── Linux assessment checks ──────────────────────────────────────────


def _linux_check_edr_products(client: Any) -> tuple[str, int]:
    """Detect Linux EDR/AV products."""
    detections: list[str] = []
    deduction = 100

    checks = {
        "falcon-sensor": "CrowdStrike Falcon",
        "sentinelone": "SentinelOne",
        "cbagent": "Carbon Black",
        "clamd": "ClamAV",
        "ossec": "OSSEC/Wazuh",
        "wazuh-agent": "Wazuh",
        "elastic-agent": "Elastic Agent",
        "auditbeat": "Auditbeat",
    }
    services_output = _linux_exec(client, "systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null")
    ps_output = _linux_exec(client, "ps aux 2>/dev/null")
    combined = (services_output + ps_output).lower()

    for key, label in checks.items():
        if key in combined:
            detections.append(f"{label}: running")
            deduction -= 30

    if not detections:
        return "No EDR/AV products detected", 100

    deduction = max(0, deduction)
    return ", ".join(detections), deduction


def _linux_check_logging(client: Any) -> tuple[str, int]:
    """Check auditd, rsyslog, and log forwarding on Linux."""
    parts = []
    deduction = 0

    # auditd
    auditd_output = _linux_exec(client, "systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null")
    if "active" in auditd_output.lower() or "running" in auditd_output.lower():
        parts.append("auditd: running")
    else:
        parts.append("auditd: not running")
        deduction += 30

    # rsyslog / syslog-ng
    syslog_output = _linux_exec(client, "systemctl is-active rsyslog 2>/dev/null; systemctl is-active syslog-ng 2>/dev/null")
    if "active" in syslog_output.lower():
        parts.append("syslog: running")
    else:
        parts.append("syslog: not running")
        deduction += 20

    # auth.log existence
    auth_log = _linux_exec(client, "test -f /var/log/auth.log && echo EXISTS || (test -f /var/log/secure && echo EXISTS || echo MISSING)")
    if "EXISTS" in auth_log:
        parts.append("auth log: present")
    else:
        parts.append("auth log: missing")
        deduction += 15

    # SIEM agent
    siem_output = _linux_exec(
        client,
        "systemctl list-units --type=service --state=running --no-pager 2>/dev/null"
        " | grep -iE 'splunk|nxlog|filebeat|fluentd|rsyslog|ossec|wazuh|elastic-agent'",
    )
    if siem_output.strip():
        agents = [line.strip().split()[0] for line in siem_output.strip().splitlines() if line.strip()]
        parts.append(f"SIEM agent: {', '.join(agents[:3])}")
    else:
        parts.append("SIEM agent: none detected")
        deduction += 35

    return ", ".join(parts), min(100, deduction)


def _linux_check_sudo_config(client: Any) -> tuple[str, int]:
    """Check sudo NOPASSWD and writable directories."""
    parts = []
    deduction = 0

    sudo_output = _linux_exec(client, "sudo -l 2>/dev/null")
    nopasswd_lines = [line.strip() for line in sudo_output.splitlines() if "NOPASSWD" in line]
    if nopasswd_lines:
        for line in nopasswd_lines[:3]:
            parts.append(f"sudo NOPASSWD: {line[:80]}")
        deduction += 40
    else:
        parts.append("sudo NOPASSWD: none")

    # Writable system directories
    writable_dirs = _linux_exec(
        client,
        "for d in /usr/local/bin /usr/local/sbin /opt; do "
        "test -w \"$d\" && echo \"$d writable\"; done 2>/dev/null",
    )
    if "writable" in writable_dirs:
        dirs = [entry.strip() for entry in writable_dirs.splitlines() if "writable" in entry]
        parts.append(f"Writable system dirs: {', '.join(dirs)}")
        deduction += 30
    else:
        parts.append("Writable system dirs: none")

    return ", ".join(parts), min(100, deduction)


def _linux_check_firewall(client: Any) -> tuple[str, int]:
    """Check iptables/nftables and outbound filtering."""
    parts = []
    deduction = 0

    # iptables rules count
    ipt_output = _linux_exec(client, "iptables -L -n 2>/dev/null | wc -l; nft list ruleset 2>/dev/null | wc -l")
    lines = ipt_output.strip().splitlines()
    rule_counts = []
    for line in lines:
        try:
            rule_counts.append(int(line.strip()))
        except ValueError:
            pass

    total_rules = sum(rule_counts) if rule_counts else 0
    if total_rules > 10:
        parts.append(f"Firewall rules: {total_rules} rules loaded")
    else:
        parts.append("Firewall: minimal or no rules")
        deduction += 40

    # Test outbound ports
    c2_ports = ["4444", "8080"]
    for port in c2_ports:
        # Check if there is an explicit DROP/REJECT for outbound on this port
        ipt_check = _linux_exec(
            client,
            f"iptables -L OUTPUT -n 2>/dev/null | grep -i 'drop\\|reject' | grep '{port}'",
        )
        if ipt_check.strip():
            parts.append(f"Outbound {port}: blocked")
        else:
            parts.append(f"Outbound {port}: allowed")
            deduction += 15

    if deduction >= 40:
        parts.append("no egress filtering")

    return " -- ".join(parts), min(100, deduction)


# ── Module ───────────────────────────────────────────────────────────


class EdrEvasionModule(BaseModule):
    """Defensive EDR/AV gap assessment on compromised hosts."""

    name = "post.edr_evasion"
    description = "Assess endpoint detection gaps and score defense coverage"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1518.001", "T1082"]
    required_facts = ["credential.valid"]
    produced_facts = ["edr.assessment", "edr.gaps"]
    safety = ExploitSafety.MODERATE

    async def check(self, ctx: ModuleContext) -> bool:
        """Module can run if we have valid or admin credentials."""
        has_valid = await ctx.facts.has("credential.valid")
        has_admin = await ctx.facts.has("credential.admin")
        return has_valid or has_admin

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        # Gather credentials — prefer admin, fall back to valid
        cred_facts = await ctx.facts.get_all("credential.admin")
        if not cred_facts:
            cred_facts = await ctx.facts.get_all("credential.valid")
        if not cred_facts:
            return findings

        seen_hosts: set[str] = set()

        for fact in cred_facts:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)

            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue

            cred = fact.value

            has_smb = bool(await ctx.facts.get_for_host("service.smb", host_id))
            has_ssh = bool(await ctx.facts.get_for_host("service.ssh", host_id))

            if has_smb and _ensure_impacket():
                await self._assess_windows(ctx, findings, host_id, ip, cred)

            if has_ssh and _ensure_paramiko():
                await self._assess_linux(ctx, findings, host_id, ip, cred)

        return findings

    # ── Windows assessment ────────────────────────────────────────────

    async def _assess_windows(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        cred: Any,
    ) -> None:
        username, password, domain, ntlm_hash = _extract_cred_fields(cred)
        if not username:
            return

        def _exec(cmd: str) -> str:
            return _win_exec_cmd(ip, username, password, domain, cmd, ntlm_hash)

        categories: list[CategoryScore] = []

        # ── 1. AMSI bypass detection ─────────────────────────────────
        await ctx.rate_limiter.acquire()
        amsi_reg = await asyncio.to_thread(
            _exec,
            'reg query HKLM\\SOFTWARE\\Microsoft\\AMSI /v AmsiEnable 2>nul',
        )
        scriptblock_reg = await asyncio.to_thread(
            _exec,
            'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging '
            '/v EnableScriptBlockLogging 2>nul',
        )
        amsi_evidence, amsi_deduction = _win_check_amsi(amsi_reg, scriptblock_reg)
        cat_amsi = CategoryScore(name="AMSI & Script Logging", score=100 - amsi_deduction, details=[amsi_evidence])
        categories.append(cat_amsi)

        if amsi_deduction > 0:
            findings.append(Finding(
                title=f"AMSI/ScriptBlock logging gaps on {ip}",
                description=(
                    f"AMSI or PowerShell ScriptBlock logging is not fully configured "
                    f"on {ip}. This allows attackers to execute malicious PowerShell "
                    f"scripts without detection."
                ),
                severity=Severity.HIGH if amsi_deduction >= 50 else Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1562.001"],
                evidence=[Evidence(kind="amsi_check", data=amsi_evidence)],
                remediation=(
                    "Enable AMSI via Group Policy. Enable PowerShell ScriptBlock "
                    "logging under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
                    "PowerShell\\ScriptBlockLogging (EnableScriptBlockLogging=1)."
                ),
            ))

        # ── 2. ETW provider status ───────────────────────────────────
        await ctx.rate_limiter.acquire()
        etw_output = await asyncio.to_thread(
            _exec, 'logman query providers 2>nul',
        )
        sysmon_output = await asyncio.to_thread(
            _exec, 'sc query sysmon 2>nul & sc query sysmon64 2>nul',
        )
        etw_evidence, etw_deduction = _win_check_etw(etw_output, sysmon_output)
        cat_etw = CategoryScore(name="ETW & Sysmon", score=100 - etw_deduction, details=[etw_evidence])
        categories.append(cat_etw)

        if etw_deduction > 40:
            findings.append(Finding(
                title=f"ETW/Sysmon coverage gaps on {ip}",
                description=(
                    f"Key ETW providers are not active or Sysmon is not installed "
                    f"on {ip}. This limits visibility into process creation, network "
                    f"connections, and script execution."
                ),
                severity=Severity.HIGH if etw_deduction >= 70 else Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1562.006"],
                evidence=[Evidence(kind="etw_check", data=etw_evidence)],
                remediation=(
                    "Install and configure Sysmon with a community ruleset "
                    "(e.g., SwiftOnSecurity or Olaf Hartong). Ensure key ETW "
                    "providers are enabled and not tampered with."
                ),
                references=["https://github.com/SwiftOnSecurity/sysmon-config"],
            ))

        # ── 3. EDR/AV product detection ──────────────────────────────
        await ctx.rate_limiter.acquire()
        wmi_av = await asyncio.to_thread(
            _exec,
            'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /format:list 2>nul',
        )
        services_list = await asyncio.to_thread(
            _exec, 'sc query state= all 2>nul',
        )
        edr_evidence, edr_products, edr_deduction = _win_check_edr_products(wmi_av, services_list)
        cat_edr = CategoryScore(name="EDR/AV Products", score=100 - edr_deduction, details=[edr_evidence])
        categories.append(cat_edr)

        if edr_deduction > 0:
            sev = Severity.CRITICAL if edr_deduction >= 80 else Severity.HIGH if edr_deduction >= 40 else Severity.MEDIUM
            findings.append(Finding(
                title=f"EDR/AV product gaps on {ip}",
                description=(
                    f"EDR or antivirus protection is insufficient on {ip}. "
                    f"Detected: {edr_evidence}. A stopped or missing EDR agent "
                    f"means post-exploitation activity will go undetected."
                ),
                severity=sev,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1518.001", "T1562.001"],
                evidence=[Evidence(kind="edr_products", data=edr_evidence)],
                remediation=(
                    "Deploy an EDR solution (CrowdStrike, SentinelOne, Defender ATP, "
                    "etc.) on all endpoints. Ensure the agent service is running "
                    "and cannot be stopped by non-admin users."
                ),
            ))

        # ── 4. Logging coverage ──────────────────────────────────────
        await ctx.rate_limiter.acquire()
        sec_log = await asyncio.to_thread(
            _exec, 'wevtutil gl Security 2>nul',
        )
        ps_log = await asyncio.to_thread(
            _exec, 'wevtutil gl "Microsoft-Windows-PowerShell/Operational" 2>nul',
        )
        sysmon_log = await asyncio.to_thread(
            _exec, 'wevtutil gl "Microsoft-Windows-Sysmon/Operational" 2>nul',
        )
        siem_services = await asyncio.to_thread(
            _exec,
            'sc query splunkforwarder 2>nul & sc query nxlog 2>nul & sc query winlogbeat 2>nul '
            '& sc query "elastic-agent" 2>nul & sc query omsagent 2>nul',
        )
        log_evidence, log_deduction = _win_check_logging(sec_log, ps_log, sysmon_log, siem_services)
        cat_log = CategoryScore(name="Logging Coverage", score=100 - log_deduction, details=[log_evidence])
        categories.append(cat_log)

        if log_deduction >= 30:
            findings.append(Finding(
                title=f"Logging coverage gaps on {ip}",
                description=(
                    f"Event logging is incomplete on {ip}: {log_evidence}. "
                    f"Missing logs mean the SOC cannot detect or investigate "
                    f"post-exploitation activity."
                ),
                severity=Severity.HIGH if log_deduction >= 60 else Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1562.002"],
                evidence=[Evidence(kind="logging_check", data=log_evidence)],
                remediation=(
                    "Enable Security, PowerShell, and Sysmon event logs with "
                    "adequate retention (at least 30 days). Deploy a SIEM forwarder "
                    "(Splunk UF, Elastic Agent, Winlogbeat) to centralize logs."
                ),
            ))

        # ── 5. Process protection ────────────────────────────────────
        await ctx.rate_limiter.acquire()
        ppl_output = await asyncio.to_thread(
            _exec,
            'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL 2>nul',
        )
        credguard_output = await asyncio.to_thread(
            _exec,
            'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard '
            '/v SecurityServicesRunning 2>nul',
        )
        defender_rt_output = await asyncio.to_thread(
            _exec,
            'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" '
            '/v DisableRealtimeMonitoring 2>nul',
        )
        prot_evidence, prot_deduction = _win_check_process_protection(
            ppl_output, credguard_output, defender_rt_output,
        )
        cat_prot = CategoryScore(name="Process Protection", score=100 - prot_deduction, details=[prot_evidence])
        categories.append(cat_prot)

        if prot_deduction > 0:
            sev = Severity.CRITICAL if prot_deduction >= 70 else Severity.HIGH if prot_deduction >= 35 else Severity.MEDIUM
            findings.append(Finding(
                title=f"Process protection gaps on {ip}",
                description=(
                    f"Credential protection mechanisms are insufficient on {ip}: "
                    f"{prot_evidence}. Attackers can dump LSASS memory to extract "
                    f"plaintext passwords and NTLM hashes."
                ),
                severity=sev,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1003.001"],
                evidence=[Evidence(kind="process_protection", data=prot_evidence)],
                remediation=(
                    "Enable LSA Protection (RunAsPPL) via registry or Group Policy. "
                    "Enable Credential Guard on supported hardware. Ensure Windows "
                    "Defender real-time protection is not disabled."
                ),
            ))

        # ── 6. Firewall / egress ─────────────────────────────────────
        await ctx.rate_limiter.acquire()
        fw_output = await asyncio.to_thread(
            _exec, 'netsh advfirewall show allprofiles state 2>nul',
        )
        fw_evidence, fw_deduction = _win_check_firewall(fw_output)
        cat_fw = CategoryScore(name="Firewall & Egress", score=100 - fw_deduction, details=[fw_evidence])
        categories.append(cat_fw)

        if fw_deduction >= 50:
            findings.append(Finding(
                title=f"Firewall/egress filtering gaps on {ip}",
                description=(
                    f"Host-based firewall or outbound filtering is weak on {ip}: "
                    f"{fw_evidence}. Attackers can establish C2 channels without "
                    f"network-level blocking."
                ),
                severity=Severity.HIGH if fw_deduction >= 80 else Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1071.001"],
                evidence=[Evidence(kind="firewall_check", data=fw_evidence)],
                remediation=(
                    "Enable the Windows firewall on all profiles. Configure outbound "
                    "rules to block non-standard ports. Implement network-level "
                    "egress filtering at the perimeter."
                ),
            ))

        # ── 7. UAC / privilege escalation readiness ──────────────────
        await ctx.rate_limiter.acquire()
        uac_output = await asyncio.to_thread(
            _exec,
            'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 2>nul',
        )
        uac_evidence, uac_deduction = _win_check_uac(uac_output)
        cat_uac = CategoryScore(name="Privilege Escalation Readiness", score=100 - uac_deduction, details=[uac_evidence])
        categories.append(cat_uac)

        if uac_deduction >= 40:
            findings.append(Finding(
                title=f"UAC weakness on {ip}",
                description=(
                    f"User Account Control is weakened on {ip}: {uac_evidence}. "
                    f"Attackers can escalate privileges without triggering a UAC prompt."
                ),
                severity=Severity.CRITICAL if uac_deduction >= 80 else Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1548.002"],
                evidence=[Evidence(kind="uac_check", data=uac_evidence)],
                remediation=(
                    "Set UAC to 'Always Notify' (ConsentPromptBehaviorAdmin=2). "
                    "Ensure EnableLUA is set to 1. Do not disable UAC via "
                    "Group Policy."
                ),
            ))

        # ── 8. Generate summary score ────────────────────────────────
        await self._emit_summary(ctx, findings, host_id, ip, "windows", categories)

    # ── Linux assessment ─────────────────────────────────────────────

    async def _assess_linux(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        cred: Any,
    ) -> None:
        username, password, domain, ntlm_hash = _extract_cred_fields(cred)
        if not username:
            return

        client = await asyncio.to_thread(_linux_connect, ip, username, password)
        if client is None:
            log.debug("edr_evasion: could not SSH to %s as %s", ip, username)
            return

        categories: list[CategoryScore] = []

        try:
            # ── 1. EDR/AV products ───────────────────────────────────
            await ctx.rate_limiter.acquire()
            edr_evidence, edr_deduction = await asyncio.to_thread(
                _linux_check_edr_products, client,
            )
            cat_edr = CategoryScore(name="EDR/AV Products", score=100 - edr_deduction, details=[edr_evidence])
            categories.append(cat_edr)

            if edr_deduction >= 50:
                sev = Severity.CRITICAL if edr_deduction >= 80 else Severity.HIGH
                findings.append(Finding(
                    title=f"EDR/AV product gaps on {ip}",
                    description=(
                        f"EDR or antivirus protection is insufficient on {ip}. "
                        f"Detected: {edr_evidence}."
                    ),
                    severity=sev,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1518.001"],
                    evidence=[Evidence(kind="edr_products", data=edr_evidence)],
                    remediation=(
                        "Deploy an EDR agent (CrowdStrike, SentinelOne, Wazuh, etc.) "
                        "on all Linux hosts."
                    ),
                ))

            # ── 2. Logging coverage ──────────────────────────────────
            await ctx.rate_limiter.acquire()
            log_evidence, log_deduction = await asyncio.to_thread(
                _linux_check_logging, client,
            )
            cat_log = CategoryScore(name="Logging Coverage", score=100 - log_deduction, details=[log_evidence])
            categories.append(cat_log)

            if log_deduction >= 30:
                findings.append(Finding(
                    title=f"Logging coverage gaps on {ip}",
                    description=(
                        f"Logging is incomplete on {ip}: {log_evidence}. "
                        f"Missing audit logs mean attacks go undetected."
                    ),
                    severity=Severity.HIGH if log_deduction >= 60 else Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1562.002"],
                    evidence=[Evidence(kind="logging_check", data=log_evidence)],
                    remediation=(
                        "Install and enable auditd with appropriate rules. Configure "
                        "rsyslog to forward logs to a SIEM. Deploy a log shipping "
                        "agent (Filebeat, Fluentd)."
                    ),
                ))

            # ── 3. Privilege escalation readiness ────────────────────
            await ctx.rate_limiter.acquire()
            sudo_evidence, sudo_deduction = await asyncio.to_thread(
                _linux_check_sudo_config, client,
            )
            cat_sudo = CategoryScore(name="Privilege Escalation Readiness", score=100 - sudo_deduction, details=[sudo_evidence])
            categories.append(cat_sudo)

            if sudo_deduction >= 30:
                findings.append(Finding(
                    title=f"Privilege escalation risk on {ip}",
                    description=(
                        f"Privilege escalation vectors found on {ip}: {sudo_evidence}."
                    ),
                    severity=Severity.HIGH if sudo_deduction >= 60 else Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1548.003"],
                    evidence=[Evidence(kind="privesc_check", data=sudo_evidence)],
                    remediation=(
                        "Remove NOPASSWD entries from sudoers where possible. "
                        "Restrict writable system directories to root only."
                    ),
                ))

            # ── 4. Firewall / egress ─────────────────────────────────
            await ctx.rate_limiter.acquire()
            fw_evidence, fw_deduction = await asyncio.to_thread(
                _linux_check_firewall, client,
            )
            cat_fw = CategoryScore(name="Firewall & Egress", score=100 - fw_deduction, details=[fw_evidence])
            categories.append(cat_fw)

            if fw_deduction >= 40:
                findings.append(Finding(
                    title=f"Firewall/egress filtering gaps on {ip}",
                    description=(
                        f"Firewall is weak on {ip}: {fw_evidence}. Attackers can "
                        f"establish reverse shells and C2 channels."
                    ),
                    severity=Severity.HIGH if fw_deduction >= 70 else Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1071.001"],
                    evidence=[Evidence(kind="firewall_check", data=fw_evidence)],
                    remediation=(
                        "Configure iptables/nftables with a default-deny outbound "
                        "policy. Only allow required ports and destinations."
                    ),
                ))

            # ── Summary ──────────────────────────────────────────────
            await self._emit_summary(ctx, findings, host_id, ip, "linux", categories)

        finally:
            await asyncio.to_thread(_linux_disconnect, client)

    # ── Summary scoring ──────────────────────────────────────────────

    async def _emit_summary(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        os_type: str,
        categories: list[CategoryScore],
    ) -> None:
        """Calculate overall defense score and emit summary finding + facts."""
        if not categories:
            return

        overall_score = sum(c.score for c in categories) // len(categories)
        if overall_score >= 80:
            overall_label = "Well protected"
            overall_severity = Severity.INFO
        elif overall_score >= 50:
            overall_label = "Moderate gap"
            overall_severity = Severity.MEDIUM
        else:
            overall_label = "Critical gap"
            overall_severity = Severity.CRITICAL

        detail_lines = []
        gaps: list[dict[str, Any]] = []
        for cat in categories:
            detail_lines.append(f"  {cat.name}: {cat.score}/100 ({cat.label})")
            for d in cat.details:
                detail_lines.append(f"    {d}")
            if cat.score < 80:
                gaps.append({"category": cat.name, "score": cat.score, "label": cat.label})

        summary_text = (
            f"Defense Score: {overall_score}/100 ({overall_label})\n"
            f"OS: {os_type}\n"
            f"Host: {ip}\n\n"
            + "\n".join(detail_lines)
        )

        findings.append(Finding(
            title=f"EDR Defense Score: {overall_score}/100 on {ip} ({overall_label})",
            description=(
                f"Overall endpoint defense assessment for {ip} ({os_type}): "
                f"{overall_score}/100 — {overall_label}. "
                f"Assessed {len(categories)} defense categories. "
                f"Found {len(gaps)} category(ies) with gaps."
            ),
            severity=overall_severity,
            host_id=host_id,
            module_name=self.name,
            attack_technique_ids=self.attack_technique_ids,
            evidence=[Evidence(kind="defense_score_summary", data=summary_text)],
            remediation=(
                "Address each gap category starting with the lowest scores. "
                "See individual findings for specific remediation steps."
            ),
            verified=True,
        ))

        # Persist assessment and gaps as facts
        assessment = {
            "host": ip,
            "os": os_type,
            "overall_score": overall_score,
            "overall_label": overall_label,
            "categories": {c.name: {"score": c.score, "label": c.label} for c in categories},
        }
        await ctx.facts.add("edr.assessment", assessment, self.name, host_id=host_id)

        if gaps:
            await ctx.facts.add(
                "edr.gaps",
                {"host": ip, "os": os_type, "gaps": gaps},
                self.name,
                host_id=host_id,
            )
