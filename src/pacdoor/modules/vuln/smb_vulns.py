"""SMB vulnerability detection — MS17-010, PrintNightmare, PetitPotam, ZeroLogon.

The most important vulnerability module for internal penetration tests.
All checks use impacket wrapped in ``asyncio.to_thread`` for non-blocking
execution.  Import failures are handled gracefully so the module can be
loaded (and skipped) when impacket is absent.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
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


# ── Lazy impacket imports ────────────────────────────────────────────

_impacket_available: bool | None = None


def _ensure_impacket() -> bool:
    """Try to import core impacket modules; cache result."""
    global _impacket_available  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        import impacket.smbconnection  # noqa: F401
        _impacket_available = True
    except ImportError:
        log.debug("impacket not installed — smb_vulns module will be skipped")
        _impacket_available = False
    return _impacket_available


# ── MS17-010 (EternalBlue) ───────────────────────────────────────────

# SMBv1 negotiation + TRANS2 SESSION_SETUP probe.
# A vulnerable system responds with STATUS_INSUFF_SERVER_RESOURCES (0xC0000205).


def _check_ms17_010(ip: str, port: int = 445, timeout: int = 10) -> bool:
    """Detect MS17-010 (EternalBlue) via SMBv1 TRANS2 SESSION_SETUP.

    Returns True if the target is likely vulnerable.
    """
    import socket

    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return False

    try:
        # SMBv1 negotiate request
        negotiate = bytearray(
            b"\x00\x00\x00\x85"  # NetBIOS session
            b"\xff\x53\x4d\x42"  # SMB header magic
            b"\x72"              # SMB_COM_NEGOTIATE
            b"\x00\x00\x00\x00" # Status
            b"\x18"              # Flags
            b"\x53\xc8"         # Flags2
            b"\x00\x00"         # PID high
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
            b"\x00\x00"         # Reserved
            b"\x00\x00"         # TID
            b"\xff\xfe"         # PID
            b"\x00\x00"         # UID
            b"\x00\x00"         # MID
            # Negotiate payload — request SMBv1 (NT LM 0.12)
            b"\x00"             # Word count
            b"\x62\x00"        # Byte count
            b"\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20"
            b"\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"
            b"\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
            b"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72"
            b"\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20"
            b"\x33\x2e\x31\x61\x00"
            b"\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"
            b"\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00"
            b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
        )
        sock.send(negotiate)
        resp = sock.recv(4096)
        if len(resp) < 36 or resp[4:8] != b"\xff\x53\x4d\x42":
            sock.close()
            return False

        # Session setup (null session for the probe)
        session_setup = bytearray(
            b"\x00\x00\x00\x63"  # NetBIOS
            b"\xff\x53\x4d\x42"  # SMB magic
            b"\x73"              # SMB_COM_SESSION_SETUP_ANDX
            b"\x00\x00\x00\x00" # Status
            b"\x18"              # Flags
            b"\x07\xc0"         # Flags2 (Unicode, NT Status, Extended Security)
            b"\x00\x00"         # PID high
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
            b"\x00\x00"         # Reserved
            b"\x00\x00"         # TID
            b"\xff\xfe"         # PID
            b"\x00\x00"         # UID
            b"\x00\x00"         # MID
            b"\x0d"             # Word count = 13
            b"\xff"             # AndXCommand
            b"\x00"             # Reserved
            b"\x00\x00"         # AndXOffset
            b"\xdf\xff"         # MaxBuffer
            b"\x02\x00"         # MaxMpxCount
            b"\x01\x00"         # VcNumber
            b"\x00\x00\x00\x00" # SessionKey
            b"\x00\x00"         # OEM password length
            b"\x00\x00"         # Unicode password length
            b"\x00\x00\x00\x00" # Reserved
            b"\x40\x00\x00\x00" # Capabilities
            b"\x26\x00"         # Byte count
            b"\x00"             # Account name (null)
            b"\x2e\x00"         # Primary domain
            b"\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20"
            b"\x32\x31\x39\x35\x00"  # Native OS
            b"\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20"
            b"\x35\x2e\x30\x00"      # Native LAN Manager
        )
        sock.send(session_setup)
        resp = sock.recv(4096)

        if len(resp) < 36:
            sock.close()
            return False

        # Build TRANS2 SESSION_SETUP to probe for vulnerability
        # We use tree connect to IPC$ first
        tree_connect = bytearray(
            b"\x00\x00\x00\x47"  # NetBIOS
            b"\xff\x53\x4d\x42"  # SMB magic
            b"\x75"              # SMB_COM_TREE_CONNECT_ANDX
            b"\x00\x00\x00\x00" # Status
            b"\x18"              # Flags
            b"\x07\xc0"         # Flags2
            b"\x00\x00"         # PID high
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
            b"\x00\x00"         # Reserved
            b"\x00\x00"         # TID
            b"\xff\xfe"         # PID
        )
        # Extract UID from session setup response
        uid = struct.unpack("<H", resp[32:34])[0]
        tree_connect += struct.pack("<H", uid)
        tree_connect += bytearray(
            b"\x00\x00"         # MID
            b"\x04"             # Word count
            b"\xff"             # AndXCommand
            b"\x00"             # Reserved
            b"\x00\x00"         # AndXOffset
            b"\x00\x00"         # Flags
            b"\x01\x00"         # Password length
            b"\x1a\x00"         # Byte count
            b"\x00"             # Password
            b"\x5c\x5c"         # \\
        )
        # Add IP + \IPC$ path
        ipc_path = f"{ip}\\IPC$\x00".encode("utf-16-le")
        tree_connect += ipc_path
        tree_connect += b"\x3f\x3f\x3f\x3f\x3f\x00"  # Service "?????"

        # Fix NetBIOS length
        total_len = len(tree_connect) - 4
        struct.pack_into(">I", tree_connect, 0, total_len)

        sock.send(tree_connect)
        resp = sock.recv(4096)

        if len(resp) < 36:
            sock.close()
            return False

        # Extract TID
        tid = struct.unpack("<H", resp[28:30])[0]

        # TRANS2 SESSION_SETUP — the actual vulnerability probe
        trans2 = bytearray(
            b"\x00\x00\x00\x4e"  # NetBIOS (placeholder)
            b"\xff\x53\x4d\x42"  # SMB magic
            b"\x32"              # SMB_COM_TRANSACTION2
            b"\x00\x00\x00\x00" # Status
            b"\x18"              # Flags
            b"\x07\xc0"         # Flags2
            b"\x00\x00"         # PID high
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
            b"\x00\x00"         # Reserved
        )
        trans2 += struct.pack("<H", tid)
        trans2 += b"\xff\xfe"  # PID
        trans2 += struct.pack("<H", uid)
        trans2 += bytearray(
            b"\x00\x00"         # MID
            b"\x0f"             # Word count = 15
            b"\x0c\x00"         # Total param count
            b"\x00\x00"         # Total data count
            b"\x01\x00"         # Max param count
            b"\x00\x00"         # Max data count
            b"\x00"             # Max setup count
            b"\x00"             # Reserved
            b"\x00\x00"         # Flags
            b"\xa6\xd9\xa4\x00" # Timeout
            b"\x00\x00"         # Reserved
            b"\x0c\x00"         # Param count
            b"\x42\x00"         # Param offset (66)
            b"\x00\x00"         # Data count
            b"\x4e\x00"         # Data offset
            b"\x0e"             # Setup count
            b"\x00"             # Reserved
            b"\x0e\x00"         # Subcommand: SESSION_SETUP
            b"\x00\x00" b"\x00\x00" b"\x00\x00"
            b"\x00\x00" b"\x00\x00" b"\x00\x00"
            b"\x00\x00" b"\x00\x00" b"\x00\x00"
            b"\x00\x00" b"\x00\x00" b"\x00\x00"
            b"\x00\x00"         # Byte count
        )

        # Fix NetBIOS length
        total_len = len(trans2) - 4
        struct.pack_into(">I", trans2, 0, total_len)

        sock.send(trans2)
        resp = sock.recv(4096)
        sock.close()

        if len(resp) < 12:
            return False

        # Check NT Status code — STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205
        # means vulnerable. STATUS_INVALID_PARAMETER = patched.
        nt_status = struct.unpack("<I", resp[8:12])[0] if len(resp) >= 12 else 0
        return nt_status == 0xC0000205

    except Exception:
        with contextlib.suppress(Exception):
            sock.close()
        return False


# ── PrintNightmare (CVE-2021-1675 / CVE-2021-34527) ─────────────────


def _check_print_nightmare(ip: str, port: int = 445, timeout: int = 10) -> bool:
    """Check if Print Spooler is accessible via \\pipe\\spoolss.

    Connects via SMB and attempts to open the spoolss named pipe.
    If accessible, the host is potentially vulnerable to PrintNightmare.
    """
    try:
        from impacket.smbconnection import SMBConnection  # type: ignore[import-untyped]
    except ImportError:
        return False

    try:
        conn = SMBConnection(ip, ip, sess_port=port, timeout=timeout)
        conn.negotiateSession()
        conn.login("", "")  # null session

        # Try to connect to the spoolss pipe
        try:
            tid = conn.connectTree("IPC$")
            fid = conn.openFile(tid, "\\spoolss", desiredAccess=0x12019F)
            conn.closeFile(tid, fid)
            conn.disconnectTree(tid)
            conn.close()
            return True
        except Exception:
            # Try with a different access mask
            try:
                fid = conn.openFile(tid, "\\spoolss", desiredAccess=0x0002019F)
                conn.closeFile(tid, fid)
                conn.disconnectTree(tid)
                conn.close()
                return True
            except Exception:
                pass

        conn.close()
    except Exception:
        pass
    return False


# ── SMB Signing ──────────────────────────────────────────────────────


def _check_smb_signing(ip: str, port: int = 445, timeout: int = 10) -> bool:
    """Return True if SMB signing is NOT required (vulnerable to relay)."""
    try:
        from impacket.smbconnection import SMBConnection  # type: ignore[import-untyped]
    except ImportError:
        return False

    try:
        conn = SMBConnection(ip, ip, sess_port=port, timeout=timeout)
        conn.negotiateSession()
        result = not conn.isSigningRequired()
        conn.close()
        return result
    except Exception:
        return False


# ── PetitPotam (CVE-2021-36942) ──────────────────────────────────────


def _check_petitpotam(ip: str, port: int = 445, timeout: int = 10) -> bool:
    """Check for PetitPotam via EfsRpcOpenFileRaw on \\pipe\\lsarpc.

    Attempts to bind to the EFSRPC interface. If the bind succeeds,
    the host is potentially vulnerable (the Encrypting File System
    Remote Protocol is accessible).
    """
    try:
        from impacket.dcerpc.v5 import epm  # noqa: F401 # type: ignore[import-untyped]
        from impacket.dcerpc.v5 import transport as dce_transport  # type: ignore[import-untyped]
    except ImportError:
        return False

    # EFSRPC UUID
    efsrpc_uuid = "c681d488-d850-11d0-8c52-00c04fd90f7e"
    efsrpc_version = "1.0"

    try:
        rpctransport = dce_transport.SMBTransport(
            ip, port, r"\lsarpc", "", "", timeout=timeout
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()

        try:
            dce.bind(
                epm.uuidtup_to_bin((efsrpc_uuid, efsrpc_version))
            )
            # If bind succeeds, the pipe is accessible
            dce.disconnect()
            return True
        except Exception:
            pass

        # Try alternate UUID
        alt_uuid = "df1941c5-fe89-4e79-bf10-463657acf44d"
        try:
            dce2 = rpctransport.get_dce_rpc()
            dce2.connect()
            dce2.bind(
                epm.uuidtup_to_bin((alt_uuid, efsrpc_version))
            )
            dce2.disconnect()
            return True
        except Exception:
            pass

        dce.disconnect()
    except Exception:
        pass
    return False


# ── ZeroLogon (CVE-2020-1472) ────────────────────────────────────────


def _check_zerologon(ip: str, timeout: int = 10) -> bool:
    """Check for ZeroLogon (CVE-2020-1472) vulnerability.

    Attempts to bind to the Netlogon RPC service and send a
    NetrServerAuthenticate3 with zero credentials. We only CHECK,
    we do NOT complete the exploit (which would reset the DC password).

    Returns True if the target responds in a way that indicates
    vulnerability (accepts the zero-credential authentication attempt).
    """
    try:
        from impacket.dcerpc.v5 import (
            nrpc,  # type: ignore[import-untyped]
        )
        from impacket.dcerpc.v5 import transport as dce_transport  # type: ignore[import-untyped]
    except ImportError:
        return False

    # Netlogon UUID
    nrpc_uuid = nrpc.MSRPC_UUID_NRPC

    try:
        # Connect to Netlogon via named pipe or direct TCP 135
        binding = f"ncacn_ip_tcp:{ip}[135]"
        rpctransport = dce_transport.DCERPCTransportFactory(binding)
        rpctransport.set_connect_timeout(timeout)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc_uuid)

        # Build NetrServerReqChallenge with 8 zero bytes
        # We use a computer name derived from the IP to avoid collision
        computer_name = f"PROBE{ip.replace('.', '')}"[:15]

        try:
            nrpc.hNetrServerReqChallenge(
                dce, None, computer_name + "\x00",
                b"\x00" * 8,
            )

            # Now try NetrServerAuthenticate3 with zero credential
            # If it succeeds, the DC is vulnerable
            try:
                nrpc.hNetrServerAuthenticate3(
                    dce, None, computer_name + "$\x00",
                    nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                    computer_name + "\x00",
                    b"\x00" * 8,  # Zero credential
                    0x212FFFFF,   # Negotiate flags
                )
                # If we get here without exception, it's vulnerable
                dce.disconnect()
                return True
            except Exception:
                # Expected: STATUS_ACCESS_DENIED on patched systems
                pass
        except Exception:
            pass

        dce.disconnect()
    except Exception:
        pass
    return False


# ── Module ───────────────────────────────────────────────────────────


class SMBVulnsModule(BaseModule):
    name = "vuln.smb_vulns"
    description = "SMB vulnerability detection — EternalBlue, PrintNightmare, PetitPotam, ZeroLogon"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1210"]
    required_facts = ["service.smb"]
    produced_facts = [
        "vuln.ms17_010",
        "vuln.printnightmare",
        "vuln.smb_signing_disabled",
        "vuln.petitpotam",
        "vuln.zerologon",
    ]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _ensure_impacket():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        if not _ensure_impacket():
            return []

        findings: list[Finding] = []

        # Gather all hosts with SMB service
        smb_facts = await ctx.facts.get_all("service.smb")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in smb_facts:
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
            await self._scan_host(ctx, findings, host_id, ip, port_num)

        return findings

    async def _scan_host(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Run all SMB vulnerability checks on a single host."""

        # ── 1. MS17-010 (EternalBlue) ────────────────────────────────
        await ctx.rate_limiter.acquire()
        try:
            vuln = await asyncio.to_thread(_check_ms17_010, ip, port)
        except Exception:
            vuln = False

        if vuln:
            await ctx.facts.add(
                "vuln.ms17_010",
                {"host": ip, "port": port, "cve": "CVE-2017-0144"},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"MS17-010 (EternalBlue) — {ip}:{port}",
                description=(
                    f"Host {ip}:{port} is vulnerable to MS17-010 (EternalBlue). "
                    "This critical vulnerability in SMBv1 allows remote code "
                    "execution as SYSTEM without authentication. Widely exploited "
                    "by WannaCry, NotPetya, and other malware families."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                cvss_score=9.8,
                cve_id="CVE-2017-0144",
                module_name=self.name,
                attack_technique_ids=["T1210"],
                evidence=[Evidence(
                    kind="ms17_010",
                    data=(
                        f"TRANS2 SESSION_SETUP returned "
                        f"STATUS_INSUFF_SERVER_RESOURCES on {ip}:{port} — "
                        f"indicates unpatched SMBv1 (MS17-010/EternalBlue)"
                    ),
                )],
                remediation=(
                    "Apply Microsoft security update MS17-010 immediately. "
                    "Disable SMBv1 via: "
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $false"
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                    "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
                    "https://attack.mitre.org/techniques/T1210/",
                ],
                verified=True,
            ))

        # ── 2. PrintNightmare (CVE-2021-1675/34527) ──────────────────
        await ctx.rate_limiter.acquire()
        try:
            vuln = await asyncio.to_thread(_check_print_nightmare, ip, port)
        except Exception:
            vuln = False

        if vuln:
            await ctx.facts.add(
                "vuln.printnightmare",
                {"host": ip, "port": port, "cve": "CVE-2021-34527"},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"PrintNightmare (Spooler accessible) — {ip}:{port}",
                description=(
                    f"The Print Spooler service on {ip} is accessible via "
                    "\\\\pipe\\\\spoolss. This is a prerequisite for "
                    "PrintNightmare (CVE-2021-1675/CVE-2021-34527), which "
                    "allows remote code execution and local privilege "
                    "escalation through the Print Spooler service."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                cvss_score=8.8,
                cve_id="CVE-2021-34527",
                module_name=self.name,
                attack_technique_ids=["T1210"],
                evidence=[Evidence(
                    kind="printnightmare",
                    data=(
                        f"\\\\pipe\\\\spoolss accessible on {ip}:{port} "
                        f"— Print Spooler service is running and reachable"
                    ),
                )],
                remediation=(
                    "Disable the Print Spooler service if not needed: "
                    "Stop-Service -Name Spooler -Force; "
                    "Set-Service -Name Spooler -StartupType Disabled. "
                    "Apply Microsoft patches KB5004945 and later."
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-1675",
                    "https://attack.mitre.org/techniques/T1210/",
                ],
                verified=True,
            ))

        # ── 3. SMB Signing ───────────────────────────────────────────
        await ctx.rate_limiter.acquire()
        try:
            signing_disabled = await asyncio.to_thread(
                _check_smb_signing, ip, port
            )
        except Exception:
            signing_disabled = False

        if signing_disabled:
            await ctx.facts.add(
                "vuln.smb_signing_disabled",
                {"host": ip, "port": port},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"SMB signing not required — {ip}:{port}",
                description=(
                    f"SMB signing is not enforced on {ip}:{port}. This enables "
                    "NTLM relay attacks where an attacker intercepts "
                    "authentication and forwards it to this host to gain "
                    "unauthorized access. Combined with responder/mitm6, this "
                    "is a common path to domain compromise."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1557"],
                evidence=[Evidence(
                    kind="smb_signing",
                    data=f"SMB signing required: False on {ip}:{port}",
                )],
                remediation=(
                    "Enable and require SMB signing via Group Policy: "
                    "Computer Configuration > Policies > Windows Settings > "
                    "Security Settings > Local Policies > Security Options > "
                    "'Microsoft network server: Digitally sign communications "
                    "(always)' = Enabled"
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
            ))

        # ── 4. PetitPotam (CVE-2021-36942) ───────────────────────────
        await ctx.rate_limiter.acquire()
        try:
            vuln = await asyncio.to_thread(_check_petitpotam, ip, port)
        except Exception:
            vuln = False

        if vuln:
            await ctx.facts.add(
                "vuln.petitpotam",
                {"host": ip, "port": port, "cve": "CVE-2021-36942"},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"PetitPotam (EFSRPC accessible) — {ip}:{port}",
                description=(
                    f"The EFSRPC interface is accessible on {ip} via "
                    "\\\\pipe\\\\lsarpc. This enables PetitPotam "
                    "(CVE-2021-36942), which can coerce the machine account "
                    "to authenticate to an attacker-controlled host. "
                    "Combined with NTLM relay to AD CS, this allows domain "
                    "compromise."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                cvss_score=7.5,
                cve_id="CVE-2021-36942",
                module_name=self.name,
                attack_technique_ids=["T1187"],
                evidence=[Evidence(
                    kind="petitpotam",
                    data=(
                        f"EFSRPC bind succeeded on {ip}:{port} via "
                        f"\\\\pipe\\\\lsarpc — PetitPotam coercion possible"
                    ),
                )],
                remediation=(
                    "Apply Microsoft security updates. Disable the Encrypting "
                    "File System service if not needed. Enable Extended "
                    "Protection for Authentication (EPA) on AD CS."
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-36942",
                    "https://attack.mitre.org/techniques/T1187/",
                ],
                verified=True,
            ))

        # ── 5. ZeroLogon (CVE-2020-1472) ─────────────────────────────
        # Only check if this looks like a domain controller (port 135 or
        # 88/Kerberos typically present). ZeroLogon targets DC only.
        dc_indicators = await ctx.facts.get_for_host("service.ldap", host_id)
        kerberos = await ctx.facts.get_for_host("service.kerberos", host_id)
        # Also check port.open for port 88 or 389
        host_ports = await ctx.facts.get_for_host("port.open", host_id)
        dc_ports = {88, 389, 636}
        has_dc_port = any(
            hasattr(p, "port") and p.port in dc_ports
            for p in host_ports
        )

        if dc_indicators or kerberos or has_dc_port:
            await ctx.rate_limiter.acquire()
            try:
                vuln = await asyncio.to_thread(_check_zerologon, ip)
            except Exception:
                vuln = False

            if vuln:
                await ctx.facts.add(
                    "vuln.zerologon",
                    {"host": ip, "cve": "CVE-2020-1472"},
                    self.name,
                    host_id=host_id,
                )
                findings.append(Finding(
                    title=f"ZeroLogon (CVE-2020-1472) — {ip}",
                    description=(
                        f"Domain controller {ip} is vulnerable to ZeroLogon "
                        "(CVE-2020-1472). This critical vulnerability allows "
                        "an unauthenticated attacker to gain domain admin "
                        "privileges by exploiting a flaw in the Netlogon "
                        "authentication protocol. CVSS 10.0."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=host_id,
                    cvss_score=10.0,
                    cve_id="CVE-2020-1472",
                    module_name=self.name,
                    attack_technique_ids=["T1210"],
                    evidence=[Evidence(
                        kind="zerologon",
                        data=(
                            f"NetrServerAuthenticate3 accepted zero "
                            f"credentials on {ip} — DC is vulnerable to "
                            f"CVE-2020-1472 (ZeroLogon). "
                            f"NOTE: Detection only, DC password not changed."
                        ),
                    )],
                    remediation=(
                        "Apply Microsoft security update KB4565349 immediately. "
                        "Enable 'Domain controller: Allow vulnerable Netlogon "
                        "secure channel connections' enforcement mode. Monitor "
                        "Event ID 5829 for vulnerable connections."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
                        "https://attack.mitre.org/techniques/T1210/",
                    ],
                    verified=True,
                ))
