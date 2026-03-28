"""Automatic hash cracking integration with hashcat/john.

Collects extracted hashes from the fact store (NTLM, Kerberos TGS,
AS-REP, NetNTLMv2, Linux shadow) and cracks them using hashcat or
john the ripper.  Falls back to a pure-Python NTLM brute-force
against the top 100 passwords when neither binary is available.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import shutil
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

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

# ── Hash-type constants ───────────────────────────────────────────────

# hashcat mode -> (description, fact_type_hint, hash_prefix_or_test)
_HASH_TYPES: dict[int, str] = {
    1000: "NTLM",
    13100: "Kerberos TGS-REP (etype 23)",
    18200: "Kerberos AS-REP (etype 23)",
    5600: "NetNTLMv2",
    1800: "sha512crypt",
    7400: "sha256crypt",
    500: "md5crypt",
}

# Per hash-type timeout (seconds).
_CRACK_TIMEOUT = 120

# Path to the built-in wordlist relative to the package data directory.
_WORDLIST_REL = Path("data", "wordlists", "passwords-top1000.txt")

# Top 100 passwords for pure-Python NTLM fallback.
_TOP_100_PASSWORDS: list[str] = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "admin", "password1",
    "welcome", "Password1", "p@ssw0rd", "passw0rd", "Password123",
]


def _wordlist_path() -> Path:
    """Resolve the built-in wordlist path."""
    # Walk up from this file to the pacdoor package root.
    pkg_root = Path(__file__).resolve().parent.parent.parent  # src/pacdoor
    return pkg_root / _WORDLIST_REL


def _ntlm_hash(password: str) -> str:
    """Compute the NTLM (NT) hash of a password — MD4(UTF-16LE)."""
    # MD4 via hashlib (OpenSSL must support it; available on most platforms).
    try:
        return hashlib.new("md4", password.encode("utf-16le")).hexdigest()
    except ValueError:
        # Some Python builds disable MD4.  Use a pure-Python fallback.
        return _md4_pure(password.encode("utf-16le"))


# ── Pure-Python MD4 (fallback when OpenSSL disables it) ──────────────

def _md4_pure(data: bytes) -> str:
    """Minimal pure-Python MD4 implementation (RFC 1320)."""

    def _left_rotate(n: int, b: int) -> int:
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z) & 0xFFFFFFFF

    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def _h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    msg = bytearray(data)
    orig_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[i : i + 64]))
        a, b, c, d = a0, b0, c0, d0

        # Round 1
        for k in range(16):
            if k % 4 == 0:
                a = _left_rotate((a + _f(b, c, d) + x[k]) & 0xFFFFFFFF, 3)
            elif k % 4 == 1:
                d = _left_rotate((d + _f(a, b, c) + x[k]) & 0xFFFFFFFF, 7)
            elif k % 4 == 2:
                c = _left_rotate((c + _f(d, a, b) + x[k]) & 0xFFFFFFFF, 11)
            else:
                b = _left_rotate((b + _f(c, d, a) + x[k]) & 0xFFFFFFFF, 19)

        # Round 2
        for k in [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]:
            idx = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15].index(k)
            val = (0x5A827999 + x[k]) & 0xFFFFFFFF
            if idx % 4 == 0:
                a = _left_rotate((a + _g(b, c, d) + val) & 0xFFFFFFFF, 3)
            elif idx % 4 == 1:
                d = _left_rotate((d + _g(a, b, c) + val) & 0xFFFFFFFF, 5)
            elif idx % 4 == 2:
                c = _left_rotate((c + _g(d, a, b) + val) & 0xFFFFFFFF, 9)
            else:
                b = _left_rotate((b + _g(c, d, a) + val) & 0xFFFFFFFF, 13)

        # Round 3
        for k in [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]:
            idx = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15].index(k)
            val = (0x6ED9EBA1 + x[k]) & 0xFFFFFFFF
            if idx % 4 == 0:
                a = _left_rotate((a + _h(b, c, d) + val) & 0xFFFFFFFF, 3)
            elif idx % 4 == 1:
                d = _left_rotate((d + _h(a, b, c) + val) & 0xFFFFFFFF, 9)
            elif idx % 4 == 2:
                c = _left_rotate((c + _h(d, a, b) + val) & 0xFFFFFFFF, 11)
            else:
                b = _left_rotate((b + _h(c, d, a) + val) & 0xFFFFFFFF, 15)

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0).hex()


# ── Hash classification helpers ──────────────────────────────────────

def _classify_hash(value: str) -> int | None:
    """Return the hashcat mode for a hash string, or None if unknown."""
    value = value.strip()

    # Kerberos TGS (hashcat -m 13100)
    if value.startswith("$krb5tgs$"):
        return 13100

    # Kerberos AS-REP (hashcat -m 18200)
    if value.startswith("$krb5asrep$"):
        return 18200

    # sha512crypt (hashcat -m 1800)
    if value.startswith("$6$"):
        return 1800

    # sha256crypt (hashcat -m 7400)
    if value.startswith("$5$"):
        return 7400

    # md5crypt (hashcat -m 500)
    if value.startswith("$1$"):
        return 500

    # NetNTLMv2 (hashcat -m 5600) — format: user::domain:challenge:hash:blob
    if value.count(":") >= 5 and "::" in value:
        return 5600

    # NTLM hash — 32 hex chars, or LM:NT pair (32:32)
    if ":" in value:
        parts = value.split(":")
        if len(parts) == 2 and all(len(p) == 32 for p in parts):
            return 1000
    elif len(value) == 32:
        try:
            int(value, 16)
            return 1000
        except ValueError:
            pass

    return None


def _extract_nt_hash(value: str) -> str:
    """Extract just the NT hash from an LM:NT pair, or return as-is."""
    if ":" in value:
        parts = value.split(":")
        if len(parts) == 2 and len(parts[1]) == 32:
            return parts[1].lower()
    return value.lower()


# ── Module ───────────────────────────────────────────────────────────


class HashCrackModule(BaseModule):
    """Automatic hash cracking via hashcat, john, or pure-Python NTLM brute."""

    name = "post.hash_crack"
    description = "Crack extracted hashes with hashcat/john or pure-Python NTLM brute"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1110.002"]
    # NOTE: check() uses OR logic — the module runs if *either* fact type
    # is present (Kerberos hashes OR NTLM hashes in credential.valid).
    # Both are listed here for dependency-graph visibility; the actual
    # gate is the check() override below.
    required_facts = ["credential.kerberos_hash", "credential.valid"]
    produced_facts = ["credential.cracked"]
    safety = ExploitSafety.SAFE

    async def check(self, ctx: ModuleContext) -> bool:
        """Run if we have Kerberos hashes OR NTLM hash credentials."""
        has_kerb = await ctx.facts.has("credential.kerberos_hash")
        if has_kerb:
            return True

        # Check for NTLM_HASH credentials in credential.valid
        valid_creds = await ctx.facts.get_values("credential.valid")
        for cred in valid_creds:
            cred_type = (
                cred.cred_type if hasattr(cred, "cred_type")
                else cred.get("cred_type", "") if isinstance(cred, dict)
                else ""
            )
            if str(cred_type) in ("ntlm_hash", "NTLM_HASH", CredentialType.NTLM_HASH):
                return True

        return False

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        # ── Collect all hashes from the fact store ───────────────────
        # Dict: hashcat_mode -> list of (username, hash_value, host_id, domain)
        hash_buckets: dict[int, list[tuple[str, str, str | None, str | None]]] = {}

        # 1) Kerberos hashes from Kerberoast / AS-REP roast
        kerb_creds = await ctx.facts.get_all("credential.kerberos_hash")
        for fact in kerb_creds:
            cred = fact.value
            username = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
            value = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))
            domain = cred.domain if hasattr(cred, "domain") else (cred.get("domain") if isinstance(cred, dict) else None)
            host_id = fact.host_id

            mode = _classify_hash(value)
            if mode is not None:
                hash_buckets.setdefault(mode, []).append((username, value, host_id, domain))

        # 2) NTLM hashes from SAM dump / cred_harvest / NTDS
        valid_creds = await ctx.facts.get_all("credential.valid")
        for fact in valid_creds:
            cred = fact.value
            cred_type = (
                str(cred.cred_type) if hasattr(cred, "cred_type")
                else str(cred.get("cred_type", "")) if isinstance(cred, dict)
                else ""
            )
            if cred_type not in ("ntlm_hash", "NTLM_HASH", str(CredentialType.NTLM_HASH)):
                # Also check for shadow hashes (value starts with $6$, $5$, $1$)
                value = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))
                shadow_mode = _classify_hash(value)
                if shadow_mode in (1800, 7400, 500):
                    username = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
                    domain = cred.domain if hasattr(cred, "domain") else (cred.get("domain") if isinstance(cred, dict) else None)
                    hash_buckets.setdefault(shadow_mode, []).append(
                        (username, value, fact.host_id, domain)
                    )
                continue

            username = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
            value = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))
            domain = cred.domain if hasattr(cred, "domain") else (cred.get("domain") if isinstance(cred, dict) else None)
            host_id = fact.host_id

            mode = _classify_hash(value)
            if mode is not None:
                hash_buckets.setdefault(mode, []).append((username, value, host_id, domain))

        if not hash_buckets:
            log.debug("hash_crack: no hashes found in fact store")
            return findings

        total_hashes = sum(len(v) for v in hash_buckets.values())
        log.debug(
            "hash_crack: collected %d hashes across %d types",
            total_hashes, len(hash_buckets),
        )

        # ── Determine cracking backend ───────────────────────────────
        hashcat_path = shutil.which("hashcat")
        john_path = shutil.which("john")
        wordlist = _wordlist_path()

        if hashcat_path and wordlist.exists():
            cracked = await self._crack_hashcat(
                ctx, hashcat_path, wordlist, hash_buckets,
            )
        elif john_path and wordlist.exists():
            cracked = await self._crack_john(
                ctx, john_path, wordlist, hash_buckets,
            )
        else:
            # Pure-Python NTLM fallback — only handles mode 1000
            cracked = await self._crack_python_ntlm(
                ctx, hash_buckets.get(1000, []),
            )
            if not hashcat_path and not john_path:
                log.debug(
                    "hash_crack: neither hashcat nor john found; "
                    "used pure-Python NTLM brute for %d hashes",
                    len(hash_buckets.get(1000, [])),
                )

        # ── Store results ────────────────────────────────────────────
        for username, password, host_id, domain in cracked:
            new_cred = Credential(
                host_id=host_id,
                username=username,
                cred_type=CredentialType.PASSWORD,
                value=password,
                domain=domain,
                source_module=self.name,
                valid=True,
            )
            await ctx.facts.add(
                "credential.cracked", new_cred, self.name, host_id=host_id,
            )
            if ctx.db is not None:
                await ctx.db.insert_credential(new_cred)

            finding = Finding(
                title=f"Hash cracked: {username} -> plaintext password recovered",
                description=(
                    f"Successfully cracked the password hash for user "
                    f"'{username}'{' in domain ' + domain if domain else ''}. "
                    f"The plaintext password is now available for further "
                    f"authentication and lateral movement."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1110.002"],
                evidence=[
                    Evidence(kind="cracked_user", data=username),
                    Evidence(
                        kind="cracked_password",
                        data=f"{password[:2]}{'*' * (len(password) - 2)}",
                    ),
                ],
                remediation=(
                    "Enforce strong password policies with a minimum of 14 "
                    "characters. Use a password blocklist to prevent common "
                    "passwords. Implement multi-factor authentication. For "
                    "service accounts, use Group Managed Service Accounts (gMSA) "
                    "with automatically rotated passwords."
                ),
                verified=True,
            )
            findings.append(finding)

            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

        return findings

    # ── Hashcat backend ──────────────────────────────────────────────

    async def _crack_hashcat(
        self,
        ctx: ModuleContext,
        hashcat_path: str,
        wordlist: Path,
        hash_buckets: dict[int, list[tuple[str, str, str | None, str | None]]],
    ) -> list[tuple[str, str, str | None, str | None]]:
        """Crack hashes using hashcat."""
        cracked: list[tuple[str, str, str | None, str | None]] = []

        # Check for best64 rule
        rules_file: str | None = None
        for candidate in [
            "/usr/share/hashcat/rules/best64.rule",
            "/opt/hashcat/rules/best64.rule",
            os.path.join(os.path.dirname(hashcat_path), "rules", "best64.rule"),
        ]:
            if os.path.isfile(candidate):
                rules_file = candidate
                break

        for mode, entries in hash_buckets.items():
            if not entries:
                continue

            # Build username -> hash mapping for result correlation
            user_map: dict[str, tuple[str, str | None, str | None]] = {}

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".hashes", delete=False,
            ) as f:
                hash_file = f.name
                for username, hash_val, host_id, domain in entries:
                    # For NTLM, extract just the NT hash
                    if mode == 1000:
                        clean_hash = _extract_nt_hash(hash_val)
                    else:
                        clean_hash = hash_val
                    f.write(clean_hash + "\n")
                    user_map[clean_hash.lower()] = (username, host_id, domain)

            try:
                cmd = [
                    hashcat_path,
                    "-m", str(mode),
                    "-a", "0",           # Straight attack
                    hash_file,
                    str(wordlist),
                    "--potfile-disable",  # Don't use potfile
                    "--quiet",           # Minimal output
                    "-o", hash_file + ".cracked",
                    "--outfile-format", "2",  # hash:plain
                ]
                if rules_file:
                    cmd.extend(["-r", rules_file])

                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(
                        proc.communicate(), timeout=_CRACK_TIMEOUT,
                    )
                except TimeoutError:
                    log.debug(
                        "hash_crack: hashcat timed out on mode %d after %ds",
                        mode, _CRACK_TIMEOUT,
                    )
                    with contextlib.suppress(ProcessLookupError):
                        proc.terminate()
                except OSError as exc:
                    log.debug("hash_crack: hashcat exec failed: %s", exc)
                    continue

                # Parse cracked output
                cracked_file = hash_file + ".cracked"
                if os.path.isfile(cracked_file):
                    with open(cracked_file) as f:
                        for line in f:
                            line = line.strip()
                            if ":" not in line:
                                continue
                            hash_part, plaintext = line.split(":", 1)
                            lookup = hash_part.lower()
                            if lookup in user_map:
                                username, host_id, domain = user_map[lookup]
                                cracked.append((username, plaintext, host_id, domain))
                    os.unlink(cracked_file)
            finally:
                if os.path.isfile(hash_file):
                    os.unlink(hash_file)

        return cracked

    # ── John the Ripper backend ──────────────────────────────────────

    async def _crack_john(
        self,
        ctx: ModuleContext,
        john_path: str,
        wordlist: Path,
        hash_buckets: dict[int, list[tuple[str, str, str | None, str | None]]],
    ) -> list[tuple[str, str, str | None, str | None]]:
        """Crack hashes using john the ripper."""
        cracked: list[tuple[str, str, str | None, str | None]] = []

        # Map hashcat modes to john formats
        john_format_map: dict[int, str] = {
            1000: "NT",
            13100: "krb5tgs",
            18200: "krb5asrep",
            5600: "netntlmv2",
            1800: "sha512crypt",
            7400: "sha256crypt",
            500: "md5crypt",
        }

        for mode, entries in hash_buckets.items():
            if not entries:
                continue

            john_format = john_format_map.get(mode)
            if john_format is None:
                continue

            user_map: dict[str, tuple[str, str | None, str | None]] = {}

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".hashes", delete=False,
            ) as f:
                hash_file = f.name
                for username, hash_val, host_id, domain in entries:
                    # John uses user:hash format for some types
                    if mode == 1000:
                        clean_hash = _extract_nt_hash(hash_val)
                        f.write(f"{username}:{clean_hash}\n")
                    else:
                        f.write(hash_val + "\n")
                    user_map[username.lower()] = (username, host_id, domain)

            try:
                cmd = [
                    john_path,
                    hash_file,
                    f"--format={john_format}",
                    f"--wordlist={wordlist}",
                    "--no-log",
                ]

                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(
                        proc.communicate(), timeout=_CRACK_TIMEOUT,
                    )
                except TimeoutError:
                    log.debug(
                        "hash_crack: john timed out on format %s after %ds",
                        john_format, _CRACK_TIMEOUT,
                    )
                    with contextlib.suppress(ProcessLookupError):
                        proc.terminate()
                except OSError as exc:
                    log.debug("hash_crack: john exec failed: %s", exc)
                    continue

                # Parse cracked results via --show
                try:
                    show_proc = await asyncio.create_subprocess_exec(
                        john_path, hash_file,
                        f"--format={john_format}",
                        "--show",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    show_stdout, _ = await asyncio.wait_for(
                        show_proc.communicate(), timeout=30,
                    )
                    show_text = show_stdout.decode("utf-8", errors="replace")

                    for line in show_text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("(") or "password hashes cracked" in line:
                            continue
                        # Format: username:password or hash:password
                        if ":" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                user_part = parts[0].lower()
                                plaintext = parts[1]
                                if user_part in user_map:
                                    username, host_id, domain = user_map[user_part]
                                    cracked.append((username, plaintext, host_id, domain))
                except (TimeoutError, OSError):
                    pass
            finally:
                if os.path.isfile(hash_file):
                    os.unlink(hash_file)

        return cracked

    # ── Pure-Python NTLM fallback ────────────────────────────────────

    async def _crack_python_ntlm(
        self,
        ctx: ModuleContext,
        ntlm_entries: list[tuple[str, str, str | None, str | None]],
    ) -> list[tuple[str, str, str | None, str | None]]:
        """Brute-force NTLM hashes against top 100 passwords — pure Python."""
        if not ntlm_entries:
            return []

        def _brute() -> list[tuple[str, str, str | None, str | None]]:
            # Pre-compute NT hashes for top 100 passwords
            precomputed: dict[str, str] = {}
            for pwd in _TOP_100_PASSWORDS:
                precomputed[_ntlm_hash(pwd)] = pwd

            results: list[tuple[str, str, str | None, str | None]] = []
            for username, hash_val, host_id, domain in ntlm_entries:
                nt_hash = _extract_nt_hash(hash_val)
                if nt_hash in precomputed:
                    results.append((username, precomputed[nt_hash], host_id, domain))
            return results

        return await asyncio.to_thread(_brute)
