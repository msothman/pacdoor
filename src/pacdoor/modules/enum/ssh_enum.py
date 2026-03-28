"""SSH enumeration — auth methods, weak algorithms, banner analysis, CVEs."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from pacdoor.core.models import Evidence, Finding, Phase, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Lazy-imported at first use so the module can still be loaded (and
# gracefully skipped) when paramiko is not installed.
_paramiko_available: bool | None = None
_paramiko: object | None = None


def _ensure_paramiko() -> bool:
    """Try to import paramiko; cache the result."""
    global _paramiko_available, _paramiko  # noqa: PLW0603
    if _paramiko_available is not None:
        return _paramiko_available
    try:
        import paramiko as _pm  # type: ignore[import-untyped]

        _paramiko = _pm
        _paramiko_available = True
    except ImportError:
        log.warning("paramiko not installed — ssh_enum module will be skipped")
        _paramiko_available = False
    return _paramiko_available


# ── Weak algorithm sets ──────────────────────────────────────────────

WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
WEAK_CIPHERS = {"arcfour", "blowfish-cbc", "3des-cbc"}
WEAK_CIPHER_PATTERNS = ("aes128-cbc", "aes192-cbc", "aes256-cbc")
WEAK_MACS = {"hmac-md5", "hmac-sha1"}
WEAK_HOST_KEY_TYPES = {"ssh-dss"}

# ── Known CVE mapping by OpenSSH version ─────────────────────────────

_OPENSSH_CVES: list[tuple[tuple[int, int], str, str, Severity]] = [
    # (max_version_exclusive, CVE, description, severity)
    (
        (7, 7),
        "CVE-2018-15473",
        "OpenSSH user enumeration — allows remote attackers to determine "
        "whether a user account exists by sending crafted authentication "
        "requests and observing response timing/behavior.",
        Severity.HIGH,
    ),
    (
        (8, 3),
        "CVE-2020-15778",
        "OpenSSH scp command injection — the scp client allows command "
        "injection via crafted filenames passed to the server, potentially "
        "leading to remote code execution.",
        Severity.HIGH,
    ),
]


def _parse_openssh_version(banner: str) -> tuple[int, int] | None:
    """Extract (major, minor) from an OpenSSH banner string."""
    m = re.search(r"OpenSSH[_\s](\d+)\.(\d+)", banner, re.IGNORECASE)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None


# ── Helpers (all synchronous — run via asyncio.to_thread) ────────────


def _probe_ssh(ip: str, port: int, timeout: int = 10) -> dict | None:
    """Connect to an SSH service and gather configuration details.

    Returns a dict with banner, auth_methods, kex, ciphers, macs,
    host_key_types — or None on failure.
    """
    if _paramiko is None:
        return None

    result: dict = {}
    sock = None
    transport = None

    try:
        import socket

        sock = socket.create_connection((ip, port), timeout=timeout)
        transport = _paramiko.Transport(sock)  # type: ignore[union-attr]
        transport.connect()

        # Banner / version string
        remote_version = transport.remote_version or ""
        result["banner"] = remote_version

        # Security options contain supported algorithms
        sec_opts = transport.get_security_options()
        result["kex"] = list(sec_opts.kex)
        result["ciphers"] = list(sec_opts.ciphers)
        result["macs"] = list(sec_opts.digests)
        result["host_key_types"] = list(sec_opts.key_types)

        # Auth methods — try a bogus username to enumerate methods
        try:
            transport.auth_none("__pacdoor_probe__")
        except _paramiko.BadAuthenticationType as e:  # type: ignore[union-attr]
            result["auth_methods"] = list(e.allowed_types)
        except Exception:
            result["auth_methods"] = []

    except Exception:
        if not result:
            return None
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass

    return result


# ── Module ───────────────────────────────────────────────────────────


class SSHEnumModule(BaseModule):
    name = "enum.ssh_enum"
    description = "SSH enumeration — auth methods, weak algorithms, banner CVEs"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046"]
    required_facts = ["service.ssh"]
    produced_facts = ["ssh.auth_methods", "ssh.weak_algos"]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _ensure_paramiko():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        if not _ensure_paramiko():
            return []

        findings: list[Finding] = []

        ssh_facts = await ctx.facts.get_all("service.ssh")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []  # (host_id, ip, port)

        for fact in ssh_facts:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 22
            targets.append((host_id, ip, port_num))

        for host_id, ip, port_num in targets:
            await ctx.rate_limiter.acquire()
            await self._enumerate_host(ctx, findings, host_id, ip, port_num)

        return findings

    async def _enumerate_host(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Run full SSH enumeration on a single host."""

        probe = await asyncio.to_thread(_probe_ssh, ip, port)
        if probe is None:
            log.debug("ssh_enum: could not connect to %s:%d", ip, port)
            return

        banner = probe.get("banner", "")
        auth_methods = probe.get("auth_methods", [])
        kex_algos = probe.get("kex", [])
        ciphers = probe.get("ciphers", [])
        macs = probe.get("macs", [])
        host_key_types = probe.get("host_key_types", [])

        # ── Store auth methods fact ──────────────────────────────────
        await ctx.facts.add(
            "ssh.auth_methods",
            {
                "host": ip,
                "port": port,
                "banner": banner,
                "auth_methods": auth_methods,
            },
            self.name,
            host_id=host_id,
        )

        # ── 1. Weak key exchange algorithms ──────────────────────────
        weak_kex = [k for k in kex_algos if k in WEAK_KEX]

        # ── 2. Weak ciphers ──────────────────────────────────────────
        weak_ciph = [
            c for c in ciphers
            if c in WEAK_CIPHERS or c in WEAK_CIPHER_PATTERNS
        ]

        # ── 3. Weak MACs ─────────────────────────────────────────────
        weak_mac = [m for m in macs if m in WEAK_MACS]

        # ── 4. Weak host key types ───────────────────────────────────
        weak_hk = [k for k in host_key_types if k in WEAK_HOST_KEY_TYPES]

        all_weak: dict[str, list[str]] = {}
        if weak_kex:
            all_weak["key_exchange"] = weak_kex
        if weak_ciph:
            all_weak["ciphers"] = weak_ciph
        if weak_mac:
            all_weak["macs"] = weak_mac
        if weak_hk:
            all_weak["host_key_types"] = weak_hk

        if all_weak:
            await ctx.facts.add(
                "ssh.weak_algos",
                {"host": ip, "port": port, "weak": all_weak},
                self.name,
                host_id=host_id,
            )

            details_lines: list[str] = []
            for category, algos in all_weak.items():
                details_lines.append(f"  {category}: {', '.join(algos)}")
            details = "\n".join(details_lines)

            findings.append(Finding(
                title=f"Weak SSH algorithms on {ip}:{port}",
                description=(
                    f"SSH service on {ip}:{port} supports weak cryptographic "
                    f"algorithms that may be vulnerable to downgrade attacks "
                    f"or brute-force decryption:\n{details}"
                ),
                severity=Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="ssh_weak_algos",
                    data=f"Weak algorithms on {ip}:{port}:\n{details}",
                )],
                remediation=(
                    "Disable weak algorithms in sshd_config. Set "
                    "'KexAlgorithms', 'Ciphers', 'MACs', and "
                    "'HostKeyAlgorithms' to only include strong algorithms. "
                    "Remove diffie-hellman-group1-sha1, diffie-hellman-group14-sha1, "
                    "arcfour, blowfish-cbc, 3des-cbc, aes*-cbc ciphers, "
                    "hmac-md5, hmac-sha1, and ssh-dss."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                    "https://www.openssh.com/security.html",
                ],
            ))

        # ── 5. Password auth enabled ─────────────────────────────────
        if "password" in auth_methods:
            findings.append(Finding(
                title=f"SSH password authentication enabled on {ip}:{port}",
                description=(
                    f"SSH service on {ip}:{port} allows password-based "
                    f"authentication. This enables brute-force and credential "
                    f"stuffing attacks against user accounts."
                ),
                severity=Severity.LOW,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="ssh_auth",
                    data=(
                        f"Allowed auth methods on {ip}:{port}: "
                        f"{', '.join(auth_methods)}"
                    ),
                )],
                remediation=(
                    "Disable password authentication in sshd_config: set "
                    "'PasswordAuthentication no' and 'ChallengeResponseAuthentication no'. "
                    "Use key-based authentication exclusively."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 6. Known CVEs by OpenSSH version ─────────────────────────
        version = _parse_openssh_version(banner)
        if version is not None:
            for max_ver, cve_id, cve_desc, cve_sev in _OPENSSH_CVES:
                if version < max_ver:
                    findings.append(Finding(
                        title=f"{cve_id}: {ip}:{port} (OpenSSH {version[0]}.{version[1]})",
                        description=(
                            f"SSH service on {ip}:{port} reports OpenSSH "
                            f"{version[0]}.{version[1]} via banner "
                            f"'{banner}'. This version is affected by "
                            f"{cve_id}: {cve_desc}"
                        ),
                        severity=cve_sev,
                        host_id=host_id,
                        module_name=self.name,
                        cve_id=cve_id,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[Evidence(
                            kind="ssh_banner",
                            data=f"Banner: {banner} -> {cve_id}",
                        )],
                        remediation=(
                            f"Upgrade OpenSSH to a version that patches {cve_id}. "
                            f"Current version ({version[0]}.{version[1]}) is below "
                            f"the fix threshold ({max_ver[0]}.{max_ver[1]})."
                        ),
                        references=[
                            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                            "https://www.openssh.com/security.html",
                        ],
                    ))

        # ── 7. Old SSH protocol (SSH-1) ──────────────────────────────
        if banner and "SSH-1" in banner and "SSH-1.99" not in banner:
            findings.append(Finding(
                title=f"SSH protocol version 1 on {ip}:{port}",
                description=(
                    f"SSH service on {ip}:{port} advertises SSH protocol "
                    f"version 1 (banner: '{banner}'). SSHv1 has known "
                    f"cryptographic weaknesses including susceptibility to "
                    f"man-in-the-middle attacks and session hijacking."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="ssh_banner",
                    data=f"SSH-1 protocol detected: {banner}",
                )],
                remediation=(
                    "Disable SSH protocol version 1 in sshd_config: set "
                    "'Protocol 2'. SSH-1 is deprecated and insecure."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))
