"""OS fingerprinting from network behaviour — TTL, TCP window, banners, and port heuristics.

Combines multiple signals to identify the target operating system:
  1. TTL analysis from a live TCP connection
  2. TCP window size correlation
  3. Service banner keyword matching
  4. Open-port combination heuristics

Updates the Host object and persists changes to the database.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import socket
import struct
from typing import TYPE_CHECKING

from pacdoor.core.models import Evidence, Finding, Host, Phase, Port, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── TTL → OS mapping ────────────────────────────────────────────────────

_TTL_RANGES: list[tuple[int, int, str]] = [
    # (low, high, os_family)
    (1, 70, "Linux"),         # Default 64
    (71, 135, "Windows"),     # Default 128
    (200, 255, "BSD/Network Device"),  # Default 255
]

# ── TCP window size → OS hints ──────────────────────────────────────────
# Maps specific default window sizes to likely OS family.

_WINDOW_HINTS: dict[int, str] = {
    5840: "Linux",
    14600: "Linux",
    29200: "Linux",
    8192: "Windows",
    65535: "Windows/macOS",
}

# ── Banner keyword → OS mapping ─────────────────────────────────────────
# (keyword_lower, os_family, os_version_or_distro)

_BANNER_OS_KEYWORDS: list[tuple[str, str, str | None]] = [
    ("microsoft", "Windows", None),
    ("windows", "Windows", None),
    ("ubuntu", "Linux", "Ubuntu"),
    ("debian", "Linux", "Debian"),
    ("centos", "Linux", "CentOS"),
    ("red hat", "Linux", "Red Hat"),
    ("fedora", "Linux", "Fedora"),
    ("suse", "Linux", "SUSE"),
    ("alpine", "Linux", "Alpine"),
    ("openbsd", "BSD", "OpenBSD"),
    ("freebsd", "BSD", "FreeBSD"),
    ("netbsd", "BSD", "NetBSD"),
]

# ── Port combination heuristics ─────────────────────────────────────────
# Each entry: (required_ports frozenset, os_family, os_version_hint)

_PORT_COMBOS: list[tuple[frozenset[int], str, str | None]] = [
    (frozenset({88, 389, 445}), "Windows", "Domain Controller"),
    (frozenset({135, 445, 3389}), "Windows", "Server/Desktop"),
    (frozenset({135, 445}), "Windows", None),
    (frozenset({3389}), "Windows", None),
    (frozenset({22}), "Linux", None),  # SSH alone is a weak signal
]

# ── Confidence scoring ──────────────────────────────────────────────────
# Each detection method contributes a weight. We pick the OS with the
# highest cumulative score.

_WEIGHT_TTL = 3
_WEIGHT_WINDOW = 2
_WEIGHT_BANNER = 4
_WEIGHT_PORTS = 2


def _ttl_to_os(ttl: int) -> str | None:
    """Map a TTL value to an OS family string."""
    for lo, hi, os_family in _TTL_RANGES:
        if lo <= ttl <= hi:
            return os_family
    return None


class OsDetectModule(BaseModule):
    """OS fingerprinting via TTL, window size, banners, and port patterns."""

    name = "recon.os_detect"
    description = "OS fingerprinting from network behaviour"
    phase = Phase.RECON
    attack_technique_ids = ["T1082"]
    required_facts = ["port.open"]
    produced_facts = ["os.detected"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        hosts: list[Host] = await ctx.facts.get_values("host")
        ports: list[Port] = await ctx.facts.get_values("port.open")
        if not hosts:
            return []

        # Build per-host port set and banner list.
        host_ports: dict[str, set[int]] = {}
        host_banners: dict[str, list[str]] = {}
        for p in ports:
            host_ports.setdefault(p.host_id, set()).add(p.port)
            if p.banner:
                host_banners.setdefault(p.host_id, []).append(p.banner)

        findings: list[Finding] = []

        for host in hosts:
            result = await self._fingerprint_host(
                ctx,
                host,
                host_ports.get(host.id, set()),
                host_banners.get(host.id, []),
            )
            if result:
                findings.append(result)

        return findings

    async def _fingerprint_host(
        self,
        ctx: ModuleContext,
        host: Host,
        open_ports: set[int],
        banners: list[str],
    ) -> Finding | None:
        """Combine multiple signals to detect OS for a single host."""
        # Accumulate votes: {os_family: score}
        votes: dict[str, float] = {}
        evidence_items: list[Evidence] = []
        os_version: str | None = None

        # ── 1. TTL analysis ──────────────────────────────────────────
        ttl = await self._probe_ttl(host.ip, open_ports)
        if ttl is not None:
            ttl_os = _ttl_to_os(ttl)
            if ttl_os:
                votes[ttl_os] = votes.get(ttl_os, 0) + _WEIGHT_TTL
                evidence_items.append(
                    Evidence(kind="ttl", data=f"TTL={ttl} -> {ttl_os}")
                )

        # ── 2. TCP window size ───────────────────────────────────────
        window_size = await self._probe_window_size(host.ip, open_ports)
        if window_size is not None:
            win_os = _WINDOW_HINTS.get(window_size)
            if win_os:
                # "Windows/macOS" contributes to both but at half weight.
                if "/" in win_os:
                    for part in win_os.split("/"):
                        votes[part] = votes.get(part, 0) + _WEIGHT_WINDOW / 2
                else:
                    votes[win_os] = votes.get(win_os, 0) + _WEIGHT_WINDOW
                evidence_items.append(
                    Evidence(kind="tcp_window", data=f"Window={window_size} -> {win_os}")
                )

        # ── 3. Service banner correlation ────────────────────────────
        for banner in banners:
            banner_lower = banner.lower()
            for keyword, bos_family, bos_version in _BANNER_OS_KEYWORDS:
                if keyword in banner_lower:
                    votes[bos_family] = votes.get(bos_family, 0) + _WEIGHT_BANNER
                    if bos_version:
                        os_version = bos_version
                    evidence_items.append(
                        Evidence(
                            kind="banner",
                            data=f"'{keyword}' in banner -> {bos_family}"
                                 + (f" ({bos_version})" if bos_version else ""),
                        )
                    )
                    break  # One match per banner is enough.

        # ── 4. Port combination heuristics ───────────────────────────
        for required, pos_family, pos_hint in _PORT_COMBOS:
            if required.issubset(open_ports):
                votes[pos_family] = votes.get(pos_family, 0) + _WEIGHT_PORTS
                if pos_hint and not os_version:
                    os_version = pos_hint
                evidence_items.append(
                    Evidence(
                        kind="port_pattern",
                        data=f"Ports {sorted(required)} -> {pos_family}"
                             + (f" ({pos_hint})" if pos_hint else ""),
                    )
                )
                break  # Use highest-priority match only.

        if not votes:
            return None

        # Pick the winner.
        detected_os = max(votes, key=lambda k: votes[k])
        confidence = votes[detected_os]

        # ── Update Host model ────────────────────────────────────────
        host.os = detected_os
        if os_version:
            host.os_version = os_version

        # Persist to database.
        if ctx.db is not None:
            await ctx.db.insert_host(host)

        # Publish fact.
        await ctx.facts.add(
            "os.detected",
            {"os": detected_os, "os_version": os_version,
             "confidence": confidence},
            self.name,
            host_id=host.id,
        )

        finding = Finding(
            title=f"OS detected: {detected_os}"
                  + (f" ({os_version})" if os_version else "")
                  + f" on {host.ip}",
            description=(
                f"Operating system fingerprinting identified the host "
                f"{host.ip} as {detected_os}"
                + (f" ({os_version})" if os_version else "")
                + f" with confidence score {confidence:.0f}. "
                f"Based on {len(evidence_items)} signal(s)."
            ),
            severity=Severity.INFO,
            host_id=host.id,
            module_name=self.name,
            attack_technique_ids=self.attack_technique_ids,
            evidence=evidence_items,
        )

        if ctx.db is not None:
            await ctx.db.insert_finding(finding)

        return finding

    # ── TTL probing ──────────────────────────────────────────────────────

    async def _probe_ttl(self, ip: str, open_ports: set[int]) -> int | None:
        """Try to determine the TTL of packets from *ip*.

        Attempts raw socket first (requires elevated privileges).  Falls
        back to a ctypes-based approach on Windows (SIO_RCVALL or
        getsockopt).  If neither works, returns None and the module
        relies on other heuristics.
        """
        port = self._pick_probe_port(open_ports)
        if port is None:
            return None

        # Try platform-specific methods.
        if platform.system() == "Windows":
            ttl = await self._ttl_via_connect_windows(ip, port)
        else:
            ttl = await self._ttl_via_connect_unix(ip, port)

        return ttl

    @staticmethod
    def _pick_probe_port(open_ports: set[int]) -> int | None:
        """Pick the best port to probe for TTL.  Prefer common services."""
        preferred = [80, 443, 22, 21, 25, 8080, 8443]
        for p in preferred:
            if p in open_ports:
                return p
        # Fall back to any open port.
        return next(iter(open_ports), None)

    async def _ttl_via_connect_windows(self, ip: str, port: int) -> int | None:
        """Windows: connect TCP and try to extract TTL via IP_TTL getsockopt."""
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._win_ttl_sync, ip, port),
                timeout=5.0,
            )
        except (TimeoutError, OSError):
            return None

    @staticmethod
    def _win_ttl_sync(ip: str, port: int) -> int | None:
        """Synchronous Windows TTL probe via raw socket or SIO_RCVALL.

        Windows does not expose the received TTL through a normal
        connected socket.  We attempt a raw IPPROTO_IP socket to
        capture the IP header.  If raw sockets are unavailable
        (no admin), we return None and rely on heuristics.
        """
        try:
            # Attempt a raw socket (requires Administrator).
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            raw.settimeout(4)
            raw.bind((socket.gethostbyname(socket.gethostname()), 0))
            # Enable receiving all IP packets (promiscuous).
            SIO_RCVALL = 0x98000001
            raw.ioctl(SIO_RCVALL, 1)

            # Open a normal TCP connection to trigger a response.
            trigger = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            trigger.settimeout(3)
            try:
                trigger.connect((ip, port))
            except OSError:
                pass
            finally:
                trigger.close()

            # Read packets and look for one from the target IP.
            deadline_attempts = 20
            for _ in range(deadline_attempts):
                try:
                    pkt = raw.recv(65535)
                except TimeoutError:
                    break
                if len(pkt) < 20:
                    continue
                # IP header: source IP at offset 12-16.
                src_ip = socket.inet_ntoa(pkt[12:16])
                if src_ip == ip:
                    ttl = pkt[8]  # TTL field in IP header.
                    raw.ioctl(SIO_RCVALL, 0)
                    raw.close()
                    return ttl

            raw.ioctl(SIO_RCVALL, 0)
            raw.close()
        except (OSError, PermissionError):
            # No raw socket access — expected for non-admin users.
            pass
        return None

    async def _ttl_via_connect_unix(self, ip: str, port: int) -> int | None:
        """Unix: connect TCP and read TTL via IP_TTL getsockopt."""
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._unix_ttl_sync, ip, port),
                timeout=5.0,
            )
        except (TimeoutError, OSError):
            return None

    @staticmethod
    def _unix_ttl_sync(ip: str, port: int) -> int | None:
        """Synchronous Unix TTL probe.

        On Linux, IP_RECVTTL or IP_TTL on the connected socket gives us
        the last received TTL.  We also attempt a raw socket fallback.
        """
        # Method 1: IP_TTL on connected socket (some kernels expose
        # received TTL this way).
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            # IP_TTL (level=IPPROTO_IP=0, opt=IP_TTL=2) on the
            # connected socket returns the *received* TTL on Linux.
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
            if 1 <= ttl <= 255:
                return ttl
        except OSError:
            pass

        # Method 2: raw socket (requires CAP_NET_RAW or root).
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw.settimeout(4)

            # Send SYN via a normal socket.
            trigger = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            trigger.settimeout(3)
            try:
                trigger.connect((ip, port))
            except OSError:
                pass
            finally:
                trigger.close()

            for _ in range(20):
                try:
                    pkt = raw.recv(65535)
                except TimeoutError:
                    break
                if len(pkt) < 20:
                    continue
                src_ip = socket.inet_ntoa(pkt[12:16])
                if src_ip == ip:
                    ttl = pkt[8]
                    raw.close()
                    return ttl

            raw.close()
        except (OSError, PermissionError):
            pass

        return None

    # ── TCP window size probing ──────────────────────────────────────────

    async def _probe_window_size(self, ip: str, open_ports: set[int]) -> int | None:
        """Attempt to read the TCP window size from a SYN-ACK response.

        This requires raw sockets.  Returns None if unavailable.
        """
        port = self._pick_probe_port(open_ports)
        if port is None:
            return None

        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._window_size_sync, ip, port),
                timeout=5.0,
            )
        except (TimeoutError, OSError):
            return None

    @staticmethod
    def _window_size_sync(ip: str, port: int) -> int | None:
        """Read TCP window size from the SYN-ACK packet via raw socket."""
        try:
            if platform.system() == "Windows":
                raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                raw.settimeout(4)
                raw.bind((socket.gethostbyname(socket.gethostname()), 0))
                SIO_RCVALL = 0x98000001
                raw.ioctl(SIO_RCVALL, 1)
            else:
                raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                raw.settimeout(4)

            # Trigger a connection.
            trigger = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            trigger.settimeout(3)
            try:
                trigger.connect((ip, port))
            except OSError:
                pass
            finally:
                trigger.close()

            for _ in range(20):
                try:
                    pkt = raw.recv(65535)
                except TimeoutError:
                    break
                if len(pkt) < 40:
                    continue
                src_ip = socket.inet_ntoa(pkt[12:16])
                if src_ip != ip:
                    continue
                # IP header length (IHL).
                ihl = (pkt[0] & 0x0F) * 4
                if len(pkt) < ihl + 20:
                    continue
                # TCP header starts at offset ihl.
                tcp_header = pkt[ihl:ihl + 20]
                # TCP window size is at bytes 14-16 in the TCP header.
                window_size = struct.unpack("!H", tcp_header[14:16])[0]

                if platform.system() == "Windows":
                    raw.ioctl(SIO_RCVALL, 0)
                raw.close()
                return window_size

            if platform.system() == "Windows":
                raw.ioctl(SIO_RCVALL, 0)
            raw.close()
        except (OSError, PermissionError):
            pass
        return None
