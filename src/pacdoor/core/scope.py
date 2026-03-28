"""Hard scope enforcement — never scan outside the defined boundary.

The ScopeEnforcer validates every target IP before any network activity.
It supports IPv4/IPv6 addresses, CIDR ranges, and hostnames.  Exclusions
take priority over inclusions (a host in both lists is out of scope).

Integration points:
  - Engine._seed_targets():   validate all user-provided targets
  - FactStore.add():          when adding a "host" fact, validate IP
  - Lateral movement:         before connecting to a new host
  - Port scan:                skip excluded IPs
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path

log = logging.getLogger(__name__)

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _safe_addr_in_net(addr: _Address, net: _Network) -> bool:
    """Check if addr is in net, handling mixed IPv4/IPv6 gracefully."""
    try:
        return addr in net
    except TypeError:
        return False


class ScopeEnforcer:
    """Immutable scope boundary checker.

    Parameters
    ----------
    in_scope:
        List of IPs, CIDRs, or hostnames that define the allowed scope.
    exclude:
        List of IPs, CIDRs, or hostnames to exclude (takes priority).
    """

    def __init__(
        self,
        in_scope: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        self._in_networks: list[_Network] = []
        self._in_ips: set[str] = set()
        self._in_hostnames: set[str] = set()

        self._ex_networks: list[_Network] = []
        self._ex_ips: set[str] = set()
        self._ex_hostnames: set[str] = set()

        for entry in in_scope or []:
            self._parse_into(entry, self._in_networks, self._in_ips, self._in_hostnames)
        for entry in exclude or []:
            self._parse_into(entry, self._ex_networks, self._ex_ips, self._ex_hostnames)

        log.info(
            "Scope enforcer initialised: %d in-scope entries, %d exclusions",
            len(self._in_networks) + len(self._in_ips) + len(self._in_hostnames),
            len(self._ex_networks) + len(self._ex_ips) + len(self._ex_hostnames),
        )

    # ── Public API ────────────────────────────────────────────────────

    def is_in_scope(self, ip: str) -> bool:
        """Return True if *ip* is within the allowed scope.

        An IP must match at least one in-scope entry AND must NOT match
        any exclusion entry.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Not a valid IP — treat as hostname lookup
            return self._check_hostname(ip)

        # Exclusions take priority
        if self._is_excluded_addr(addr, ip):
            return False

        return self._is_included_addr(addr, ip)

    def validate(self, target: str) -> bool:
        """Validate a target string (IP, CIDR, or hostname).

        For CIDRs, checks that the entire range falls within scope.
        For hostnames, resolves to IP first.
        """
        # Try as IP address first
        try:
            ipaddress.ip_address(target)
            return self.is_in_scope(target)
        except ValueError:
            pass

        # Try as CIDR
        try:
            network = ipaddress.ip_network(target, strict=False)
            # A CIDR is in scope if every address is in scope.
            # For efficiency, check that the network overlaps with at
            # least one in-scope network and does NOT overlap with any
            # exclusion.
            if self._cidr_excluded(network):
                return False
            return self._cidr_included(network)
        except ValueError:
            pass

        # Hostname — resolve and check
        return self._check_hostname(target)

    @staticmethod
    def from_file(path: Path) -> list[str]:
        """Read scope entries from a file (one CIDR/IP/hostname per line).

        Blank lines and lines starting with ``#`` are ignored.
        """
        entries: list[str] = []
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                entries.append(stripped)
        return entries

    # ── Internals ─────────────────────────────────────────────────────

    @staticmethod
    def _parse_into(
        entry: str,
        networks: list[_Network],
        ips: set[str],
        hostnames: set[str],
    ) -> None:
        """Parse a single scope entry into the appropriate collection."""
        # Try IP address
        try:
            addr = ipaddress.ip_address(entry)
            ips.add(str(addr))
            return
        except ValueError:
            pass

        # Try CIDR
        try:
            net = ipaddress.ip_network(entry, strict=False)
            networks.append(net)
            return
        except ValueError:
            pass

        # Fall back to hostname
        hostnames.add(entry.lower())

    def _is_included_addr(self, addr: _Address, ip_str: str) -> bool:
        """Check if address matches any in-scope entry."""
        if ip_str in self._in_ips:
            return True
        return any(_safe_addr_in_net(addr, net) for net in self._in_networks)

    def _is_excluded_addr(self, addr: _Address, ip_str: str) -> bool:
        """Check if address matches any exclusion entry."""
        if ip_str in self._ex_ips:
            return True
        return any(_safe_addr_in_net(addr, net) for net in self._ex_networks)

    def _cidr_included(self, network: _Network) -> bool:
        """Check if a CIDR range is fully covered by in-scope entries."""
        # /32 (IPv4) and /128 (IPv6) have no hosts() entries — handle specially
        if network.num_addresses == 1:
            addr_str = str(network.network_address)
            if addr_str in self._in_ips:
                return True
            addr = network.network_address
            for net in self._in_networks:
                try:
                    if addr in net:
                        return True
                except TypeError:
                    continue
            return False
        for net in self._in_networks:
            try:
                if network.subnet_of(net):
                    return True
            except TypeError:
                continue
        # Also check if ALL individual addresses are in the IP set
        # (only practical for small ranges)
        if network.num_addresses <= 256:
            return all(
                str(addr) in self._in_ips
                or any(_safe_addr_in_net(addr, net) for net in self._in_networks)
                for addr in network.hosts()
            )
        return False

    def _cidr_excluded(self, network: _Network) -> bool:
        """Check if any part of a CIDR range overlaps with exclusions."""
        for net in self._ex_networks:
            try:
                if network.overlaps(net):
                    return True
            except TypeError:
                continue
        return False

    def _check_hostname(self, hostname: str) -> bool:
        """Resolve hostname and check if its IP is in scope."""
        lower = hostname.lower()

        # Check hostname exclusions first
        if lower in self._ex_hostnames:
            return False

        # Check hostname inclusions
        if lower in self._in_hostnames:
            return True

        # Resolve to IP and check
        try:
            results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            if results:
                resolved_ip = results[0][4][0]
                return self.is_in_scope(resolved_ip)
        except (socket.gaierror, OSError):
            pass

        return False
