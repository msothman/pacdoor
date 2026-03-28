"""Host discovery — ICMP/TCP ping sweep to find live hosts in a CIDR range."""

from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv4Network
from typing import TYPE_CHECKING

from pacdoor.core.models import Finding, Host, Phase, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Common ports for TCP ping when ICMP is blocked
PING_PORTS = [80, 443, 22, 445, 3389]

# Maximum IPs to probe concurrently within a single batch.
# Prevents creating hundreds of thousands of coroutines at once
# (e.g. a /16 has 65 534 hosts).
_BATCH_SIZE = 1000


class HostDiscoveryModule(BaseModule):
    name = "recon.host_discovery"
    description = "Discover live hosts via TCP ping sweep"
    phase = Phase.RECON
    # T1018 = Remote System Discovery (host sweep).
    # T1046 = Network Service Scanning (port-level), used by port_scan instead.
    attack_technique_ids = ["T1018"]
    required_facts = ["cidr"]
    produced_facts = ["host"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        cidrs = await ctx.facts.get_values("cidr")
        findings: list[Finding] = []
        discovered = 0
        sem = asyncio.Semaphore(200)

        async def check_host(ip_str: str) -> bool:
            """Return True if the host is alive."""
            async with sem:
                return await self._tcp_ping(ip_str)

        # Collect all IPs across all CIDRs, then process in batches
        # to avoid creating hundreds of thousands of coroutines at once.
        all_ips: list[str] = []
        for cidr_str in cidrs:
            network = IPv4Network(cidr_str, strict=False)
            for addr in network.hosts():
                all_ips.append(str(addr))

        # Process in batches of _BATCH_SIZE
        for batch_start in range(0, len(all_ips), _BATCH_SIZE):
            batch = all_ips[batch_start : batch_start + _BATCH_SIZE]
            results = await asyncio.gather(
                *(check_host(ip) for ip in batch)
            )
            for ip_str, alive in zip(batch, results, strict=False):
                if alive:
                    host = Host(ip=ip_str)
                    await ctx.facts.add("host", host, self.name)
                    discovered += 1

        if discovered > 0:
            findings.append(Finding(
                title=f"Host discovery: {discovered} live hosts found",
                description=f"TCP ping sweep across {len(cidrs)} CIDR range(s)",
                severity=Severity.INFO,
                module_name=self.name,
                attack_technique_ids=["T1018"],
            ))
        return findings

    async def _tcp_ping(self, ip: str) -> bool:
        """Try TCP connect to common ports. If any succeed OR refuse, host is alive.

        A ConnectionRefusedError (TCP RST) means the host IS reachable but
        the port is closed — the host is still alive.  Only timeouts and
        unreachable errors indicate the host is down.
        """
        for port in PING_PORTS:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=1.5
                )
                writer.close()
                await writer.wait_closed()
                return True
            except ConnectionRefusedError:
                # RST received — host IS alive, port just closed
                return True
            except (TimeoutError, OSError):
                continue
        return False
