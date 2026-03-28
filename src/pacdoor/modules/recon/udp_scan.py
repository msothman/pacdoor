"""UDP port scanner -- discovers services that only listen on UDP.

UDP scanning is fundamentally different from TCP: a sent packet may
receive a response (open), an ICMP unreachable (closed), or no response
at all (open|filtered).  This module targets the top 20 most important
UDP ports and sends protocol-specific probes for accurate service
identification.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

from pacdoor.core.models import (
    Finding,
    Host,
    Phase,
    Port,
    PortState,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Top 20 UDP ports ────────────────────────────────────────────────────

TOP_UDP_PORTS: list[int] = [
    53,     # DNS
    67,     # DHCP
    69,     # TFTP
    123,    # NTP
    137,    # NetBIOS Name Service
    138,    # NetBIOS Datagram
    161,    # SNMP
    162,    # SNMP Trap
    443,    # QUIC/DTLS
    500,    # IKE/VPN
    514,    # Syslog
    520,    # RIP
    623,    # IPMI
    1434,   # MSSQL Browser
    1900,   # SSDP/UPnP
    4500,   # IPsec NAT-T
    5060,   # SIP
    5353,   # mDNS
    11211,  # Memcached
]

# Map UDP ports to service fact types.
UDP_SERVICE_MAP: dict[int, str] = {
    53: "dns",
    67: "dhcp",
    69: "tftp",
    123: "ntp",
    137: "netbios",
    138: "netbios",
    161: "snmp",
    162: "snmp",
    443: "quic",
    500: "ike",
    514: "syslog",
    520: "rip",
    623: "ipmi",
    1434: "mssql_browser",
    1900: "ssdp",
    4500: "ipsec",
    5060: "sip",
    5353: "mdns",
    11211: "memcached",
}

# ── Protocol-specific probes ────────────────────────────────────────────


def _build_dns_probe() -> bytes:
    """DNS query for version.bind (CH TXT) -- standard DNS fingerprint."""
    # Transaction ID: 0x1337
    # Flags: standard query, recursion desired
    # Questions: 1, Answers: 0, Authority: 0, Additional: 0
    header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
    # QNAME: version.bind
    qname = (
        b"\x07version\x04bind\x00"
    )
    # QTYPE: TXT (16), QCLASS: CH (3)
    question = struct.pack(">HH", 16, 3)
    return header + qname + question


def _build_snmp_probe() -> bytes:
    """SNMP GET request for sysDescr.0 with 'public' community string.

    ASN.1 BER-encoded SNMPv1 GET-REQUEST.
    """
    # Pre-built SNMPv1 GET sysDescr.0 with community 'public'
    # This is a well-known, minimal SNMP GET packet.
    return bytes([
        0x30, 0x29,                                     # SEQUENCE (41 bytes)
        0x02, 0x01, 0x00,                               # INTEGER: version=0 (SNMPv1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING: "public"
        0xa0, 0x1c,                                     # GET-REQUEST (28 bytes)
        0x02, 0x04, 0x01, 0x02, 0x03, 0x04,             # INTEGER: request-id
        0x02, 0x01, 0x00,                               # INTEGER: error-status=0
        0x02, 0x01, 0x00,                               # INTEGER: error-index=0
        0x30, 0x0e,                                     # SEQUENCE: varbind list
        0x30, 0x0c,                                     # SEQUENCE: varbind
        0x06, 0x08,                                     # OID (8 bytes)
        0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # 1.3.6.1.2.1.1.1.0 (sysDescr)
        0x05, 0x00,                                     # NULL value
    ])


def _build_ntp_probe() -> bytes:
    """NTP version query (mode 3, version 3)."""
    # Leap=0, Version=3, Mode=3 (client), rest zeros
    packet = bytearray(48)
    packet[0] = 0x1B  # LI=0, VN=3, Mode=3
    return bytes(packet)


def _build_ssdp_probe() -> bytes:
    """SSDP M-SEARCH discovery request."""
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"ST: ssdp:all\r\n"
        b"MX: 2\r\n"
        b"\r\n"
    )


def _build_sip_probe(target_ip: str) -> bytes:
    """SIP OPTIONS probe."""
    return (
        f"OPTIONS sip:test@{target_ip} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {target_ip};branch=z9hG4bK-probe\r\n"
        f"From: <sip:probe@{target_ip}>;tag=probe1\r\n"
        f"To: <sip:test@{target_ip}>\r\n"
        f"Call-ID: probe-{target_ip}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


def _build_netbios_probe() -> bytes:
    """NetBIOS Name Service NBSTAT query (node status request)."""
    # Transaction ID: 0x1337
    # Flags: 0x0000 (query)
    # Questions: 1
    header = struct.pack(">HHHHHH", 0x1337, 0x0000, 1, 0, 0, 0)
    # NBSTAT query: name = * (wildcard), padded to 16 bytes, half-ASCII encoded
    # Wildcard name: 0x20 repeated 32 times (encoding of "*" + padding)
    name = b"\x20" + b"\x43\x4b" * 15 + b"\x41\x41\x00"
    # NBSTAT type (0x0021), class IN (0x0001)
    question = struct.pack(">HH", 0x0021, 0x0001)
    return header + name + question


def _build_mssql_browser_probe() -> bytes:
    """MSSQL Browser Service query -- request instance list."""
    return b"\x02"  # Single byte 0x02 = CLNT_UCAST_EX


def _build_memcached_probe() -> bytes:
    """Memcached stats command."""
    return b"stats\r\n"


def _build_ipmi_probe() -> bytes:
    """IPMI RMCP Get Channel Authentication Capabilities."""
    # RMCP header + ASF presence ping
    return bytes([
        0x06, 0x00, 0xff, 0x07,  # RMCP header: version 6, reserved, seq 0xff, class ASF
        0x00, 0x00, 0x00, 0x00,  # Session ID
        0x00, 0x00, 0x00, 0x00,  # Sequence number
        0x20, 0x18, 0xc8, 0x81,  # ASF payload: IANA, message type, tag, reserved
        0x00, 0x38, 0x8e, 0x04,  # Get channel auth capabilities
        0xb5,                    # Checksum
    ])


def _get_probe(port: int, target_ip: str) -> bytes:
    """Get the protocol-specific probe for a given UDP port.

    Returns a generic empty payload for ports without a specific probe.
    """
    if port == 53:
        return _build_dns_probe()
    if port == 161 or port == 162:
        return _build_snmp_probe()
    if port == 123:
        return _build_ntp_probe()
    if port == 1900:
        return _build_ssdp_probe()
    if port == 5060:
        return _build_sip_probe(target_ip)
    if port == 137:
        return _build_netbios_probe()
    if port == 1434:
        return _build_mssql_browser_probe()
    if port == 11211:
        return _build_memcached_probe()
    if port == 623:
        return _build_ipmi_probe()
    if port == 5353:
        # mDNS: use same DNS probe format but multicast
        return _build_dns_probe()
    # For ports without specific probes, send a null byte
    return b"\x00"


def _parse_banner(port: int, data: bytes) -> str:
    """Best-effort extraction of a readable banner from the response."""
    if not data:
        return ""
    try:
        if port == 53 or port == 5353:
            return f"DNS response ({len(data)} bytes)"
        if port == 161 or port == 162:
            # Try to extract sysDescr from SNMP response
            text = data.decode("utf-8", errors="replace")
            # Rough extraction of printable content
            printable = "".join(c for c in text if c.isprintable() or c == " ")
            return printable[:200] if printable else f"SNMP response ({len(data)} bytes)"
        if port == 123:
            return f"NTP response ({len(data)} bytes)"
        if port == 1900:
            text = data.decode("utf-8", errors="replace")
            return text[:200]
        if port == 5060:
            text = data.decode("utf-8", errors="replace")
            # Extract first line (SIP status)
            first_line = text.split("\r\n")[0] if "\r\n" in text else text[:80]
            return first_line
        if port == 137:
            return f"NetBIOS response ({len(data)} bytes)"
        if port == 1434:
            text = data.decode("utf-8", errors="replace")
            return text[:200]
        if port == 11211:
            text = data.decode("utf-8", errors="replace")
            return text[:200]
        if port == 623:
            return f"IPMI response ({len(data)} bytes)"
        # Generic
        text = data.decode("utf-8", errors="replace")
        printable = "".join(c for c in text if c.isprintable() or c == " ")
        return printable[:200] if printable else f"Response ({len(data)} bytes)"
    except Exception:
        return f"Response ({len(data)} bytes)"


# ── Timeout and concurrency ─────────────────────────────────────────────

_UDP_TIMEOUT = 3.0   # seconds per port (UDP needs longer timeouts)
_CONCURRENCY = 50    # concurrent probes


# ── Module ───────────────────────────────────────────────────────────────


class UDPScanModule(BaseModule):
    """UDP port scanner targeting the top 20 most important UDP services."""

    name = "recon.udp_scan"
    description = "UDP scan on discovered hosts (top 20 UDP ports)"
    phase = Phase.RECON
    attack_technique_ids = ["T1046"]
    required_facts = ["host"]
    produced_facts = ["port.open", "service.*"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        hosts = await ctx.facts.get_values("host")
        findings: list[Finding] = []
        sem = asyncio.Semaphore(_CONCURRENCY)
        total_open = 0

        async def scan_udp_port(host: Host, port_num: int) -> None:
            nonlocal total_open
            async with sem:
                state, banner = await self._probe_port(host.ip, port_num)
                if state != PortState.OPEN:
                    return

                svc_name = UDP_SERVICE_MAP.get(port_num)
                port = Port(
                    host_id=host.id,
                    port=port_num,
                    protocol="udp",
                    state=PortState.OPEN,
                    service_name=svc_name,
                    banner=banner or None,
                )
                await ctx.facts.add(
                    "port.open", port, self.name, host_id=host.id,
                )

                if ctx.db is not None:
                    await ctx.db.insert_port(port)

                total_open += 1

                # Add service-specific facts for the planner
                if svc_name:
                    await ctx.facts.add(
                        f"service.{svc_name}", port, self.name,
                        host_id=host.id,
                    )

        tasks = []
        for host in hosts:
            for port_num in TOP_UDP_PORTS:
                tasks.append(scan_udp_port(host, port_num))

        await asyncio.gather(*tasks)

        if total_open > 0:
            findings.append(Finding(
                title=(
                    f"UDP scan: {total_open} open ports "
                    f"across {len(hosts)} hosts"
                ),
                description=(
                    f"UDP probe scan on {len(TOP_UDP_PORTS)} ports "
                    f"with protocol-specific payloads"
                ),
                severity=Severity.INFO,
                module_name=self.name,
                attack_technique_ids=["T1046"],
            ))

        return findings

    @staticmethod
    async def _probe_port(
        ip: str,
        port_num: int,
    ) -> tuple[PortState, str]:
        """Send a UDP probe and classify the response.

        Returns (state, banner_text).
        """
        loop = asyncio.get_running_loop()
        probe_data = _get_probe(port_num, ip)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.settimeout(0)

        try:
            # Send the probe
            await loop.sock_sendto(sock, probe_data, (ip, port_num))

            # Wait for response with timeout
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096),
                    timeout=_UDP_TIMEOUT,
                )
                # Got a response -- port is definitively open
                banner = _parse_banner(port_num, data)
                return PortState.OPEN, banner
            except TimeoutError:
                # No response -- could be open|filtered or silently dropped.
                # We only report confirmed open (with response) to reduce
                # false positives. True UDP scans are inherently unreliable.
                return PortState.FILTERED, ""
            except OSError as e:
                # ICMP unreachable received (connection refused on UDP)
                # This means the port is definitively closed.
                err_str = str(e).lower()
                if "refused" in err_str or "unreachable" in err_str:
                    return PortState.CLOSED, ""
                return PortState.FILTERED, ""
        except OSError:
            return PortState.FILTERED, ""
        finally:
            sock.close()
