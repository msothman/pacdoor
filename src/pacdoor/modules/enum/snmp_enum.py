"""SNMP enumeration — community string brute-force and system info extraction."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING

from pacdoor.core.models import (
    Evidence,
    Finding,
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Default community strings to test, ordered by likelihood.
_COMMUNITY_STRINGS: list[str] = [
    "public",
    "private",
    "community",
    "manager",
    "admin",
    "default",
    "snmp",
]

# Well-known OIDs for system info (SNMPv1/v2c).
_OID_SYSDESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
_OID_SYSNAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
_OID_SYSLOCATION = (1, 3, 6, 1, 2, 1, 1, 6, 0)
_OID_SYSCONTACT = (1, 3, 6, 1, 2, 1, 1, 4, 0)


# ── Minimal BER / ASN.1 encoding for SNMPv1/v2c GET ─────────────────
# We craft raw SNMP packets to avoid any library dependency.


def _encode_length(length: int) -> bytes:
    """BER definite-length encoding."""
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _encode_integer(value: int) -> bytes:
    """BER INTEGER."""
    if value == 0:
        payload = b"\x00"
    else:
        payload = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return b"\x02" + _encode_length(len(payload)) + payload


def _encode_octet_string(value: bytes) -> bytes:
    """BER OCTET STRING."""
    return b"\x04" + _encode_length(len(value)) + value


def _encode_oid(oid: tuple[int, ...]) -> bytes:
    """BER OBJECT IDENTIFIER."""
    # First two components are encoded as 40*X + Y
    body = bytes([40 * oid[0] + oid[1]])
    for component in oid[2:]:
        if component < 128:
            body += bytes([component])
        else:
            # Multi-byte encoding
            parts: list[int] = []
            val = component
            parts.append(val & 0x7F)
            val >>= 7
            while val:
                parts.append(0x80 | (val & 0x7F))
                val >>= 7
            body += bytes(reversed(parts))
    return b"\x06" + _encode_length(len(body)) + body


def _encode_null() -> bytes:
    return b"\x05\x00"


def _encode_sequence(contents: bytes) -> bytes:
    return b"\x30" + _encode_length(len(contents)) + contents


def _build_snmp_get(community: str, oid: tuple[int, ...], request_id: int = 1) -> bytes:
    """Build a complete SNMPv1 GET-request packet."""
    # VarBind: SEQUENCE { OID, NULL }
    varbind = _encode_sequence(_encode_oid(oid) + _encode_null())
    # VarBindList: SEQUENCE { VarBind }
    varbind_list = _encode_sequence(varbind)
    # PDU: GetRequest-PDU (0xA0) { request-id, error-status(0), error-index(0), varbind-list }
    pdu_body = (
        _encode_integer(request_id)
        + _encode_integer(0)  # error-status
        + _encode_integer(0)  # error-index
        + varbind_list
    )
    pdu = b"\xa0" + _encode_length(len(pdu_body)) + pdu_body
    # Message: SEQUENCE { version(0=v1), community, pdu }
    message_body = (
        _encode_integer(0)  # version SNMPv1
        + _encode_octet_string(community.encode("ascii"))
        + pdu
    )
    return _encode_sequence(message_body)


def _decode_snmp_response(data: bytes) -> str | None:
    """Extract the first OCTET STRING value from an SNMP response.

    This is a minimal parser — enough to pull out sysDescr-style strings
    from a well-formed response.  Returns None on any parse error.
    """
    try:
        # Walk through the response to find the value in the VarBind.
        # The response structure is:
        #   SEQUENCE { version, community, GetResponse-PDU {
        #     request-id, error-status, error-index,
        #     SEQUENCE { SEQUENCE { OID, value } }
        #   }}
        # We look for the last OCTET STRING (tag 0x04) that appears
        # after an OID (tag 0x06).
        idx = 0
        last_octet: str | None = None
        found_oid = False
        while idx < len(data) - 2:
            tag = data[idx]
            idx += 1
            # Decode length
            length_byte = data[idx]
            idx += 1
            if length_byte & 0x80:
                num_bytes = length_byte & 0x7F
                length = int.from_bytes(data[idx:idx + num_bytes], "big")
                idx += num_bytes
            else:
                length = length_byte

            if tag == 0x06:  # OID
                found_oid = True
                idx += length
            elif tag == 0x04 and found_oid:  # OCTET STRING after OID
                if idx + length <= len(data):
                    last_octet = data[idx:idx + length].decode("utf-8", errors="replace")
                idx += length
            elif tag in (0x30, 0xA2):  # SEQUENCE or GetResponse — descend
                continue
            else:
                idx += length

        return last_octet
    except Exception:
        return None


def _snmp_get(
    ip: str,
    port: int,
    community: str,
    oid: tuple[int, ...],
    timeout: float = 3.0,
) -> str | None:
    """Send an SNMP GET and return the string value, or None on failure."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        packet = _build_snmp_get(community, oid)
        sock.sendto(packet, (ip, port))
        data, _ = sock.recvfrom(4096)
        return _decode_snmp_response(data)
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


def _try_community(ip: str, port: int, community: str, timeout: float = 3.0) -> bool:
    """Test whether a community string works by requesting sysDescr."""
    return _snmp_get(ip, port, community, _OID_SYSDESCR, timeout) is not None


def _get_system_info(
    ip: str,
    port: int,
    community: str,
    timeout: float = 3.0,
) -> dict[str, str | None]:
    """Retrieve basic system info OIDs using a known-good community string."""
    return {
        "sysDescr": _snmp_get(ip, port, community, _OID_SYSDESCR, timeout),
        "sysName": _snmp_get(ip, port, community, _OID_SYSNAME, timeout),
        "sysLocation": _snmp_get(ip, port, community, _OID_SYSLOCATION, timeout),
        "sysContact": _snmp_get(ip, port, community, _OID_SYSCONTACT, timeout),
    }


# Community strings that grant write access — higher severity.
_WRITE_COMMUNITIES = {"private", "manager", "admin"}


# ── Module ───────────────────────────────────────────────────────────


class SNMPEnumModule(BaseModule):
    name = "enum.snmp_enum"
    description = "SNMP enumeration — community string brute-force and system info"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046"]
    required_facts = ["service.snmp"]
    produced_facts = [
        "snmp.community",
        "snmp.info",
    ]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        snmp_facts = await ctx.facts.get_all("service.snmp")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in snmp_facts:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 161
            targets.append((host_id, ip, port_num))

        for host_id, ip, port_num in targets:
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
        """Probe community strings and extract system info for a single host."""

        valid_communities: list[str] = []

        # ── 1. Brute-force community strings ─────────────────────────
        for community in _COMMUNITY_STRINGS:
            works = await asyncio.to_thread(_try_community, ip, port, community)
            if works:
                valid_communities.append(community)

                await ctx.facts.add(
                    "snmp.community",
                    {"host": ip, "port": port, "community": community},
                    self.name,
                    host_id=host_id,
                )

                is_write = community in _WRITE_COMMUNITIES
                severity = Severity.CRITICAL if is_write else Severity.HIGH
                label = "read-write" if is_write else "read-only"

                findings.append(Finding(
                    title=f"SNMP default community string '{community}' on {ip}",
                    description=(
                        f"Host {ip}:{port} responds to SNMP queries with the "
                        f"default community string '{community}' ({label}). "
                        + (
                            "Write-capable community strings allow an attacker to "
                            "modify device configuration remotely."
                            if is_write
                            else "This exposes system information and may reveal "
                            "network topology, running processes, and interfaces."
                        )
                    ),
                    severity=severity,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1046"],
                    evidence=[Evidence(
                        kind="snmp_community",
                        data=(
                            f"Community string '{community}' accepted on "
                            f"{ip}:{port} ({label})"
                        ),
                    )],
                    remediation=(
                        f"Change the SNMP community string from the default "
                        f"'{community}' to a strong, random value. Consider "
                        "migrating to SNMPv3 with authentication and encryption. "
                        "Restrict SNMP access to management networks via ACLs."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1046/",
                    ],
                ))

        if not valid_communities:
            return

        # ── 2. Extract system information using first valid community
        best_community = valid_communities[0]
        sys_info = await asyncio.to_thread(
            _get_system_info, ip, port, best_community,
        )

        # Filter out None values
        populated = {k: v for k, v in sys_info.items() if v is not None}
        if populated:
            await ctx.facts.add(
                "snmp.info",
                {"host": ip, "port": port, "community": best_community, **populated},
                self.name,
                host_id=host_id,
            )

            info_lines = "\n".join(f"  {k}: {v}" for k, v in populated.items())
            findings.append(Finding(
                title=f"SNMP system information disclosed on {ip}",
                description=(
                    f"Retrieved system information from {ip}:{port} using "
                    f"community string '{best_community}'. This may reveal "
                    "OS version, hostname, and network topology details useful "
                    "for further enumeration."
                ),
                severity=Severity.LOW,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="snmp_sysinfo",
                    data=f"SNMP system info from {ip}:\n{info_lines}",
                )],
                remediation=(
                    "Restrict SNMP access to authorized management stations "
                    "and use SNMPv3 with strong authentication."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))
