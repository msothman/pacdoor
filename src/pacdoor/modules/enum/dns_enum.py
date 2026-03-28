"""DNS enumeration — zone transfers, record queries, open resolver, DNSSEC."""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from pacdoor.core.models import Evidence, Finding, Phase, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Lazy-imported at first use so the module can still be loaded (and
# gracefully skipped) when dnspython is not installed.
_dns_available: bool | None = None
_dns: object | None = None
_dns_query: object | None = None
_dns_zone: object | None = None
_dns_rdatatype: object | None = None
_dns_resolver: object | None = None


def _ensure_dnspython() -> bool:
    """Try to import dnspython; cache the result."""
    global _dns_available, _dns, _dns_query, _dns_zone  # noqa: PLW0603
    global _dns_rdatatype, _dns_resolver  # noqa: PLW0603
    if _dns_available is not None:
        return _dns_available
    try:
        import dns as _d  # type: ignore[import-untyped]
        import dns.query as _dq  # type: ignore[import-untyped]
        import dns.rdatatype as _drt  # type: ignore[import-untyped]
        import dns.resolver as _dr  # type: ignore[import-untyped]
        import dns.zone as _dz  # type: ignore[import-untyped]

        _dns = _d
        _dns_query = _dq
        _dns_zone = _dz
        _dns_rdatatype = _drt
        _dns_resolver = _dr
        _dns_available = True
    except ImportError:
        log.warning("dnspython not installed — using raw socket DNS queries")
        _dns_available = False
    return _dns_available


# ── DNS record types ─────────────────────────────────────────────────

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV")

# DNS query type codes for raw packet construction
_QTYPE_MAP = {
    "A": 1, "NS": 2, "SOA": 6, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "AXFR": 252,
}

_DNS_TIMEOUT = 10


# ── Raw DNS packet helpers (fallback when dnspython unavailable) ─────


def _build_dns_query(domain: str, qtype: int, rd: bool = True) -> bytes:
    """Build a minimal DNS query packet."""
    import random

    txn_id = random.randint(0, 65535)
    flags = 0x0100 if rd else 0x0000  # RD bit
    header = struct.pack(">HHHHHH", txn_id, flags, 1, 0, 0, 0)

    # Encode QNAME
    qname = b""
    for label in domain.split("."):
        encoded = label.encode("ascii")
        qname += struct.pack("B", len(encoded)) + encoded
    qname += b"\x00"

    question = qname + struct.pack(">HH", qtype, 1)  # QCLASS=IN
    return header + question


def _parse_dns_response_count(data: bytes) -> int:
    """Return the ANCOUNT from a DNS response header."""
    if len(data) < 12:
        return 0
    return struct.unpack(">H", data[6:8])[0]


def _parse_dns_flags(data: bytes) -> int:
    """Return raw flags from a DNS response."""
    if len(data) < 12:
        return 0
    return struct.unpack(">H", data[2:4])[0]


async def _raw_udp_query(
    ip: str, port: int, domain: str, qtype: int, rd: bool = True,
) -> bytes | None:
    """Send a raw DNS query via UDP and return the response."""
    import socket

    packet = _build_dns_query(domain, qtype, rd=rd)

    def _do_query() -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_DNS_TIMEOUT)
        try:
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(4096)
            return data
        except (TimeoutError, OSError):
            return None
        finally:
            sock.close()

    return await asyncio.to_thread(_do_query)


async def _raw_tcp_query(
    ip: str, port: int, domain: str, qtype: int,
) -> bytes | None:
    """Send a raw DNS query via TCP (for AXFR). Returns the response."""
    packet = _build_dns_query(domain, qtype, rd=False)
    # TCP DNS messages are prefixed with 2-byte length
    tcp_packet = struct.pack(">H", len(packet)) + packet

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=_DNS_TIMEOUT,
        )
    except (TimeoutError, OSError):
        return None

    try:
        writer.write(tcp_packet)
        await writer.drain()

        # Read length prefix
        len_data = await asyncio.wait_for(
            reader.readexactly(2), timeout=_DNS_TIMEOUT,
        )
        msg_len = struct.unpack(">H", len_data)[0]

        # Read the full response
        data = await asyncio.wait_for(
            reader.readexactly(msg_len), timeout=_DNS_TIMEOUT,
        )
        return data
    except (TimeoutError, OSError, asyncio.IncompleteReadError):
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── Module ───────────────────────────────────────────────────────────


class DNSEnumModule(BaseModule):
    name = "enum.dns_enum"
    description = "DNS enumeration — zone transfers, records, open resolver, DNSSEC"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046", "T1590.002"]
    required_facts = ["service.dns"]
    produced_facts = ["dns.zone_transfer", "dns.records"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        dns_facts = await ctx.facts.get_all("service.dns")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []  # (host_id, ip, port)

        for fact in dns_facts:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 53
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
        """Run full DNS enumeration on a single host."""

        # Determine the domain to query.  Prefer hostname from the fact
        # store; fall back to reverse-lookup or the IP itself.
        domain = await self._get_domain(ctx, host_id, ip)

        if _ensure_dnspython():
            await self._enumerate_with_dnspython(
                ctx, findings, host_id, ip, port, domain,
            )
        else:
            await self._enumerate_raw(
                ctx, findings, host_id, ip, port, domain,
            )

    async def _get_domain(
        self, ctx: ModuleContext, host_id: str, ip: str,
    ) -> str:
        """Resolve a domain name for the target from available facts."""
        for host in await ctx.facts.get_values("host"):
            if host.id == host_id and host.hostname:
                return host.hostname
        # Fallback: use the IP as the query target
        return ip

    # ── dnspython implementation ─────────────────────────────────────

    async def _enumerate_with_dnspython(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        domain: str,
    ) -> None:
        """Full enumeration using dnspython."""

        # 1. Zone transfer (AXFR)
        await self._try_zone_transfer_dnspython(
            ctx, findings, host_id, ip, port, domain,
        )

        # 2. Record enumeration
        await self._query_records_dnspython(
            ctx, findings, host_id, ip, port, domain,
        )

        # 3. Open resolver check
        await self._check_open_resolver_dnspython(
            ctx, findings, host_id, ip, port,
        )

        # 4. DNSSEC check
        await self._check_dnssec_dnspython(
            ctx, findings, host_id, ip, port, domain,
        )

        # 5. Version disclosure (version.bind CHAOS TXT)
        await self._check_version_disclosure_dnspython(
            ctx, findings, host_id, ip, port,
        )

    async def _try_zone_transfer_dnspython(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        domain: str,
    ) -> None:
        """Attempt AXFR zone transfer using dnspython."""
        try:
            def _do_axfr() -> list[str]:
                zone = _dns_zone.from_xfr(  # type: ignore[union-attr]
                    _dns_query.xfr(ip, domain, port=port, lifetime=_DNS_TIMEOUT),  # type: ignore[union-attr]
                )
                records: list[str] = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(
                                f"{name}.{domain} {rdataset.rdtype.name} {rdata}"
                            )
                return records

            records = await asyncio.to_thread(_do_axfr)

            if records:
                await ctx.facts.add(
                    "dns.zone_transfer",
                    {
                        "host": ip,
                        "port": port,
                        "domain": domain,
                        "records": records[:500],  # cap for storage
                    },
                    self.name,
                    host_id=host_id,
                )

                record_sample = "\n".join(
                    f"  {r}" for r in records[:20]
                )
                truncated = (
                    f"\n  ... and {len(records) - 20} more records"
                    if len(records) > 20
                    else ""
                )

                findings.append(Finding(
                    title=f"DNS zone transfer allowed on {ip}:{port}",
                    description=(
                        f"DNS server {ip}:{port} permits AXFR zone transfer "
                        f"for domain '{domain}'. This exposes the entire DNS "
                        f"zone including all hostnames, IP addresses, mail "
                        f"servers, and internal infrastructure. "
                        f"{len(records)} record(s) extracted."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="dns_zone_transfer",
                        data=(
                            f"AXFR succeeded for {domain} on {ip}:{port}. "
                            f"{len(records)} records:\n"
                            f"{record_sample}{truncated}"
                        ),
                    )],
                    remediation=(
                        "Restrict zone transfers to authorized secondary DNS "
                        "servers only. In BIND: use 'allow-transfer { trusted; };'. "
                        "In Windows DNS: configure zone transfer restrictions "
                        "in the Zone Properties > Zone Transfers tab."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1590/002/",
                    ],
                ))

        except Exception:
            log.debug("dns_enum: AXFR failed for %s on %s:%d", domain, ip, port)

    async def _query_records_dnspython(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        domain: str,
    ) -> None:
        """Query common record types using dnspython."""
        all_records: dict[str, list[str]] = {}

        for rtype in _RECORD_TYPES:
            try:
                def _do_query(rt: str = rtype) -> list[str]:
                    resolver = _dns_resolver.Resolver()  # type: ignore[union-attr]
                    resolver.nameservers = [ip]
                    resolver.port = port
                    resolver.lifetime = _DNS_TIMEOUT
                    answers = resolver.resolve(domain, rt)
                    return [str(rdata) for rdata in answers]

                records = await asyncio.to_thread(_do_query)
                if records:
                    all_records[rtype] = records
            except Exception:
                continue

        if all_records:
            await ctx.facts.add(
                "dns.records",
                {
                    "host": ip,
                    "port": port,
                    "domain": domain,
                    "records": all_records,
                },
                self.name,
                host_id=host_id,
            )

            record_lines: list[str] = []
            for rtype, values in all_records.items():
                for val in values:
                    record_lines.append(f"  {rtype:6s} {val}")

            findings.append(Finding(
                title=f"DNS records for {domain} on {ip}:{port}",
                description=(
                    f"Queried {len(all_records)} record type(s) for domain "
                    f"'{domain}' via DNS server {ip}:{port}."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="dns_records",
                    data=f"DNS records for {domain}:\n"
                         + "\n".join(record_lines),
                )],
            ))

    async def _check_open_resolver_dnspython(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Check if the DNS server answers recursive queries for external domains."""
        try:
            def _do_check() -> bool:
                resolver = _dns_resolver.Resolver()  # type: ignore[union-attr]
                resolver.nameservers = [ip]
                resolver.port = port
                resolver.lifetime = _DNS_TIMEOUT
                # Query a well-known external domain
                answers = resolver.resolve("example.com", "A")
                return len(list(answers)) > 0

            is_open = await asyncio.to_thread(_do_check)

            if is_open:
                findings.append(Finding(
                    title=f"Open DNS resolver on {ip}:{port}",
                    description=(
                        f"DNS server {ip}:{port} answers recursive queries "
                        f"for external domains. Open resolvers can be abused "
                        f"for DNS amplification DDoS attacks and cache "
                        f"poisoning."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="dns_open_resolver",
                        data=(
                            f"Recursive query for example.com succeeded on "
                            f"{ip}:{port}"
                        ),
                    )],
                    remediation=(
                        "Disable recursion for external clients. In BIND: "
                        "set 'recursion no;' or restrict with "
                        "'allow-recursion { localhost; internal; };'. "
                        "In Windows DNS: disable recursion in the Advanced "
                        "tab of DNS server properties."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1046/",
                    ],
                ))

        except Exception:
            pass

    async def _check_dnssec_dnspython(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        domain: str,
    ) -> None:
        """Check if the domain has DNSSEC enabled (DNSKEY record)."""
        try:
            def _do_check() -> bool:
                resolver = _dns_resolver.Resolver()  # type: ignore[union-attr]
                resolver.nameservers = [ip]
                resolver.port = port
                resolver.lifetime = _DNS_TIMEOUT
                answers = resolver.resolve(domain, "DNSKEY")
                return len(list(answers)) > 0

            has_dnssec = await asyncio.to_thread(_do_check)

            if not has_dnssec:
                findings.append(Finding(
                    title=f"DNSSEC not enabled for {domain}",
                    description=(
                        f"Domain '{domain}' on DNS server {ip}:{port} does "
                        f"not have DNSSEC configured. Without DNSSEC, DNS "
                        f"responses can be spoofed or modified in transit."
                    ),
                    severity=Severity.LOW,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="dns_dnssec",
                        data=f"No DNSKEY record found for {domain} on {ip}:{port}",
                    )],
                    remediation=(
                        "Enable DNSSEC for the domain by generating zone "
                        "signing keys (ZSK/KSK) and publishing DS records "
                        "with the domain registrar. Use 'dnssec-enable yes;' "
                        "and 'dnssec-validation auto;' in BIND."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1590/002/",
                    ],
                ))

        except Exception:
            # Query failure (NXDOMAIN, timeout) — DNSSEC not present
            findings.append(Finding(
                title=f"DNSSEC not enabled for {domain}",
                description=(
                    f"Domain '{domain}' on DNS server {ip}:{port} does "
                    f"not have DNSSEC configured. Without DNSSEC, DNS "
                    f"responses can be spoofed or modified in transit."
                ),
                severity=Severity.LOW,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="dns_dnssec",
                    data=f"No DNSKEY record found for {domain} on {ip}:{port}",
                )],
                remediation=(
                    "Enable DNSSEC for the domain by generating zone "
                    "signing keys (ZSK/KSK) and publishing DS records "
                    "with the domain registrar."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1590/002/",
                ],
            ))

    async def _check_version_disclosure_dnspython(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Query version.bind TXT CHAOS for BIND version disclosure."""
        try:
            import dns.message  # type: ignore[import-untyped]
            import dns.name  # type: ignore[import-untyped]
            import dns.rdataclass  # type: ignore[import-untyped]
            import dns.rdatatype  # type: ignore[import-untyped]

            def _do_query() -> str | None:
                request = dns.message.make_query(
                    dns.name.from_text("version.bind"),
                    dns.rdatatype.TXT,
                    dns.rdataclass.CH,
                )
                response = _dns_query.udp(  # type: ignore[union-attr]
                    request, ip, port=port, timeout=_DNS_TIMEOUT,
                )
                for rrset in response.answer:
                    for rdata in rrset:
                        return str(rdata)
                return None

            version = await asyncio.to_thread(_do_query)

            if version:
                findings.append(Finding(
                    title=f"DNS version disclosure on {ip}:{port}",
                    description=(
                        f"DNS server {ip}:{port} discloses its version via "
                        f"version.bind CHAOS TXT query: {version}. This "
                        f"information helps attackers identify specific "
                        f"software versions and known vulnerabilities."
                    ),
                    severity=Severity.LOW,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="dns_version",
                        data=f"version.bind CHAOS TXT: {version}",
                    )],
                    remediation=(
                        "Hide the DNS server version. In BIND: set "
                        "'version \"none\";' or 'version \"not disclosed\";' "
                        "in the options block."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1046/",
                    ],
                ))

        except Exception:
            pass

    # ── Raw socket fallback implementation ────────────────────────────

    async def _enumerate_raw(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        domain: str,
    ) -> None:
        """Enumeration using raw DNS packets when dnspython is unavailable."""

        # 1. Zone transfer (AXFR) via TCP
        await self._try_zone_transfer_raw(
            ctx, findings, host_id, ip, port, domain,
        )

        # 2. Record queries via UDP
        await self._query_records_raw(
            ctx, findings, host_id, ip, port, domain,
        )

        # 3. Open resolver check
        await self._check_open_resolver_raw(
            ctx, findings, host_id, ip, port,
        )

        # 4. Version disclosure
        await self._check_version_disclosure_raw(
            ctx, findings, host_id, ip, port,
        )

    async def _try_zone_transfer_raw(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        domain: str,
    ) -> None:
        """Attempt AXFR zone transfer using raw TCP."""
        data = await _raw_tcp_query(ip, port, domain, _QTYPE_MAP["AXFR"])
        if data is None:
            return

        # Check RCODE in flags (bits 0-3 of second flags byte)
        flags = _parse_dns_flags(data)
        rcode = flags & 0x000F
        ancount = _parse_dns_response_count(data)

        # RCODE 0 = NOERROR with answers means AXFR succeeded
        if rcode == 0 and ancount > 0:
            await ctx.facts.add(
                "dns.zone_transfer",
                {
                    "host": ip,
                    "port": port,
                    "domain": domain,
                    "record_count": ancount,
                },
                self.name,
                host_id=host_id,
            )

            findings.append(Finding(
                title=f"DNS zone transfer allowed on {ip}:{port}",
                description=(
                    f"DNS server {ip}:{port} permits AXFR zone transfer "
                    f"for domain '{domain}'. This exposes the entire DNS "
                    f"zone including all hostnames, IP addresses, and "
                    f"internal infrastructure. {ancount} record(s) in response."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="dns_zone_transfer",
                    data=(
                        f"AXFR succeeded for {domain} on {ip}:{port}. "
                        f"Response contains {ancount} answer record(s)."
                    ),
                )],
                remediation=(
                    "Restrict zone transfers to authorized secondary DNS "
                    "servers only. In BIND: use 'allow-transfer { trusted; };'. "
                    "In Windows DNS: configure zone transfer restrictions "
                    "in the Zone Properties > Zone Transfers tab."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1590/002/",
                ],
            ))

    async def _query_records_raw(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
        domain: str,
    ) -> None:
        """Query common record types using raw UDP packets."""
        records_found: dict[str, int] = {}

        for rtype in _RECORD_TYPES:
            qtype = _QTYPE_MAP.get(rtype)
            if qtype is None:
                continue

            data = await _raw_udp_query(ip, port, domain, qtype)
            if data is None:
                continue

            ancount = _parse_dns_response_count(data)
            if ancount > 0:
                records_found[rtype] = ancount

        if records_found:
            await ctx.facts.add(
                "dns.records",
                {
                    "host": ip,
                    "port": port,
                    "domain": domain,
                    "record_counts": records_found,
                },
                self.name,
                host_id=host_id,
            )

            record_lines = "\n".join(
                f"  {rtype:6s} {count} record(s)"
                for rtype, count in records_found.items()
            )
            findings.append(Finding(
                title=f"DNS records for {domain} on {ip}:{port}",
                description=(
                    f"Queried {len(records_found)} record type(s) for "
                    f"domain '{domain}' via DNS server {ip}:{port}."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="dns_records",
                    data=f"DNS records for {domain}:\n{record_lines}",
                )],
            ))

    async def _check_open_resolver_raw(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Check for open resolver using raw UDP query."""
        data = await _raw_udp_query(
            ip, port, "example.com", _QTYPE_MAP["A"], rd=True,
        )
        if data is None:
            return

        flags = _parse_dns_flags(data)
        rcode = flags & 0x000F
        ra = (flags >> 7) & 1  # RA (Recursion Available) bit
        ancount = _parse_dns_response_count(data)

        if rcode == 0 and ra == 1 and ancount > 0:
            findings.append(Finding(
                title=f"Open DNS resolver on {ip}:{port}",
                description=(
                    f"DNS server {ip}:{port} answers recursive queries "
                    f"for external domains. Open resolvers can be abused "
                    f"for DNS amplification DDoS attacks and cache "
                    f"poisoning."
                ),
                severity=Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="dns_open_resolver",
                    data=(
                        f"Recursive query for example.com succeeded on "
                        f"{ip}:{port} (RA=1, ANCOUNT={ancount})"
                    ),
                )],
                remediation=(
                    "Disable recursion for external clients. In BIND: "
                    "set 'recursion no;' or restrict with "
                    "'allow-recursion { localhost; internal; };'. "
                    "In Windows DNS: disable recursion in the Advanced "
                    "tab of DNS server properties."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

    async def _check_version_disclosure_raw(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Query version.bind CHAOS TXT using raw UDP."""
        # Build a CHAOS TXT query for version.bind
        # QCLASS=CH (3) instead of IN (1)
        import random

        txn_id = random.randint(0, 65535)
        flags = 0x0100  # RD
        header = struct.pack(">HHHHHH", txn_id, flags, 1, 0, 0, 0)

        # Encode "version.bind"
        qname = b"\x07version\x04bind\x00"
        question = qname + struct.pack(">HH", 16, 3)  # TXT=16, CH=3

        packet = header + question

        import socket

        def _do_query() -> bytes | None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(_DNS_TIMEOUT)
            try:
                sock.sendto(packet, (ip, port))
                data, _ = sock.recvfrom(4096)
                return data
            except (TimeoutError, OSError):
                return None
            finally:
                sock.close()

        data = await asyncio.to_thread(_do_query)
        if data is None:
            return

        ancount = _parse_dns_response_count(data)
        if ancount > 0:
            # Attempt to extract the TXT string from the answer
            version_str = _extract_txt_from_response(data)
            if version_str:
                findings.append(Finding(
                    title=f"DNS version disclosure on {ip}:{port}",
                    description=(
                        f"DNS server {ip}:{port} discloses its version via "
                        f"version.bind CHAOS TXT query: {version_str}. This "
                        f"information helps attackers identify specific "
                        f"software versions and known vulnerabilities."
                    ),
                    severity=Severity.LOW,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="dns_version",
                        data=f"version.bind CHAOS TXT: {version_str}",
                    )],
                    remediation=(
                        "Hide the DNS server version. In BIND: set "
                        "'version \"none\";' or 'version \"not disclosed\";' "
                        "in the options block."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1046/",
                    ],
                ))


def _extract_txt_from_response(data: bytes) -> str | None:
    """Extract the first TXT record string from a raw DNS response."""
    if len(data) < 12:
        return None

    # Skip header (12 bytes)
    offset = 12

    # Skip question section (1 question assumed)
    # Skip QNAME
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length >= 0xC0:  # Compression pointer
            offset += 2
            break
        offset += 1 + length
    # Skip QTYPE + QCLASS
    offset += 4

    # Parse answer section — skip NAME
    while offset < len(data):
        b = data[offset]
        if b >= 0xC0:  # Compression pointer
            offset += 2
            break
        if b == 0:
            offset += 1
            break
        offset += 1 + b

    if offset + 10 > len(data):
        return None

    # Skip TYPE (2) + CLASS (2) + TTL (4)
    offset += 8
    # RDLENGTH
    rdlen = struct.unpack(">H", data[offset : offset + 2])[0]
    offset += 2

    if offset + rdlen > len(data) or rdlen < 2:
        return None

    # TXT record: first byte is string length
    txt_len = data[offset]
    offset += 1
    if offset + txt_len > len(data):
        return None

    return data[offset : offset + txt_len].decode("utf-8", errors="replace")
