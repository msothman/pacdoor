"""Service detection — banner grabbing and OS fingerprinting on open ports."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl as _ssl
from typing import TYPE_CHECKING

from pacdoor.core.models import Finding, Host, Phase, Port, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Banner patterns -> (regex, product_name, service_type)
BANNER_PATTERNS: list[tuple[str, str, str]] = [
    # SSH
    (r"SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)", "OpenSSH", "ssh"),
    (r"SSH-[\d.]+-dropbear_([\d.]+)", "Dropbear", "ssh"),
    # FTP
    (r"220.*Microsoft FTP Service", "Microsoft FTP", "ftp"),
    (r"220.*vsftpd ([\d.]+)", "vsftpd", "ftp"),
    (r"220.*ProFTPD ([\d.]+)", "ProFTPD", "ftp"),
    (r"220.*FileZilla Server ([\d.]+)", "FileZilla", "ftp"),
    # SMTP
    (r"220.*ESMTP Postfix", "Postfix", "smtp"),
    (r"220.*Microsoft ESMTP", "Microsoft Exchange", "smtp"),
    (r"220.*Exim ([\d.]+)", "Exim", "smtp"),
    # HTTP
    (r"Server: Apache/([\d.]+)", "Apache", "http"),
    (r"Server: nginx/([\d.]+)", "nginx", "http"),
    (r"Server: Microsoft-IIS/([\d.]+)", "IIS", "http"),
    (r"Server: Microsoft-HTTPAPI/([\d.]+)", "Microsoft HTTPAPI", "http"),
    (r"Server: lighttpd/([\d.]+)", "lighttpd", "http"),
    # IMAP
    (r"\* OK.*Dovecot", "Dovecot", "imap"),
    (r"\* OK.*Cyrus", "Cyrus", "imap"),
    # Databases
    (r"mysql_native_password", "MySQL", "mysql"),
    (r"MariaDB", "MariaDB", "mysql"),
    (r"PostgreSQL", "PostgreSQL", "postgresql"),
    # Redis  — responds to PING with +PONG
    (r"\+PONG", "Redis", "redis"),
    (r"-ERR.*redis", "Redis", "redis"),
    # MongoDB — binary protocol, but initial handshake often contains "MongoDB"
    (r"MongoDB", "MongoDB", "mongodb"),
    (r"ismaster", "MongoDB", "mongodb"),
    # Elasticsearch — JSON banner containing cluster info
    (r'"cluster_name"\s*:', "Elasticsearch", "elasticsearch"),
    (r'"tagline"\s*:\s*"You Know, for Search"', "Elasticsearch", "elasticsearch"),
    # RDP — RDP protocol starts with specific bytes, but banner may contain
    (r"\x03\x00", "RDP", "rdp"),
    # WinRM
    (r"WinRM", "WinRM", "winrm"),
    (r"Windows Remote Management", "WinRM", "winrm"),
]

# Ports that require SSL/TLS wrapping for the connection
SSL_PORTS: frozenset[int] = frozenset([443, 8443, 636, 993, 995, 465])

class ServiceDetectModule(BaseModule):
    name = "recon.service_detect"
    description = "Banner grabbing and service version detection"
    phase = Phase.RECON
    attack_technique_ids = ["T1046"]
    required_facts = ["port.open"]
    produced_facts = ["service.version"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        ports: list[Port] = await ctx.facts.get_values("port.open")
        findings: list[Finding] = []
        sem = asyncio.Semaphore(100)
        detected = 0

        # Build a host_id -> ip lookup dict once (O(1) per port instead of O(n))
        hosts: list[Host] = await ctx.facts.get_values("host")
        host_ip_map: dict[str, str] = {h.id: h.ip for h in hosts}

        async def grab_banner(port_obj: Port) -> None:
            nonlocal detected
            async with sem:
                ip = host_ip_map.get(port_obj.host_id)
                if not ip:
                    return
                banner = await self._grab_banner(ip, port_obj.port)
                if banner:
                    port_obj.banner = banner[:500]
                    product, version = self._identify_service(banner)
                    if product:
                        port_obj.product = product
                        port_obj.service_version = version
                        detected += 1
                        await ctx.facts.add(
                            "service.version", port_obj, self.name,
                            host_id=port_obj.host_id,
                        )

        tasks = [grab_banner(p) for p in ports]
        await asyncio.gather(*tasks)

        if detected > 0:
            findings.append(Finding(
                title=f"Service detection: identified {detected} service versions",
                description="Banner grabbing on open ports",
                severity=Severity.INFO,
                module_name=self.name,
                attack_technique_ids=["T1046"],
            ))
        return findings

    async def _grab_banner(self, ip: str, port: int) -> str | None:
        """Connect and read initial banner. Uses SSL for known TLS ports."""
        try:
            # Determine whether this port needs SSL/TLS
            ssl_ctx: _ssl.SSLContext | None = None
            if port in SSL_PORTS:
                ssl_ctx = _ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = _ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx),
                timeout=3.0,
            )
            # Some services send a banner immediately
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
            except TimeoutError:
                # HTTP services need a request first
                if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 9090):
                    writer.write(
                        f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
                    )
                    await writer.drain()
                    try:
                        data = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                        banner = data.decode("utf-8", errors="replace").strip()
                    except TimeoutError:
                        banner = None
                elif port == 6379:
                    # Redis: send PING
                    writer.write(b"PING\r\n")
                    await writer.drain()
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                        banner = data.decode("utf-8", errors="replace").strip()
                    except TimeoutError:
                        banner = None
                else:
                    banner = None
            writer.close()
            await writer.wait_closed()
            return banner
        except (TimeoutError, OSError, ConnectionRefusedError, _ssl.SSLError):
            return None

    def _identify_service(self, banner: str) -> tuple[str | None, str | None]:
        """Match banner against known patterns."""
        for pattern, product, _svc_type in BANNER_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else None
                return product, version
        return None, None
