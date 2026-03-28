"""Auto-detects what a target is and selects the optimal attack strategy.

After port scan + service detection, the TargetProfiler classifies each host
based on open ports, OS fingerprint, banners, and service combinations.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pacdoor.core.models import Host, TargetProfile

if TYPE_CHECKING:
    from pacdoor.core.fact_store import FactStore

log = logging.getLogger(__name__)

# Port combinations that identify specific roles
DC_PORTS = {88, 389, 636, 445, 464, 3268, 3269}  # Kerberos + LDAP + SMB
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
DB_PORTS = {1433, 3306, 5432, 1521, 6379, 27017, 9200, 5984}
MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
DNS_PORTS = {53}

# Priority-ordered attack strategies per profile
STRATEGIES: dict[TargetProfile, list[str]] = {
    TargetProfile.WINDOWS_DC: [
        "enum.ldap", "enum.smb", "enum.dns",
        "vuln.smb_vulns", "vuln.default_creds",
        "exploit.credential_spray",
        "post.ad_enum", "post.cred_harvest",
        "post.lateral_move",
    ],
    TargetProfile.WINDOWS_SERVER: [
        "enum.smb", "enum.rdp",
        "vuln.smb_vulns", "vuln.default_creds",
        "exploit.credential_spray",
        "post.privesc_enum", "post.cred_harvest",
        "post.lateral_move",
    ],
    TargetProfile.LINUX_SERVER: [
        "enum.ssh", "enum.http",
        "vuln.ssh_vulns", "vuln.default_creds",
        "exploit.ssh_brute",
        "post.privesc_enum", "post.cred_harvest",
    ],
    TargetProfile.WEB_SERVER: [
        "enum.http",
        "vuln.template_scanner", "vuln.http_vulns", "vuln.tls_vulns",
        "exploit.http_exploits",
    ],
    TargetProfile.DATABASE_SERVER: [
        "enum.mssql", "enum.mysql", "enum.pgsql", "enum.redis", "enum.mongo",
        "vuln.default_creds",
        "exploit.db_exploits",
        "post.cred_harvest",
    ],
    TargetProfile.MAIL_SERVER: [
        "enum.smtp",
        "vuln.default_creds",
        "exploit.credential_spray",
    ],
    TargetProfile.DNS_SERVER: [
        "enum.dns",
    ],
    TargetProfile.NETWORK_DEVICE: [
        "enum.snmp",
        "vuln.default_creds",
    ],
    TargetProfile.IOT_EMBEDDED: [
        "vuln.default_creds",
        "enum.http",
    ],
    TargetProfile.UNKNOWN: [],  # Planner runs everything generically
}


class TargetProfiler:
    """Classifies hosts based on discovered facts."""

    async def classify(self, host: Host, facts: FactStore) -> TargetProfile:
        """Determine what kind of target this host is."""
        open_ports = await self._get_open_ports(host.id, facts)
        os_hint = (host.os or "").lower()

        # Check for Domain Controller first (highest value target)
        if DC_PORTS.issubset(open_ports) or (
            88 in open_ports and 389 in open_ports and 445 in open_ports
        ):
            return TargetProfile.WINDOWS_DC

        # Database server
        if open_ports & DB_PORTS:
            db_count = len(open_ports & DB_PORTS)
            non_db = len(open_ports - DB_PORTS)
            if db_count >= non_db or db_count >= 2:
                return TargetProfile.DATABASE_SERVER

        # Mail server
        if len(open_ports & MAIL_PORTS) >= 2:
            return TargetProfile.MAIL_SERVER

        # Web server (primarily HTTP)
        web_count = len(open_ports & WEB_PORTS)
        if web_count >= 1:
            # If it also has Windows ports, it's a Windows server with web
            if 445 in open_ports or 3389 in open_ports:
                if web_count > 2:
                    return TargetProfile.WEB_SERVER
                return TargetProfile.WINDOWS_SERVER
            # If it also has SSH, it's a Linux web server
            if 22 in open_ports:
                if web_count > 1:
                    return TargetProfile.WEB_SERVER
                return TargetProfile.LINUX_SERVER
            return TargetProfile.WEB_SERVER

        # Windows server (SMB + RDP but not DC)
        if 445 in open_ports and ("windows" in os_hint or 3389 in open_ports):
            return TargetProfile.WINDOWS_SERVER

        # Linux server
        if 22 in open_ports and ("linux" in os_hint or "ubuntu" in os_hint or "centos" in os_hint):
            return TargetProfile.LINUX_SERVER

        # Network device (SNMP but not much else)
        if 161 in open_ports and len(open_ports) <= 5:
            return TargetProfile.NETWORK_DEVICE

        # DNS server
        if 53 in open_ports and len(open_ports) <= 3:
            return TargetProfile.DNS_SERVER

        # IoT / embedded (telnet, few ports)
        if 23 in open_ports and len(open_ports) <= 4:
            return TargetProfile.IOT_EMBEDDED

        # Fallback heuristics
        if "windows" in os_hint:
            return TargetProfile.WINDOWS_SERVER
        if "linux" in os_hint:
            return TargetProfile.LINUX_SERVER

        return TargetProfile.UNKNOWN

    def get_strategy(self, profile: TargetProfile) -> list[str]:
        """Get the prioritized module list for a given profile."""
        return STRATEGIES.get(profile, [])

    async def _get_open_ports(self, host_id: str, facts: FactStore) -> set[int]:
        """Get all open port numbers for a host."""
        ports = await facts.get_for_host("port.open", host_id)
        return {p.port for p in ports if hasattr(p, "port")}
