"""TCP port scanner — discovers open ports on live hosts."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from pacdoor.core.models import Finding, Host, Phase, Port, PortState, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Nmap top ~1000 ports — most commonly open, sorted for dedup.
# Includes all well-known ports that frequently appear open in real scans,
# plus common high ports for databases, web servers, management interfaces, etc.
TOP_PORTS: list[int] = sorted(set([
    # ── Critical services (top ~100 by nmap frequency) ───────────────
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
    8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465,
    113, 81, 389, 1026, 2001, 1027, 8443, 6001, 8000, 8008, 5060, 32768,
    49152, 1433, 8081, 49154, 2000, 5432, 1028, 6646, 49153, 5631,
    49155, 49156, 3128, 9999, 9090, 1110, 5800, 2049, 1029, 6000,
    513, 990, 5357, 427, 548, 3986, 515, 7070, 554, 9200, 631, 9100,
    5985, 5986, 49, 6379, 5051, 5003, 5009, 5050, 2717, 1755, 10000,
    27017, 27018, 4899, 5101, 5120, 5190, 3000, 5666,
    # ── Well-known 1-1024 ────────────────────────────────────────────
    1, 7, 9, 11, 13, 15, 17, 19, 20, 26, 37, 42, 43, 50, 57, 67,
    68, 69, 70, 79, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109,
    115, 118, 119, 123, 124, 137, 138, 144, 150, 156, 158, 161, 162,
    170, 177, 179, 194, 201, 209, 210, 213, 218, 220, 259, 264, 280,
    311, 318, 323, 366, 383, 384, 387, 396, 400, 401, 402, 407, 416,
    417, 425, 434, 435, 444, 458, 464, 468, 475, 481, 497, 500,
    501, 502, 504, 510, 512, 514, 520, 522, 524, 530, 533, 540, 543,
    544, 546, 547, 556, 563, 564, 585, 593, 616, 617, 625, 636,
    646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720,
    722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880,
    888, 898, 900, 901, 902, 903, 911, 981, 987, 992, 999,
    1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024,
    # ── Common high ports (1025-65535) ───────────────────────────────
    1030, 1035, 1036, 1041, 1044, 1048, 1049, 1050, 1053, 1054, 1056,
    1058, 1059, 1064, 1065, 1066, 1069, 1071, 1074, 1080, 1081, 1082,
    1083, 1084, 1085, 1090, 1098, 1099, 1100, 1109, 1111, 1119, 1121,
    1122, 1126, 1130, 1131, 1137, 1138, 1141, 1145, 1147, 1148, 1149,
    1151, 1152, 1154, 1163, 1164, 1165, 1169, 1174, 1175, 1183, 1185,
    1186, 1187, 1192, 1198, 1199, 1200, 1201, 1213, 1216, 1217, 1218,
    1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287,
    1296, 1300, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1434,
    1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556,
    1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717,
    1718, 1719, 1721, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840,
    1862, 1863, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984,
    1998, 1999, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
    2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041,
    2042, 2043, 2045, 2046, 2047, 2048, 2065, 2068, 2099, 2100, 2103,
    2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161,
    2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301,
    2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500,
    2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701,
    2702, 2710, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920,
    2967, 2968, 2998, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017,
    3030, 3031, 3050, 3052, 3071, 3077, 3168, 3211, 3221, 3260,
    3261, 3268, 3269, 3283, 3300, 3301, 3322, 3323, 3324, 3325,
    3333, 3351, 3367, 3369, 3370, 3371, 3372, 3390, 3404, 3476,
    3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737,
    3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869,
    3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3995,
    3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111,
    4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445,
    4446, 4449, 4550, 4567, 4662, 4848, 4900, 4998, 5000, 5001,
    5002, 5004, 5030, 5033, 5054, 5061,
    5080, 5087, 5100, 5102, 5200, 5214, 5221, 5222,
    5225, 5226, 5269, 5280, 5298, 5405, 5414, 5431, 5440,
    5500, 5510, 5544, 5550, 5555, 5560, 5566, 5633, 5678,
    5718, 5730, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850,
    5859, 5862, 5877, 5901, 5902, 5903, 5904, 5906, 5907, 5910,
    5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963,
    5987, 5988, 5989, 5998, 5999, 6002, 6003,
    6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112,
    6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566,
    6567, 6580, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779,
    6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004,
    7007, 7019, 7025, 7100, 7103, 7106, 7200, 7201, 7402, 7435,
    7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911,
    7920, 7921, 7937, 7938, 7999, 8001, 8002, 8007, 8009,
    8010, 8011, 8021, 8022, 8031, 8042, 8045, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180,
    8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300,
    8333, 8383, 8400, 8402, 8500, 8600, 8649, 8651, 8652, 8654,
    8701, 8800, 8873, 8899, 8994, 9000, 9001, 9002, 9003, 9009,
    9010, 9011, 9040, 9050, 9071, 9080, 9081, 9091, 9099,
    9101, 9102, 9103, 9110, 9111, 9207, 9220, 9290, 9415, 9418,
    9443, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618,
    9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968,
    9998, 10001, 10002, 10003, 10004, 10009, 10010, 10012,
    10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617,
    10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000,
    12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238,
    14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000,
    16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877,
    17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780,
    19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
    22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
    27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038,
    31337, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
    33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911,
    41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080,
    49157, 49158, 49159, 49160, 49161,
    49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001,
    50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
    51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056,
    55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443,
    61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
]))

# Map well-known ports to service fact types
PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpc",
    135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp",
    636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm",
    6379: "redis", 8080: "http", 8443: "https",
    9200: "elasticsearch", 27017: "mongodb",
}

# Services that should also be tagged as HTTP
HTTP_SERVICES = {"http", "https"}


def _parse_port_spec(spec: str) -> list[int] | None:
    """Parse a user-provided port specification string.

    Returns a list of port numbers, or None to use TOP_PORTS.
    Supported formats:
      - "top1000" / "top200"  -> None (use TOP_PORTS)
      - "all"                 -> range 1-65535
      - "22,80,443"           -> explicit list
      - "1-1024"              -> range
      - "22,80,100-200,8080"  -> mixed
    """
    spec = spec.strip().lower()
    if spec in ("top1000", "top200", "default"):
        return None
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo_int, hi_int = int(lo_s), int(hi_s)
            if 1 <= lo_int <= hi_int <= 65535:
                ports.update(range(lo_int, hi_int + 1))
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports) if ports else None


class PortScanModule(BaseModule):
    name = "recon.port_scan"
    description = "TCP connect scan on discovered hosts"
    phase = Phase.RECON
    attack_technique_ids = ["T1046"]
    required_facts = ["host"]
    produced_facts = ["port.open", "service.*"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        hosts = await ctx.facts.get_values("host")
        findings: list[Finding] = []
        # Limit concurrency to 200 — safe for OS file descriptor limits
        sem = asyncio.Semaphore(200)
        total_open = 0

        # Determine which ports to scan from ctx.config["ports"] (CLI --ports)
        ports_spec: str | None = ctx.config.get("ports")
        scan_ports = (_parse_port_spec(ports_spec) if ports_spec else None) or TOP_PORTS

        async def scan_port(host: Host, port_num: int) -> None:
            nonlocal total_open
            async with sem:
                try:
                    _reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host.ip, port_num),
                        timeout=2.0,
                    )
                    writer.close()
                    await writer.wait_closed()

                    svc_name = PORT_SERVICE_MAP.get(port_num)
                    port = Port(
                        host_id=host.id,
                        port=port_num,
                        state=PortState.OPEN,
                        service_name=svc_name,
                    )
                    await ctx.facts.add("port.open", port, self.name, host_id=host.id)

                    # Persist port to database
                    if ctx.db is not None:
                        await ctx.db.insert_port(port)

                    total_open += 1

                    # Add service-specific facts for the planner
                    if svc_name:
                        await ctx.facts.add(
                            f"service.{svc_name}", port, self.name, host_id=host.id
                        )
                        # HTTP services also get tagged as service.http
                        if svc_name in HTTP_SERVICES or port_num in (8080, 8443, 8888, 8000, 3000, 9090):
                            if svc_name != "http":
                                await ctx.facts.add(
                                    "service.http", port, self.name, host_id=host.id
                                )
                except (TimeoutError, OSError, ConnectionRefusedError):
                    pass

        tasks = []
        for host in hosts:
            for port_num in scan_ports:
                tasks.append(scan_port(host, port_num))

        await asyncio.gather(*tasks)

        if total_open > 0:
            findings.append(Finding(
                title=f"Port scan: {total_open} open ports across {len(hosts)} hosts",
                description=f"TCP connect scan on {len(scan_ports)} ports",
                severity=Severity.INFO,
                module_name=self.name,
                attack_technique_ids=["T1046"],
            ))
        return findings
