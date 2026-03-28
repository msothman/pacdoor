"""WiFi reconnaissance — passive wireless network discovery and security assessment."""

from __future__ import annotations

import asyncio
import logging
import platform
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pacdoor.core.models import Evidence, ExploitSafety, Finding, Phase, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Phishing / rogue SSID patterns (case-insensitive)
_ROGUE_SSID_PATTERNS = [
    re.compile(r"^free[_\- ]?wifi", re.IGNORECASE),
    re.compile(r"^guest[_\- ]?wifi", re.IGNORECASE),
    re.compile(r"^open[_\- ]?wifi", re.IGNORECASE),
    re.compile(r"^xfinity", re.IGNORECASE),
    re.compile(r"^linksys$", re.IGNORECASE),
    re.compile(r"^netgear$", re.IGNORECASE),
    re.compile(r"^default$", re.IGNORECASE),
    re.compile(r"^setup$", re.IGNORECASE),
    re.compile(r"free[_\- ]?internet", re.IGNORECASE),
    re.compile(r"^hotel[_\- ]?wifi", re.IGNORECASE),
    re.compile(r"^airport[_\- ]?wifi", re.IGNORECASE),
]

# Standard 2.4 GHz channels (1-11 is universal)
_STANDARD_24GHZ_CHANNELS = set(range(1, 12))
# Extended 2.4 GHz channels for regions that allow them (12-14)
_EXTENDED_24GHZ_CHANNELS = set(range(12, 15))
# Standard 5 GHz channels
_STANDARD_5GHZ_CHANNELS = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
}

# Signal strength threshold (dBm) above which an AP is suspiciously strong
_SUSPICIOUS_SIGNAL_DBM = -20


@dataclass
class WifiNetwork:
    """Parsed representation of a discovered wireless network."""
    ssid: str
    bssid: str
    channel: int
    signal_dbm: int
    encryption: str  # OPEN, WEP, WPA, WPA2-PSK, WPA2-Enterprise, WPA3, WPA3-Transition
    wps_enabled: bool = False
    hidden: bool = False
    eap_type: str | None = None  # PEAP, EAP-TTLS, EAP-TLS, etc.
    raw_data: dict[str, str] = field(default_factory=dict)


@dataclass
class ConnectedClient:
    """A client station connected to an AP."""
    mac: str
    bssid: str
    signal_dbm: int | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0


async def _run_cmd(*args: str, timeout: float = 30.0) -> tuple[str, str, int]:
    """Run a command via create_subprocess_exec and return (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            proc.returncode or 0,
        )
    except FileNotFoundError:
        return "", f"Command not found: {args[0]}", 127
    except asyncio.TimeoutError:
        try:
            proc.kill()  # type: ignore[possibly-undefined]
        except ProcessLookupError:
            pass
        return "", "Command timed out", 1
    except OSError as exc:
        return "", str(exc), 1


# ---------------------------------------------------------------------------
# Platform: detect wireless interfaces
# ---------------------------------------------------------------------------

async def _detect_interfaces_linux() -> list[str]:
    """Detect wireless interfaces on Linux using iw."""
    stdout, _, rc = await _run_cmd("iw", "dev")
    if rc != 0:
        return []
    ifaces: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            ifaces.append(line.split()[1])
    return ifaces


async def _detect_interfaces_windows() -> list[str]:
    """Detect wireless interfaces on Windows using netsh."""
    stdout, _, rc = await _run_cmd("netsh", "wlan", "show", "interfaces")
    if rc != 0:
        return []
    ifaces: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("name"):
            parts = stripped.split(":", 1)
            if len(parts) == 2:
                ifaces.append(parts[1].strip())
    return ifaces


async def _detect_interfaces_darwin() -> list[str]:
    """Detect wireless interfaces on macOS."""
    stdout, _, rc = await _run_cmd(
        "networksetup", "-listallhardwareports"
    )
    if rc != 0:
        return []
    ifaces: list[str] = []
    lines = stdout.splitlines()
    for i, line in enumerate(lines):
        if "Wi-Fi" in line or "AirPort" in line:
            if i + 1 < len(lines):
                m = re.search(r"Device:\s*(\S+)", lines[i + 1])
                if m:
                    ifaces.append(m.group(1))
    return ifaces


async def _detect_interfaces() -> list[str]:
    """Auto-detect wireless interfaces for the current platform."""
    system = platform.system()
    if system == "Linux":
        return await _detect_interfaces_linux()
    if system == "Windows":
        return await _detect_interfaces_windows()
    if system == "Darwin":
        return await _detect_interfaces_darwin()
    return []


# ---------------------------------------------------------------------------
# Platform: scan for wireless networks
# ---------------------------------------------------------------------------

def _parse_encryption_linux(cell_text: str) -> tuple[str, bool, str | None]:
    """Parse encryption info from an iwlist scan cell.

    Returns (encryption_type, wps_enabled, eap_type).
    """
    wps = bool(re.search(r"WPS", cell_text, re.IGNORECASE))
    eap_type: str | None = None

    if "WPA3" in cell_text:
        if "WPA2" in cell_text:
            return "WPA3-Transition", wps, eap_type
        return "WPA3", wps, eap_type

    if "WPA2" in cell_text:
        if "802.1X" in cell_text or "EAP" in cell_text:
            eap_type = _extract_eap_type(cell_text)
            return "WPA2-Enterprise", wps, eap_type
        return "WPA2-PSK", wps, eap_type

    if "WPA" in cell_text:
        return "WPA", wps, eap_type

    if re.search(r"Encryption key:on", cell_text):
        return "WEP", wps, eap_type

    return "OPEN", wps, eap_type


def _extract_eap_type(text: str) -> str | None:
    """Try to extract EAP type from scan output."""
    for eap in ("PEAP", "EAP-TTLS", "EAP-TLS", "EAP-FAST", "LEAP"):
        if eap in text.upper():
            return eap
    return None


async def _scan_linux(iface: str) -> list[WifiNetwork]:
    """Scan using iwlist on Linux."""
    stdout, stderr, rc = await _run_cmd("iwlist", iface, "scan")
    if rc != 0:
        # Might need root — try with sudo
        stdout, stderr, rc = await _run_cmd("sudo", "iwlist", iface, "scan")
        if rc != 0:
            log.debug("iwlist scan failed on %s: %s", iface, stderr.strip())
            return []

    networks: list[WifiNetwork] = []
    # Split into cells
    cells = re.split(r"Cell \d+ - ", stdout)

    for cell in cells[1:]:  # skip preamble before first cell
        # BSSID
        bssid_m = re.search(r"Address:\s*([\dA-Fa-f:]{17})", cell)
        bssid = bssid_m.group(1).upper() if bssid_m else "00:00:00:00:00:00"

        # SSID
        ssid_m = re.search(r'ESSID:"(.*?)"', cell)
        ssid = ssid_m.group(1) if ssid_m else ""
        hidden = ssid == "" or ssid == "\\x00" * len(ssid)

        # Channel
        ch_m = re.search(r"Channel:(\d+)", cell)
        channel = int(ch_m.group(1)) if ch_m else 0

        # Signal
        sig_m = re.search(r"Signal level[=:](-?\d+)", cell)
        signal = int(sig_m.group(1)) if sig_m else -100

        encryption, wps, eap_type = _parse_encryption_linux(cell)

        networks.append(WifiNetwork(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            signal_dbm=signal,
            encryption=encryption,
            wps_enabled=wps,
            hidden=hidden,
            eap_type=eap_type,
        ))

    return networks


async def _scan_windows() -> list[WifiNetwork]:
    """Scan using netsh on Windows."""
    stdout, stderr, rc = await _run_cmd(
        "netsh", "wlan", "show", "networks", "mode=bssid"
    )
    if rc != 0:
        log.debug("netsh wlan scan failed: %s", stderr.strip())
        return []

    networks: list[WifiNetwork] = []
    # Split into blocks per SSID
    blocks = re.split(r"^SSID \d+\s*:", stdout, flags=re.MULTILINE)

    for block in blocks[1:]:
        lines = block.strip().splitlines()
        if not lines:
            continue

        ssid = lines[0].strip()
        hidden = ssid == ""

        # Defaults
        bssid = "00:00:00:00:00:00"
        channel = 0
        signal_pct = 0
        encryption = "OPEN"
        auth = ""
        wps = False
        eap_type: str | None = None

        for line in lines[1:]:
            stripped = line.strip()
            low = stripped.lower()

            if low.startswith("bssid"):
                m = re.search(r":\s*([\dA-Fa-f:]{17})", stripped)
                if m:
                    bssid = m.group(1).upper()

            elif re.match(r"channel\s*:", low):
                # Match "Channel : 36" but NOT "Channel Utilization: 6"
                m = re.search(r":\s*(\d+)", stripped)
                if m:
                    channel = int(m.group(1))

            elif low.startswith("signal"):
                m = re.search(r":\s*(\d+)%", stripped)
                if m:
                    signal_pct = int(m.group(1))

            elif low.startswith("authentication"):
                auth = stripped.split(":", 1)[1].strip() if ":" in stripped else ""

            elif low.startswith("encryption"):
                enc_val = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
                if enc_val.upper() == "WEP":
                    encryption = "WEP"
                elif enc_val.upper() == "NONE":
                    encryption = "OPEN"

        # Map auth string to our encryption type (overrides if better info)
        auth_lower = auth.lower()
        if "wpa3" in auth_lower and "wpa2" in auth_lower:
            encryption = "WPA3-Transition"
        elif "wpa3" in auth_lower:
            encryption = "WPA3"
        elif "wpa2-enterprise" in auth_lower or "802.1x" in auth_lower:
            encryption = "WPA2-Enterprise"
        elif "wpa2-personal" in auth_lower or "wpa2" in auth_lower:
            encryption = "WPA2-PSK"
        elif "wpa" in auth_lower and "wpa2" not in auth_lower:
            encryption = "WPA"

        # Convert signal percentage to approximate dBm: -100 + (pct / 2)
        signal_dbm = -100 + signal_pct // 2 if signal_pct > 0 else -100

        networks.append(WifiNetwork(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            signal_dbm=signal_dbm,
            encryption=encryption,
            wps_enabled=wps,
            hidden=hidden,
            eap_type=eap_type,
        ))

    return networks


async def _scan_darwin(iface: str) -> list[WifiNetwork]:
    """Scan using airport utility on macOS."""
    airport_path = (
        "/System/Library/PrivateFrameworks/Apple80211.framework"
        "/Versions/Current/Resources/airport"
    )
    stdout, stderr, rc = await _run_cmd(airport_path, "-s")
    if rc != 0:
        log.debug("airport scan failed: %s", stderr.strip())
        return []

    networks: list[WifiNetwork] = []
    lines = stdout.strip().splitlines()
    if len(lines) < 2:
        return []

    # First line is the header; parse column positions from it
    lines[0]

    for line in lines[1:]:
        # airport -s output is fixed-width. Typical columns:
        #   SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
        # We parse from the right since SSID can contain spaces.
        parts = line.split()
        if len(parts) < 7:
            continue

        # BSSID is always in MAC format — find it
        bssid_idx = -1
        for i, p in enumerate(parts):
            if re.match(r"^[\dA-Fa-f]{2}(:[\dA-Fa-f]{2}){5}$", p):
                bssid_idx = i
                break

        if bssid_idx < 0:
            continue

        ssid = " ".join(parts[:bssid_idx]) if bssid_idx > 0 else ""
        hidden = ssid == ""
        bssid = parts[bssid_idx].upper()

        rssi_str = parts[bssid_idx + 1] if bssid_idx + 1 < len(parts) else "-100"
        try:
            signal_dbm = int(rssi_str)
        except ValueError:
            signal_dbm = -100

        ch_str = parts[bssid_idx + 2] if bssid_idx + 2 < len(parts) else "0"
        # Channel might be "36,+1" or "6"
        ch_clean = ch_str.split(",")[0]
        try:
            channel = int(ch_clean)
        except ValueError:
            channel = 0

        # Security is everything after HT and CC columns
        security_parts = parts[bssid_idx + 5:] if bssid_idx + 5 < len(parts) else []
        security_str = " ".join(security_parts)

        encryption = "OPEN"
        wps = False
        eap_type: str | None = None

        if "WPA3" in security_str:
            if "WPA2" in security_str:
                encryption = "WPA3-Transition"
            else:
                encryption = "WPA3"
        elif "WPA2" in security_str:
            if "802.1X" in security_str or "Enterprise" in security_str:
                encryption = "WPA2-Enterprise"
                eap_type = _extract_eap_type(security_str)
            else:
                encryption = "WPA2-PSK"
        elif "WPA" in security_str:
            encryption = "WPA"
        elif "WEP" in security_str:
            encryption = "WEP"

        networks.append(WifiNetwork(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            signal_dbm=signal_dbm,
            encryption=encryption,
            wps_enabled=wps,
            hidden=hidden,
            eap_type=eap_type,
        ))

    return networks


async def _scan_networks(ifaces: list[str]) -> list[WifiNetwork]:
    """Scan for networks using the appropriate platform method."""
    system = platform.system()
    all_networks: list[WifiNetwork] = []

    if system == "Windows":
        # Windows netsh does not require a specific interface
        return await _scan_windows()

    for iface in ifaces:
        if system == "Linux":
            nets = await _scan_linux(iface)
        elif system == "Darwin":
            nets = await _scan_darwin(iface)
        else:
            nets = []
        all_networks.extend(nets)

    # Deduplicate by BSSID (same AP seen from multiple interfaces)
    seen: dict[str, WifiNetwork] = {}
    for net in all_networks:
        key = net.bssid
        if key not in seen or net.signal_dbm > seen[key].signal_dbm:
            seen[key] = net
    return list(seen.values())


# ---------------------------------------------------------------------------
# Platform: client enumeration (Linux only, requires monitor mode)
# ---------------------------------------------------------------------------

async def _enumerate_clients_linux(iface: str) -> list[ConnectedClient]:
    """List connected clients using iw station dump (Linux only)."""
    stdout, stderr, rc = await _run_cmd("iw", "dev", iface, "station", "dump")
    if rc != 0:
        log.debug("station dump failed on %s: %s", iface, stderr.strip())
        return []

    clients: list[ConnectedClient] = []
    blocks = re.split(r"Station\s+([\dA-Fa-f:]{17})", stdout)

    # blocks alternates: preamble, mac1, data1, mac2, data2, ...
    i = 1
    while i + 1 < len(blocks):
        mac = blocks[i].upper()
        data = blocks[i + 1]
        i += 2

        signal: int | None = None
        rx_bytes = 0
        tx_bytes = 0

        for line in data.splitlines():
            stripped = line.strip()
            if stripped.startswith("signal:"):
                m = re.search(r"(-?\d+)", stripped)
                if m:
                    signal = int(m.group(1))
            elif stripped.startswith("rx bytes:"):
                m = re.search(r"(\d+)", stripped)
                if m:
                    rx_bytes = int(m.group(1))
            elif stripped.startswith("tx bytes:"):
                m = re.search(r"(\d+)", stripped)
                if m:
                    tx_bytes = int(m.group(1))

        clients.append(ConnectedClient(
            mac=mac,
            bssid="",  # station dump shows clients of *our* AP
            signal_dbm=signal,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
        ))

    return clients


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _assess_encryption(net: WifiNetwork) -> Finding | None:
    """Return a finding if the network has weak or no encryption."""
    if net.encryption == "OPEN":
        return Finding(
            title=f"Open WiFi network: {net.ssid or '<hidden>'}",
            description=(
                f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) on "
                f"channel {net.channel} has no encryption. All traffic is "
                f"transmitted in cleartext and can be trivially intercepted."
            ),
            severity=Severity.CRITICAL,
            module_name="recon.wifi_recon",
            attack_technique_ids=["T1040"],
            evidence=[Evidence(
                kind="wifi_network",
                data=f"SSID={net.ssid!r} BSSID={net.bssid} CH={net.channel} ENC=OPEN",
            )],
            remediation="Enable WPA2 or WPA3 encryption on this access point.",
        )

    if net.encryption == "WEP":
        return Finding(
            title=f"WEP encryption on WiFi network: {net.ssid or '<hidden>'}",
            description=(
                f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) uses WEP "
                f"encryption, which can be cracked in minutes with freely "
                f"available tools (aircrack-ng). WEP provides no meaningful security."
            ),
            severity=Severity.CRITICAL,
            module_name="recon.wifi_recon",
            attack_technique_ids=["T1040"],
            evidence=[Evidence(
                kind="wifi_network",
                data=f"SSID={net.ssid!r} BSSID={net.bssid} CH={net.channel} ENC=WEP",
            )],
            remediation="Upgrade to WPA2-PSK (AES) or WPA3 immediately.",
        )

    if net.encryption == "WPA":
        return Finding(
            title=f"WPA (v1) encryption on WiFi network: {net.ssid or '<hidden>'}",
            description=(
                f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) uses WPA "
                f"(TKIP), which has known weaknesses. WPA2 or WPA3 should be used."
            ),
            severity=Severity.HIGH,
            module_name="recon.wifi_recon",
            attack_technique_ids=["T1040"],
            evidence=[Evidence(
                kind="wifi_network",
                data=f"SSID={net.ssid!r} BSSID={net.bssid} CH={net.channel} ENC=WPA",
            )],
            remediation="Upgrade to WPA2-PSK (AES) or WPA3.",
        )

    if net.encryption == "WPA3-Transition":
        return Finding(
            title=f"WPA3 transition mode on: {net.ssid or '<hidden>'}",
            description=(
                f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) uses WPA3 "
                f"transition mode (WPA2/WPA3 mixed). An attacker can force "
                f"downgrade to WPA2 using a rogue AP."
            ),
            severity=Severity.MEDIUM,
            module_name="recon.wifi_recon",
            attack_technique_ids=["T1040"],
            evidence=[Evidence(
                kind="wifi_network",
                data=(
                    f"SSID={net.ssid!r} BSSID={net.bssid} "
                    f"CH={net.channel} ENC=WPA3-Transition"
                ),
            )],
            remediation="Use WPA3-only mode where all clients support it.",
        )

    return None


def _assess_wps(net: WifiNetwork) -> Finding | None:
    """Return a finding if WPS is enabled."""
    if not net.wps_enabled:
        return None
    return Finding(
        title=f"WPS enabled on: {net.ssid or '<hidden>'}",
        description=(
            f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) has Wi-Fi "
            f"Protected Setup (WPS) enabled. The WPS PIN can be brute-forced "
            f"in hours using tools like Reaver, bypassing WPA2 entirely."
        ),
        severity=Severity.HIGH,
        module_name="recon.wifi_recon",
        attack_technique_ids=["T1040"],
        evidence=[Evidence(
            kind="wifi_wps",
            data=f"SSID={net.ssid!r} BSSID={net.bssid} WPS=enabled",
        )],
        remediation="Disable WPS on the access point.",
    )


def _assess_enterprise(net: WifiNetwork) -> Finding | None:
    """Check enterprise WiFi for weak EAP configurations."""
    if net.encryption != "WPA2-Enterprise":
        return None

    if net.eap_type == "PEAP":
        return Finding(
            title=f"PEAP without cert validation risk: {net.ssid or '<hidden>'}",
            description=(
                f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) uses "
                f"PEAP. If clients do not validate the RADIUS server certificate, "
                f"credentials can be captured via evil twin + hostile RADIUS."
            ),
            severity=Severity.MEDIUM,
            module_name="recon.wifi_recon",
            attack_technique_ids=["T1040", "T1016"],
            evidence=[Evidence(
                kind="wifi_eap",
                data=f"SSID={net.ssid!r} BSSID={net.bssid} EAP=PEAP",
            )],
            remediation=(
                "Enforce server certificate validation on all clients. "
                "Consider migrating to EAP-TLS (certificate-based)."
            ),
        )

    if net.eap_type == "EAP-TTLS":
        return Finding(
            title=f"EAP-TTLS downgrade risk: {net.ssid or '<hidden>'}",
            description=(
                f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) uses "
                f"EAP-TTLS, which is susceptible to inner-protocol downgrade "
                f"attacks if certificate validation is not enforced."
            ),
            severity=Severity.MEDIUM,
            module_name="recon.wifi_recon",
            attack_technique_ids=["T1040", "T1016"],
            evidence=[Evidence(
                kind="wifi_eap",
                data=f"SSID={net.ssid!r} BSSID={net.bssid} EAP=EAP-TTLS",
            )],
            remediation=(
                "Enforce server certificate pinning and consider migration to EAP-TLS."
            ),
        )

    return None


def _detect_rogue_aps(
    networks: list[WifiNetwork],
    expected_ssids: set[str] | None,
) -> list[Finding]:
    """Detect potential rogue access points."""
    findings: list[Finding] = []

    # Group by SSID to detect evil twins (same SSID, different BSSIDs/channels)
    ssid_to_nets: dict[str, list[WifiNetwork]] = {}
    for net in networks:
        if net.ssid:
            ssid_to_nets.setdefault(net.ssid, []).append(net)

    # Check for duplicate SSIDs on different channels (evil twin indicator)
    for ssid, nets in ssid_to_nets.items():
        if len(nets) < 2:
            continue
        channels = {n.channel for n in nets}
        if len(channels) > 1:
            bssid_list = ", ".join(f"{n.bssid} (ch{n.channel})" for n in nets)
            findings.append(Finding(
                title=f"Potential evil twin detected: {ssid}",
                description=(
                    f"SSID {ssid!r} was seen from {len(nets)} BSSIDs on "
                    f"{len(channels)} different channels: {bssid_list}. "
                    f"This may indicate an evil twin attack."
                ),
                severity=Severity.HIGH,
                module_name="recon.wifi_recon",
                attack_technique_ids=["T1040"],
                evidence=[Evidence(
                    kind="wifi_evil_twin",
                    data=f"SSID={ssid!r} BSSIDs=[{bssid_list}]",
                )],
                remediation=(
                    "Investigate whether all listed BSSIDs are legitimate "
                    "corporate access points. Use 802.1X with certificate "
                    "validation to mitigate evil twin attacks."
                ),
            ))

    # Check against known phishing SSID patterns
    for net in networks:
        if not net.ssid:
            continue
        for pat in _ROGUE_SSID_PATTERNS:
            if pat.search(net.ssid):
                findings.append(Finding(
                    title=f"Suspicious SSID pattern: {net.ssid}",
                    description=(
                        f"Network {net.ssid!r} (BSSID {net.bssid}) matches a "
                        f"common phishing/rogue AP naming pattern."
                    ),
                    severity=Severity.MEDIUM,
                    module_name="recon.wifi_recon",
                    attack_technique_ids=["T1040"],
                    evidence=[Evidence(
                        kind="wifi_rogue_ssid",
                        data=f"SSID={net.ssid!r} BSSID={net.bssid} pattern={pat.pattern}",
                    )],
                    remediation="Verify this is a legitimate network.",
                ))
                break  # One finding per SSID

    # Check for unexpected SSIDs if corporate list provided
    if expected_ssids:
        for net in networks:
            if net.ssid and net.ssid not in expected_ssids:
                findings.append(Finding(
                    title=f"Unexpected SSID: {net.ssid}",
                    description=(
                        f"Network {net.ssid!r} (BSSID {net.bssid}) is not in the "
                        f"expected corporate SSID list. This may be a rogue AP."
                    ),
                    severity=Severity.MEDIUM,
                    module_name="recon.wifi_recon",
                    attack_technique_ids=["T1040"],
                    evidence=[Evidence(
                        kind="wifi_unexpected",
                        data=(
                            f"SSID={net.ssid!r} BSSID={net.bssid} "
                            f"expected={sorted(expected_ssids)}"
                        ),
                    )],
                    remediation="Investigate and remove unauthorized access points.",
                ))

    # Unusually strong signal (potential nearby rogue)
    for net in networks:
        if net.signal_dbm > _SUSPICIOUS_SIGNAL_DBM:
            findings.append(Finding(
                title=f"Unusually strong AP signal: {net.ssid or '<hidden>'}",
                description=(
                    f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) has an "
                    f"unusually strong signal of {net.signal_dbm} dBm. This may "
                    f"indicate a rogue AP placed in close physical proximity."
                ),
                severity=Severity.MEDIUM,
                module_name="recon.wifi_recon",
                attack_technique_ids=["T1040"],
                evidence=[Evidence(
                    kind="wifi_strong_signal",
                    data=(
                        f"SSID={net.ssid!r} BSSID={net.bssid} "
                        f"signal={net.signal_dbm}dBm"
                    ),
                )],
                remediation="Physically locate this access point and verify it is authorized.",
            ))

    return findings


def _analyze_channels(networks: list[WifiNetwork]) -> list[Finding]:
    """Analyze channel usage for congestion and non-standard channels."""
    findings: list[Finding] = []

    # Channel congestion: count APs per channel
    channel_counts: dict[int, list[str]] = {}
    for net in networks:
        if net.channel > 0:
            channel_counts.setdefault(net.channel, []).append(
                net.ssid or net.bssid
            )

    for ch, ssids in channel_counts.items():
        if len(ssids) >= 5:
            findings.append(Finding(
                title=f"Channel congestion on channel {ch}",
                description=(
                    f"Channel {ch} has {len(ssids)} access points, which may "
                    f"cause interference and degrade network performance: "
                    f"{', '.join(ssids[:10])}"
                    + (f" (and {len(ssids) - 10} more)" if len(ssids) > 10 else "")
                ),
                severity=Severity.LOW,
                module_name="recon.wifi_recon",
                attack_technique_ids=["T1016"],
                evidence=[Evidence(
                    kind="wifi_congestion",
                    data=f"channel={ch} ap_count={len(ssids)}",
                )],
                remediation=(
                    "Reconfigure access points to use less congested channels."
                ),
            ))

    # Non-standard channels
    all_standard = _STANDARD_24GHZ_CHANNELS | _STANDARD_5GHZ_CHANNELS
    for net in networks:
        if net.channel > 0 and net.channel not in all_standard:
            findings.append(Finding(
                title=f"Non-standard channel {net.channel}: {net.ssid or '<hidden>'}",
                description=(
                    f"Network {net.ssid or '<hidden>'} (BSSID {net.bssid}) is "
                    f"operating on non-standard channel {net.channel}."
                ),
                severity=Severity.LOW,
                module_name="recon.wifi_recon",
                attack_technique_ids=["T1016"],
                evidence=[Evidence(
                    kind="wifi_channel",
                    data=f"SSID={net.ssid!r} BSSID={net.bssid} CH={net.channel}",
                )],
                remediation="Verify this channel assignment is intentional.",
            ))

    return findings


def _detect_hidden_ssids(networks: list[WifiNetwork]) -> list[Finding]:
    """Flag hidden (cloaked) SSIDs."""
    findings: list[Finding] = []
    for net in networks:
        if net.hidden:
            findings.append(Finding(
                title=f"Hidden SSID detected: BSSID {net.bssid}",
                description=(
                    f"An access point with BSSID {net.bssid} on channel "
                    f"{net.channel} is broadcasting with a hidden SSID. "
                    f"Hidden SSIDs provide no real security and can be "
                    f"trivially revealed via probe response capture."
                ),
                severity=Severity.LOW,
                module_name="recon.wifi_recon",
                attack_technique_ids=["T1016"],
                evidence=[Evidence(
                    kind="wifi_hidden",
                    data=f"BSSID={net.bssid} CH={net.channel} signal={net.signal_dbm}dBm",
                )],
                remediation=(
                    "Hidden SSIDs do not improve security. Consider making "
                    "the SSID visible and relying on proper encryption instead."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class WifiReconModule(BaseModule):
    """Passive WiFi reconnaissance and security assessment.

    Discovers wireless networks, assesses their encryption strength,
    detects potential rogue access points, and analyzes channel usage.
    All scanning is passive (no deauth frames, no injection).
    """

    name = "recon.wifi_recon"
    description = "Passive WiFi network discovery and security assessment"
    phase = Phase.RECON
    attack_technique_ids = ["T1040", "T1016"]
    required_facts: list[str] = []
    produced_facts = ["wifi.networks", "wifi.rogue_ap", "wifi.weak_encryption"]
    safety = ExploitSafety.SAFE

    async def check(self, ctx: ModuleContext) -> bool:
        """Check whether any wireless interface is available."""
        ifaces = await _detect_interfaces()
        return len(ifaces) > 0

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        # Detect wireless interfaces
        ifaces = await _detect_interfaces()
        if not ifaces:
            log.debug("No wireless interfaces detected — skipping wifi_recon")
            return []

        log.debug("Detected wireless interfaces: %s", ifaces)

        # Scan for networks
        networks = await _scan_networks(ifaces)
        if not networks:
            log.debug("No wireless networks discovered")
            return []

        log.debug("Discovered %d wireless networks", len(networks))

        # Store discovered networks as a fact
        network_dicts = [
            {
                "ssid": n.ssid,
                "bssid": n.bssid,
                "channel": n.channel,
                "signal_dbm": n.signal_dbm,
                "encryption": n.encryption,
                "wps_enabled": n.wps_enabled,
                "hidden": n.hidden,
                "eap_type": n.eap_type,
            }
            for n in networks
        ]
        await ctx.facts.add("wifi.networks", network_dicts, self.name)

        # Summary finding
        enc_counts: dict[str, int] = {}
        for net in networks:
            enc_counts[net.encryption] = enc_counts.get(net.encryption, 0) + 1
        enc_summary = ", ".join(f"{k}: {v}" for k, v in sorted(enc_counts.items()))

        findings.append(Finding(
            title=f"WiFi scan: {len(networks)} networks discovered",
            description=(
                f"Passive WiFi scan found {len(networks)} wireless networks. "
                f"Encryption breakdown: {enc_summary}."
            ),
            severity=Severity.INFO,
            module_name=self.name,
            attack_technique_ids=["T1016"],
            evidence=[Evidence(
                kind="wifi_summary",
                data=f"total={len(networks)} encryption=[{enc_summary}]",
            )],
        ))

        # Assess each network's encryption
        weak_encryption_nets: list[str] = []
        for net in networks:
            finding = _assess_encryption(net)
            if finding:
                findings.append(finding)
                weak_encryption_nets.append(net.ssid or net.bssid)

            wps_finding = _assess_wps(net)
            if wps_finding:
                findings.append(wps_finding)
                weak_encryption_nets.append(net.ssid or net.bssid)

            ent_finding = _assess_enterprise(net)
            if ent_finding:
                findings.append(ent_finding)

        if weak_encryption_nets:
            await ctx.facts.add("wifi.weak_encryption", weak_encryption_nets, self.name)

        # Rogue AP detection
        expected_ssids: set[str] | None = None
        try:
            corp_ssids = await ctx.facts.get_values("wifi.expected_ssids")
            if corp_ssids:
                expected_ssids = set(corp_ssids) if isinstance(corp_ssids, list) else None
        except Exception:
            pass

        rogue_findings = _detect_rogue_aps(networks, expected_ssids)
        if rogue_findings:
            findings.extend(rogue_findings)
            rogue_ssids = [
                net.ssid for net in networks
                if any(net.ssid and net.ssid in f.title for f in rogue_findings)
            ]
            if rogue_ssids:
                await ctx.facts.add("wifi.rogue_ap", rogue_ssids, self.name)

        # Hidden SSID detection
        findings.extend(_detect_hidden_ssids(networks))

        # Channel analysis
        findings.extend(_analyze_channels(networks))

        # Client enumeration (Linux only)
        if platform.system() == "Linux":
            for iface in ifaces:
                clients = await _enumerate_clients_linux(iface)
                if clients:
                    findings.append(Finding(
                        title=f"WiFi client enumeration: {len(clients)} clients on {iface}",
                        description=(
                            f"Enumerated {len(clients)} connected wireless clients "
                            f"on interface {iface}."
                        ),
                        severity=Severity.INFO,
                        module_name=self.name,
                        attack_technique_ids=["T1040"],
                        evidence=[Evidence(
                            kind="wifi_clients",
                            data=f"interface={iface} clients={[c.mac for c in clients]}",
                        )],
                    ))

        return findings
