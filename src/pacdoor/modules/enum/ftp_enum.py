"""FTP enumeration — anonymous access, writable dirs, TLS, file listing."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from pacdoor.core.models import Evidence, Finding, Phase, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Default FTP timeout for all socket operations.
_FTP_TIMEOUT = 10

# Directories commonly holding sensitive data on FTP servers.
_COMMON_DIRS = (
    "/", "/pub", "/incoming", "/upload", "/data", "/backup",
    "/private", "/www", "/htdocs", "/var", "/etc", "/home",
)

# Filenames that indicate sensitive content.
_SENSITIVE_FILENAMES = {
    ".htpasswd", ".env", "shadow", "passwd", "web.config",
    "wp-config.php", "id_rsa", "id_dsa", "authorized_keys",
    "database.yml", "credentials", "secrets", ".git",
}


# ── Raw FTP helpers (async TCP — no library needed) ──────────────────


async def _read_response(
    reader: asyncio.StreamReader,
) -> tuple[int, str]:
    """Read a complete FTP response, handling multi-line replies.

    Returns (status_code, full_text).
    """
    lines: list[str] = []
    while True:
        raw = await asyncio.wait_for(reader.readline(), timeout=_FTP_TIMEOUT)
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        lines.append(line)
        # Single-line: "220 Welcome" or final multi-line: "220 End"
        if len(line) >= 4 and line[3] == " " and line[:3].isdigit():
            break
    code = int(lines[-1][:3])
    return code, "\n".join(lines)


async def _send_command(
    writer: asyncio.StreamWriter,
    reader: asyncio.StreamReader,
    command: str,
) -> tuple[int, str]:
    """Send an FTP command and return the response."""
    writer.write(f"{command}\r\n".encode())
    await writer.drain()
    return await _read_response(reader)


async def _connect_ftp(
    ip: str, port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, int, str] | None:
    """Open a TCP connection to an FTP server and read the banner.

    Returns (reader, writer, banner_code, banner_text) or None.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=_FTP_TIMEOUT,
        )
        code, text = await _read_response(reader)
        return reader, writer, code, text
    except (TimeoutError, OSError):
        return None


async def _close_ftp(writer: asyncio.StreamWriter) -> None:
    """Send QUIT and close the connection."""
    try:
        writer.write(b"QUIT\r\n")
        await writer.drain()
    except Exception:
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


# ── Module ───────────────────────────────────────────────────────────


class FTPEnumModule(BaseModule):
    name = "enum.ftp_enum"
    description = "FTP enumeration — anonymous access, writable dirs, TLS, files"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046"]
    required_facts = ["service.ftp"]
    produced_facts = ["ftp.anonymous", "ftp.writable"]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        ftp_facts = await ctx.facts.get_all("service.ftp")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []  # (host_id, ip, port)

        for fact in ftp_facts:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 21
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
        """Run full FTP enumeration on a single host."""

        # ── 1. Connect and grab banner ───────────────────────────────
        result = await _connect_ftp(ip, port)
        if result is None:
            log.debug("ftp_enum: could not connect to %s:%d", ip, port)
            return

        reader, writer, banner_code, banner_text = result

        # Banner fingerprinting
        if banner_text:
            findings.append(Finding(
                title=f"FTP banner on {ip}:{port}",
                description=(
                    f"FTP service on {ip}:{port} reveals server information "
                    f"via its banner, which aids in fingerprinting and "
                    f"vulnerability identification."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="ftp_banner",
                    data=f"Banner: {banner_text}",
                )],
            ))

        # ── 2. Check TLS support ─────────────────────────────────────
        tls_supported = False
        try:
            code, text = await _send_command(writer, reader, "AUTH TLS")
            tls_supported = code == 234
        except (TimeoutError, OSError):
            pass

        if not tls_supported:
            findings.append(Finding(
                title=f"FTP does not support TLS on {ip}:{port}",
                description=(
                    f"FTP service on {ip}:{port} does not support AUTH TLS. "
                    f"All credentials and data are transmitted in cleartext, "
                    f"allowing eavesdropping and credential theft."
                ),
                severity=Severity.MEDIUM,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="ftp_tls",
                    data=f"AUTH TLS not supported on {ip}:{port}",
                )],
                remediation=(
                    "Enable FTPS (FTP over TLS) on the server or migrate "
                    "to SFTP. Configure the server to require TLS for all "
                    "connections via 'ssl_enable=YES' (vsftpd) or equivalent."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # Close initial connection before anonymous login attempt
        await _close_ftp(writer)

        # ── 3. Anonymous login ───────────────────────────────────────
        result = await _connect_ftp(ip, port)
        if result is None:
            return

        reader, writer, _, _ = result
        anon_success = False

        try:
            code, _ = await _send_command(writer, reader, "USER anonymous")
            if code in (230, 331):
                code, _ = await _send_command(
                    writer, reader, "PASS anonymous@"
                )
                if code == 230:
                    anon_success = True
        except (TimeoutError, OSError):
            pass

        if not anon_success:
            await _close_ftp(writer)
            return

        # Record anonymous access fact
        await ctx.facts.add(
            "ftp.anonymous",
            {"host": ip, "port": port, "anonymous": True},
            self.name,
            host_id=host_id,
        )

        findings.append(Finding(
            title=f"FTP anonymous access on {ip}:{port}",
            description=(
                f"FTP service on {ip}:{port} allows anonymous login. "
                f"Attackers can browse, download, and potentially upload "
                f"files without authentication."
            ),
            severity=Severity.HIGH,
            host_id=host_id,
            module_name=self.name,
            attack_technique_ids=self.attack_technique_ids,
            evidence=[Evidence(
                kind="ftp_anonymous",
                data=f"Anonymous login succeeded on {ip}:{port}",
            )],
            remediation=(
                "Disable anonymous FTP access unless explicitly required. "
                "In vsftpd: set 'anonymous_enable=NO'. In ProFTPD: remove "
                "or comment out the <Anonymous> block."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1046/",
            ],
        ))

        # ── 4. Enumerate files in common directories ─────────────────
        sensitive_found: list[str] = []

        for dirname in _COMMON_DIRS:
            try:
                code, _ = await _send_command(writer, reader, f"CWD {dirname}")
                if code != 250:
                    continue

                # Use PASV mode for LIST
                code, pasv_text = await _send_command(writer, reader, "PASV")
                if code != 227:
                    continue

                # Parse PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
                data_ip, data_port = _parse_pasv(pasv_text)
                if data_ip is None:
                    continue

                # Open data connection and send LIST
                try:
                    data_reader, data_writer = await asyncio.wait_for(
                        asyncio.open_connection(data_ip, data_port),
                        timeout=_FTP_TIMEOUT,
                    )
                except (TimeoutError, OSError):
                    continue

                code, _ = await _send_command(writer, reader, "LIST")
                if code not in (125, 150):
                    try:
                        data_writer.close()
                        await data_writer.wait_closed()
                    except Exception:
                        pass
                    continue

                # Read directory listing
                listing_data = b""
                with contextlib.suppress(TimeoutError):
                    listing_data = await asyncio.wait_for(
                        data_reader.read(65536),
                        timeout=_FTP_TIMEOUT,
                    )

                try:
                    data_writer.close()
                    await data_writer.wait_closed()
                except Exception:
                    pass

                # Read transfer complete response
                with contextlib.suppress(TimeoutError, OSError):
                    await _read_response(reader)

                listing = listing_data.decode("utf-8", errors="replace")
                for line in listing.splitlines():
                    # Typical ls -l format: last field is filename
                    parts = line.split()
                    if parts:
                        filename = parts[-1]
                        lower = filename.lower()
                        for sensitive in _SENSITIVE_FILENAMES:
                            if sensitive in lower:
                                path = (
                                    f"{dirname}/{filename}"
                                    if dirname != "/"
                                    else f"/{filename}"
                                )
                                sensitive_found.append(path)
                                break

            except (TimeoutError, OSError):
                continue

        if sensitive_found:
            file_list = "\n".join(f"  - {f}" for f in sensitive_found)
            findings.append(Finding(
                title=f"Sensitive files on FTP {ip}:{port}",
                description=(
                    f"Found {len(sensitive_found)} potentially sensitive "
                    f"file(s) accessible via anonymous FTP on {ip}:{port}."
                ),
                severity=Severity.HIGH,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="ftp_files",
                    data=f"Sensitive files found:\n{file_list}",
                )],
                remediation=(
                    "Remove sensitive files from the FTP root or restrict "
                    "access to authenticated users only. Review all files "
                    "in the FTP directory tree for credentials, keys, and "
                    "configuration data."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 5. Check writable directories ────────────────────────────
        writable_dirs: list[str] = []
        test_filename = "__pacdoor_write_test__"

        for dirname in _COMMON_DIRS:
            try:
                code, _ = await _send_command(writer, reader, f"CWD {dirname}")
                if code != 250:
                    continue

                # Use PASV for STOR
                code, pasv_text = await _send_command(writer, reader, "PASV")
                if code != 227:
                    continue

                data_ip, data_port = _parse_pasv(pasv_text)
                if data_ip is None:
                    continue

                try:
                    data_reader, data_writer = await asyncio.wait_for(
                        asyncio.open_connection(data_ip, data_port),
                        timeout=_FTP_TIMEOUT,
                    )
                except (TimeoutError, OSError):
                    continue

                code, _ = await _send_command(
                    writer, reader, f"STOR {test_filename}"
                )
                if code in (125, 150):
                    # Write succeeded — directory is writable
                    data_writer.write(b"")
                    await data_writer.drain()
                    try:
                        data_writer.close()
                        await data_writer.wait_closed()
                    except Exception:
                        pass

                    # Read transfer complete
                    with contextlib.suppress(TimeoutError, OSError):
                        await _read_response(reader)

                    writable_dirs.append(dirname)

                    # Clean up test file
                    with contextlib.suppress(TimeoutError, OSError):
                        await _send_command(
                            writer, reader, f"DELE {test_filename}"
                        )
                else:
                    try:
                        data_writer.close()
                        await data_writer.wait_closed()
                    except Exception:
                        pass

            except (TimeoutError, OSError):
                continue

        if writable_dirs:
            await ctx.facts.add(
                "ftp.writable",
                {
                    "host": ip,
                    "port": port,
                    "writable_dirs": writable_dirs,
                },
                self.name,
                host_id=host_id,
            )

            dir_list = "\n".join(f"  - {d}" for d in writable_dirs)
            findings.append(Finding(
                title=f"Writable FTP directories on {ip}:{port}",
                description=(
                    f"Found {len(writable_dirs)} writable directory(ies) "
                    f"accessible via anonymous FTP on {ip}:{port}. An "
                    f"attacker can upload malicious files, webshells, or "
                    f"use the server for staging."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="ftp_writable",
                    data=f"Writable directories:\n{dir_list}",
                )],
                remediation=(
                    "Remove write permissions for anonymous users. In "
                    "vsftpd: set 'anon_upload_enable=NO' and "
                    "'anon_mkdir_write_enable=NO'. Review directory "
                    "permissions for the FTP root and all subdirectories."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        await _close_ftp(writer)


def _parse_pasv(response: str) -> tuple[str | None, int | None]:
    """Parse a PASV response to extract the data connection address.

    Example: '227 Entering Passive Mode (192,168,1,1,234,5)'
    Returns (ip, port) or (None, None).
    """
    import re

    m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response)
    if not m:
        return None, None
    ip = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
    port = int(m.group(5)) * 256 + int(m.group(6))
    return ip, port
