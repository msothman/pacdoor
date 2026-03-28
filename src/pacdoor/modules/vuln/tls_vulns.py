"""TLS/SSL vulnerability scanner — protocol versions, certificate issues, ciphers."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

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

# Ports that commonly use TLS.
_TLS_PORTS: set[int] = {443, 8443, 636, 993, 995, 465, 3389, 5986}

# HTTP-based TLS ports (where we check HSTS).
_HTTP_TLS_PORTS: set[int] = {443, 8443}

# Deprecated protocol versions to check (name, ssl constant or None).
_DEPRECATED_PROTOCOLS: list[tuple[str, int | None]] = []

# We build the list dynamically since not all Python builds have all constants.
for _name, _attr in [
    ("SSLv3", "PROTOCOL_SSLv3"),
    ("TLSv1.0", "PROTOCOL_TLSv1"),
    ("TLSv1.1", "PROTOCOL_TLSv1_1"),
]:
    _const = getattr(ssl, _attr, None)
    if _const is not None:
        _DEPRECATED_PROTOCOLS.append((_name, _const))

# Weak signature algorithms.
_WEAK_SIG_ALGOS: set[str] = {"sha1WithRSAEncryption", "md5WithRSAEncryption", "sha1"}


# ── Helpers (all synchronous — run via asyncio.to_thread) ────────────


def _connect_tls(
    ip: str,
    port: int,
    server_hostname: str | None = None,
    timeout: int = 10,
) -> dict[str, Any] | None:
    """Connect with TLS using the default (best) protocol and return cert info.

    Returns a dict with certificate details or None on failure.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We want to inspect even invalid certs
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_hostname or ip) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_parsed = ssock.getpeercert()
                protocol_version = ssock.version()
                cipher = ssock.cipher()

                result: dict[str, Any] = {
                    "protocol": protocol_version,
                    "cipher": cipher,
                    "cert_binary": cert_bin,
                    "cert_parsed": cert_parsed,
                }
                return result
    except Exception:
        return None


def _check_deprecated_protocol(
    ip: str,
    port: int,
    protocol_name: str,
    protocol_const: int,
    timeout: int = 5,
) -> bool:
    """Test whether the server accepts a deprecated TLS/SSL version."""
    try:
        ctx = ssl.SSLContext(protocol_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip):
                return True
    except Exception:
        return False


def _check_cert_validity(cert_bin: bytes, ip: str, port: int) -> dict[str, Any]:
    """Analyze a DER-encoded certificate for common issues.

    Returns a dict of issues found.
    """
    issues: dict[str, Any] = {}
    try:
        # Use ssl to decode the DER cert for basic inspection
        # We parse the PEM-encoded form through ssl's helper
        import ssl as _ssl

        # Get human-readable text by loading into a temporary context
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        # Re-connect to get the parsed cert dict (with dates etc.)
        with socket.create_connection((ip, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # Check expiry
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            expiry = datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=UTC)
                            if expiry < datetime.now(UTC):
                                issues["expired"] = not_after
                        except ValueError:
                            pass

                    # Check self-signed (issuer == subject)
                    issuer = cert.get("issuer")
                    subject = cert.get("subject")
                    if issuer and subject and issuer == subject:
                        issues["self_signed"] = True

                    # Check SANs for wildcard
                    sans = cert.get("subjectAltName", ())
                    for _san_type, san_value in sans:
                        if san_value.startswith("*."):
                            issues["wildcard"] = san_value
                            break
    except Exception:
        pass

    return issues


def _get_cert_details(cert_bin: bytes) -> dict[str, Any]:
    """Extract detailed certificate information from DER bytes.

    Uses the cryptography library if available, falls back to basic ssl parsing.
    """
    details: dict[str, Any] = {}
    try:
        from cryptography import x509  # type: ignore[import-untyped]
        from cryptography.hazmat.primitives.asymmetric import (  # type: ignore[import-untyped]
            dsa,
            ec,
            rsa,
        )

        cert = x509.load_der_x509_certificate(cert_bin)

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid._name
        details["signature_algorithm"] = sig_algo

        # Key size
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            details["key_type"] = "RSA"
            details["key_bits"] = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            details["key_type"] = "EC"
            details["key_bits"] = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            details["key_type"] = "DSA"
            details["key_bits"] = pub_key.key_size

        # Subject
        details["subject"] = cert.subject.rfc4514_string()
        # Issuer
        details["issuer"] = cert.issuer.rfc4514_string()
        # Validity
        details["not_before"] = cert.not_valid_before_utc.isoformat()
        details["not_after"] = cert.not_valid_after_utc.isoformat()
        # Self-signed check
        details["self_signed"] = cert.subject == cert.issuer
        # Expired check
        details["expired"] = cert.not_valid_after_utc < datetime.now(UTC)

    except ImportError:
        log.debug("cryptography library not available — limited cert analysis")
    except Exception:
        pass
    return details


def _check_hsts(ip: str, port: int, timeout: int = 5) -> str | None:
    """Check for HSTS header on an HTTP/TLS endpoint.

    Returns the Strict-Transport-Security header value if present, else None.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode("ascii")
                ssock.sendall(request)
                response = b""
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break

                headers = response.decode("utf-8", errors="replace")
                for line in headers.split("\r\n"):
                    if line.lower().startswith("strict-transport-security:"):
                        return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


# ── Module ───────────────────────────────────────────────────────────


class TLSVulnsModule(BaseModule):
    name = "vuln.tls_vulns"
    description = "TLS/SSL vulnerability scanner — protocols, certificates, configuration"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1557"]
    required_facts = ["port.open"]
    produced_facts = [
        "vuln.tls.*",
    ]

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        port_facts = await ctx.facts.get_all("port.open")
        seen: set[tuple[str, int]] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in port_facts:
            host_id = fact.host_id
            if host_id is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else None
            if port_num is None or port_num not in _TLS_PORTS:
                continue
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            key = (host_id, port_num)
            if key in seen:
                continue
            seen.add(key)
            targets.append((host_id, ip, port_num))

        for host_id, ip, port_num in targets:
            await self._scan_host_port(ctx, findings, host_id, ip, port_num)

        return findings

    async def _scan_host_port(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Run all TLS checks on a single host:port."""

        # ── 1. Connect and get certificate ───────────────────────────
        tls_info = await asyncio.to_thread(_connect_tls, ip, port)
        if tls_info is None:
            log.debug("tls_vulns: could not TLS-connect to %s:%d", ip, port)
            return

        cert_bin = tls_info.get("cert_binary")

        # ── 2. Check deprecated protocol versions ────────────────────
        for proto_name, proto_const in _DEPRECATED_PROTOCOLS:
            accepted = await asyncio.to_thread(
                _check_deprecated_protocol, ip, port, proto_name, proto_const,
            )
            if accepted:
                await ctx.facts.add(
                    "vuln.tls.deprecated_protocol",
                    {"host": ip, "port": port, "protocol": proto_name},
                    self.name,
                    host_id=host_id,
                )
                findings.append(Finding(
                    title=f"Deprecated {proto_name} supported on {ip}:{port}",
                    description=(
                        f"Host {ip}:{port} accepts connections using {proto_name}, "
                        "which is deprecated and contains known vulnerabilities "
                        "(e.g. POODLE for SSLv3, BEAST for TLS 1.0). Modern clients "
                        "no longer support these protocol versions."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1557"],
                    evidence=[Evidence(
                        kind="deprecated_tls",
                        data=f"{proto_name} accepted on {ip}:{port}",
                    )],
                    remediation=(
                        f"Disable {proto_name} on the server. Only TLS 1.2 and "
                        "TLS 1.3 should be enabled. For Apache: 'SSLProtocol all "
                        "-SSLv3 -TLSv1 -TLSv1.1'. For Nginx: "
                        "'ssl_protocols TLSv1.2 TLSv1.3;'."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1557/",
                    ],
                ))

        # ── 3. Certificate analysis ──────────────────────────────────
        if cert_bin:
            cert_details = await asyncio.to_thread(_get_cert_details, cert_bin)
            cert_issues = await asyncio.to_thread(
                _check_cert_validity, cert_bin, ip, port,
            )

            # Expired certificate
            expired = cert_details.get("expired", False) or "expired" in cert_issues
            if expired:
                not_after = cert_details.get("not_after", cert_issues.get("expired", "unknown"))
                await ctx.facts.add(
                    "vuln.tls.expired_cert",
                    {"host": ip, "port": port, "not_after": str(not_after)},
                    self.name,
                    host_id=host_id,
                )
                findings.append(Finding(
                    title=f"Expired TLS certificate on {ip}:{port}",
                    description=(
                        f"The TLS certificate on {ip}:{port} has expired "
                        f"(not_after: {not_after}). Expired certificates cause "
                        "browser warnings and may indicate abandoned or "
                        "unmaintained services."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1557"],
                    evidence=[Evidence(
                        kind="expired_cert",
                        data=f"Certificate expired: not_after={not_after} on {ip}:{port}",
                    )],
                    remediation="Renew the TLS certificate before expiry using your CA or Let's Encrypt.",
                ))

            # Self-signed certificate
            self_signed = cert_details.get("self_signed", False) or cert_issues.get("self_signed", False)
            if self_signed:
                await ctx.facts.add(
                    "vuln.tls.self_signed",
                    {"host": ip, "port": port},
                    self.name,
                    host_id=host_id,
                )
                findings.append(Finding(
                    title=f"Self-signed TLS certificate on {ip}:{port}",
                    description=(
                        f"The TLS certificate on {ip}:{port} is self-signed. "
                        "Self-signed certificates are not trusted by default and "
                        "users may be conditioned to accept certificate warnings, "
                        "making MITM attacks easier."
                    ),
                    severity=Severity.LOW,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1557"],
                    evidence=[Evidence(
                        kind="self_signed_cert",
                        data=f"Self-signed certificate on {ip}:{port}",
                    )],
                    remediation=(
                        "Replace the self-signed certificate with one issued by "
                        "a trusted CA. Use Let's Encrypt for free, automated certificates."
                    ),
                ))

            # Weak signature algorithm
            sig_algo = cert_details.get("signature_algorithm", "")
            if sig_algo and any(weak in sig_algo.lower() for weak in ("sha1", "md5")):
                await ctx.facts.add(
                    "vuln.tls.weak_signature",
                    {"host": ip, "port": port, "algorithm": sig_algo},
                    self.name,
                    host_id=host_id,
                )
                findings.append(Finding(
                    title=f"Weak certificate signature ({sig_algo}) on {ip}:{port}",
                    description=(
                        f"The TLS certificate on {ip}:{port} uses {sig_algo} for "
                        "signing, which is considered cryptographically weak. "
                        "SHA-1 collision attacks are practical and certificates "
                        "signed with SHA-1 or MD5 should be replaced."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1557"],
                    evidence=[Evidence(
                        kind="weak_sig_algo",
                        data=f"Signature algorithm: {sig_algo} on {ip}:{port}",
                    )],
                    remediation=(
                        "Reissue the certificate with SHA-256 or stronger signature algorithm."
                    ),
                ))

            # Short key length
            key_bits = cert_details.get("key_bits")
            key_type = cert_details.get("key_type", "")
            if key_bits is not None and key_type == "RSA" and key_bits < 2048:
                await ctx.facts.add(
                    "vuln.tls.short_key",
                    {"host": ip, "port": port, "key_type": key_type, "key_bits": key_bits},
                    self.name,
                    host_id=host_id,
                )
                findings.append(Finding(
                    title=f"Short RSA key ({key_bits}-bit) on {ip}:{port}",
                    description=(
                        f"The TLS certificate on {ip}:{port} uses a {key_bits}-bit "
                        f"RSA key. Keys shorter than 2048 bits are considered weak "
                        "and may be factorable with sufficient resources."
                    ),
                    severity=Severity.HIGH,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1557"],
                    evidence=[Evidence(
                        kind="short_key",
                        data=f"RSA key: {key_bits} bits on {ip}:{port}",
                    )],
                    remediation="Reissue the certificate with at least a 2048-bit RSA key (4096-bit recommended).",
                ))

            # Wildcard certificate
            wildcard = cert_issues.get("wildcard")
            if wildcard:
                findings.append(Finding(
                    title=f"Wildcard certificate ({wildcard}) on {ip}:{port}",
                    description=(
                        f"The TLS certificate on {ip}:{port} is a wildcard "
                        f"certificate ({wildcard}). Compromise of the private key "
                        "would allow impersonation of all subdomains covered."
                    ),
                    severity=Severity.INFO,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1557"],
                    evidence=[Evidence(
                        kind="wildcard_cert",
                        data=f"Wildcard certificate: {wildcard} on {ip}:{port}",
                    )],
                    remediation=(
                        "Consider using specific per-service certificates instead "
                        "of wildcard certificates where feasible."
                    ),
                ))

        # ── 4. HSTS check for HTTP ports ─────────────────────────────
        if port in _HTTP_TLS_PORTS:
            hsts_value = await asyncio.to_thread(_check_hsts, ip, port)
            if hsts_value is None:
                await ctx.facts.add(
                    "vuln.tls.no_hsts",
                    {"host": ip, "port": port},
                    self.name,
                    host_id=host_id,
                )
                findings.append(Finding(
                    title=f"Missing HSTS header on {ip}:{port}",
                    description=(
                        f"The HTTPS endpoint {ip}:{port} does not send the "
                        "Strict-Transport-Security header. Without HSTS, users "
                        "may be downgraded to HTTP via SSL-stripping attacks."
                    ),
                    severity=Severity.LOW,
                    host_id=host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1557"],
                    evidence=[Evidence(
                        kind="missing_hsts",
                        data=f"No Strict-Transport-Security header on {ip}:{port}",
                    )],
                    remediation=(
                        "Add the Strict-Transport-Security header with a long max-age "
                        "(at least 1 year): 'Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload'."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    ],
                ))
