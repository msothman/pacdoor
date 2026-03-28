"""HTTP vulnerability checks — security headers and common misconfigurations."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

try:
    import aiohttp
    _aiohttp_available = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    _aiohttp_available = False

from pacdoor.core.models import Evidence, Finding, Phase, Port, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Ports that use HTTPS by default.
HTTPS_PORTS: set[int] = {443, 8443}

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=5) if _aiohttp_available else None

# Security headers to check and their expected behaviour.
SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "label": "HSTS",
        "https_only": True,
        "remediation": (
            "Add the Strict-Transport-Security header to enforce HTTPS. "
            "Example: 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload'."
        ),
    },
    "X-Content-Type-Options": {
        "label": "X-Content-Type-Options",
        "expected": "nosniff",
        "https_only": False,
        "remediation": (
            "Set 'X-Content-Type-Options: nosniff' to prevent MIME-type "
            "sniffing attacks."
        ),
    },
    "Content-Security-Policy": {
        "label": "CSP",
        "https_only": False,
        "remediation": (
            "Implement a Content-Security-Policy header to mitigate XSS "
            "and data injection attacks. Start with a restrictive policy "
            "and loosen as needed."
        ),
    },
    "X-XSS-Protection": {
        "label": "X-XSS-Protection (legacy)",
        "https_only": False,
        "remediation": (
            "Set 'X-XSS-Protection: 0' (modern recommendation) or rely "
            "on Content-Security-Policy. This header is deprecated in "
            "modern browsers but still checked for defence-in-depth."
        ),
    },
    "Permissions-Policy": {
        "label": "Permissions-Policy",
        "https_only": False,
        "remediation": (
            "Add a Permissions-Policy header to control which browser "
            "features the page can use. Example: "
            "'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
        ),
    },
    "Referrer-Policy": {
        "label": "Referrer-Policy",
        "https_only": False,
        "remediation": (
            "Set a Referrer-Policy header to control how much referrer "
            "information is sent. Recommended: "
            "'Referrer-Policy: strict-origin-when-cross-origin'."
        ),
    },
}

# Dangerous HTTP methods that should normally be disabled.
DANGEROUS_METHODS: set[str] = {"PUT", "DELETE", "TRACE"}


def _scheme_for_port(port: int) -> str:
    """Return 'https' for known TLS ports, 'http' otherwise."""
    return "https" if port in HTTPS_PORTS else "http"


class HttpVulnsModule(BaseModule):
    name = "vuln.http_vulns"
    description = "HTTP security header and misconfiguration checks"
    phase = Phase.VULN_SCAN
    attack_technique_ids = ["T1190"]
    required_facts = ["service.http"]
    produced_facts = ["vuln.http.*"]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _aiohttp_available:
            log.debug("aiohttp not installed — skipping HTTP vulnerability checks")
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        http_ports: list[Port] = await ctx.facts.get_values("service.http")
        findings: list[Finding] = []

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=REQUEST_TIMEOUT,
        ) as session:
            for port in http_ports:
                ip = await self.resolve_ip(ctx, port.host_id)
                if ip is None:
                    continue

                scheme = _scheme_for_port(port.port)
                base_url = f"{scheme}://{ip}:{port.port}"
                is_https = scheme == "https"

                port_findings = await self._check_service(
                    ctx, session, base_url, port, is_https,
                )
                findings.extend(port_findings)

        return findings

    async def _check_service(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        base_url: str,
        port: Port,
        is_https: bool,
    ) -> list[Finding]:
        """Run all vulnerability checks against a single HTTP service."""
        findings: list[Finding] = []

        # Fetch the root page once; reuse headers for multiple checks.
        await ctx.rate_limiter.acquire()
        try:
            async with session.get(
                base_url, allow_redirects=False,
            ) as resp:
                headers = resp.headers
                body = await resp.text(errors="replace")
                set_cookie = headers.getall("Set-Cookie", [])

                # 1. Security header checks.
                findings.extend(
                    self._check_security_headers(
                        headers, base_url, port, is_https,
                    )
                )

                # 1b. X-Frame-Options / CSP frame-ancestors.
                findings.extend(
                    self._check_framing_protection(headers, base_url, port)
                )

                # 2. Cookie security flags.
                findings.extend(
                    self._check_cookies(set_cookie, base_url, port, is_https)
                )

                # 4. Information disclosure via headers.
                findings.extend(
                    self._check_info_disclosure(headers, base_url, port)
                )

                # 6. Mixed content (HTTPS pages loading HTTP resources).
                if is_https:
                    findings.extend(
                        self._check_mixed_content(body, base_url, port)
                    )

        except (TimeoutError, aiohttp.ClientError, OSError):
            # Target unreachable for the root request; skip remaining checks.
            return findings

        # 3. CORS misconfiguration (requires a separate request with Origin).
        cors_findings = await self._check_cors(
            ctx, session, base_url, port,
        )
        findings.extend(cors_findings)

        # 5. Dangerous HTTP methods via OPTIONS.
        methods_findings = await self._check_http_methods(
            ctx, session, base_url, port,
        )
        findings.extend(methods_findings)

        # Publish aggregate fact for downstream modules.
        if findings:
            await ctx.facts.add(
                "vuln.http.headers",
                {"count": len(findings), "port": port.port},
                self.name,
                host_id=port.host_id,
            )

        return findings

    # ------------------------------------------------------------------
    # 1. Security headers
    # ------------------------------------------------------------------

    def _check_security_headers(
        self,
        headers: aiohttp.multidict.CIMultiDictProxy,
        base_url: str,
        port: Port,
        is_https: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for header_name, meta in SECURITY_HEADERS.items():
            # Skip HTTPS-only headers when the service is plain HTTP.
            if meta.get("https_only") and not is_https:
                continue

            value = headers.get(header_name)

            if value is None:
                findings.append(Finding(
                    title=f"Missing {meta['label']} header on {base_url}",
                    description=(
                        f"The HTTP response from {base_url} does not include "
                        f"the {header_name} header. This weakens the "
                        f"browser's built-in security protections."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=port.host_id,
                    port_id=port.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="missing_header",
                        data=f"Header '{header_name}' not present",
                    )],
                    remediation=meta["remediation"],
                ))
            elif "expected" in meta and value.lower() != meta["expected"]:
                findings.append(Finding(
                    title=(
                        f"Weak {meta['label']} header on {base_url}: "
                        f"'{value}'"
                    ),
                    description=(
                        f"The {header_name} header is present but set to "
                        f"'{value}' instead of the recommended value "
                        f"'{meta['expected']}'."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=port.host_id,
                    port_id=port.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="http_header",
                        data=f"{header_name}: {value}",
                    )],
                    remediation=meta["remediation"],
                ))

        return findings

    # ------------------------------------------------------------------
    # 1b. Framing protection (X-Frame-Options or CSP frame-ancestors)
    # ------------------------------------------------------------------

    def _check_framing_protection(
        self,
        headers: aiohttp.multidict.CIMultiDictProxy,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        xfo = headers.get("X-Frame-Options")
        csp = headers.get("Content-Security-Policy", "")

        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if xfo is None and not has_frame_ancestors:
            return [Finding(
                title=f"Missing framing protection on {base_url}",
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors "
                    "directive is set. The page may be vulnerable to "
                    "clickjacking attacks."
                ),
                severity=Severity.MEDIUM,
                host_id=port.host_id,
                port_id=port.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="missing_header",
                    data="No X-Frame-Options or CSP frame-ancestors",
                )],
                remediation=(
                    "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: "
                    "SAMEORIGIN', or add 'frame-ancestors' to your "
                    "Content-Security-Policy header."
                ),
            )]
        return []

    # ------------------------------------------------------------------
    # 2. Cookie security
    # ------------------------------------------------------------------

    def _check_cookies(
        self,
        set_cookie_headers: list[str],
        base_url: str,
        port: Port,
        is_https: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for raw_cookie in set_cookie_headers:
            lower = raw_cookie.lower()
            cookie_name = raw_cookie.split("=", 1)[0].strip()
            missing_flags: list[str] = []

            if is_https and "secure" not in lower:
                missing_flags.append("Secure")
            if "httponly" not in lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in lower:
                missing_flags.append("SameSite")

            if missing_flags:
                findings.append(Finding(
                    title=(
                        f"Cookie '{cookie_name}' missing flags: "
                        f"{', '.join(missing_flags)} on {base_url}"
                    ),
                    description=(
                        f"The Set-Cookie header for '{cookie_name}' does "
                        f"not include the {', '.join(missing_flags)} "
                        f"flag(s). This may expose the cookie to theft "
                        f"or misuse."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=port.host_id,
                    port_id=port.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="http_header",
                        data=f"Set-Cookie: {raw_cookie}",
                    )],
                    remediation=(
                        f"Add the missing flag(s) ({', '.join(missing_flags)}) "
                        f"to the Set-Cookie header for '{cookie_name}'. "
                        f"Example: 'Set-Cookie: {cookie_name}=value; "
                        f"Secure; HttpOnly; SameSite=Lax'."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------
    # 3. CORS misconfiguration
    # ------------------------------------------------------------------

    async def _check_cors(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        await ctx.rate_limiter.acquire()
        try:
            evil_origin = "https://evil.com"
            async with session.get(
                base_url,
                headers={"Origin": evil_origin},
                allow_redirects=False,
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get(
                    "Access-Control-Allow-Credentials", "",
                )

                # Reflected origin with credentials is a critical misconfiguration.
                if evil_origin in acao and acac.lower() == "true":
                    await ctx.facts.add(
                        "vuln.http.cors",
                        {"reflected_origin": True, "credentials": True,
                         "port": port.port},
                        self.name,
                        host_id=port.host_id,
                    )
                    return [Finding(
                        title=f"CORS misconfiguration on {base_url}",
                        description=(
                            f"The server reflects the attacker-controlled "
                            f"Origin header '{evil_origin}' in "
                            f"Access-Control-Allow-Origin AND enables "
                            f"Access-Control-Allow-Credentials. This allows "
                            f"any website to make authenticated cross-origin "
                            f"requests and read responses, potentially "
                            f"stealing sensitive data."
                        ),
                        severity=Severity.HIGH,
                        host_id=port.host_id,
                        port_id=port.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[Evidence(
                            kind="http_header",
                            data=(
                                f"Origin: {evil_origin} -> "
                                f"ACAO: {acao}, ACAC: {acac}"
                            ),
                        )],
                        remediation=(
                            "Do not reflect arbitrary Origin values. Use an "
                            "explicit allowlist of trusted origins. Never "
                            "combine a reflected origin with "
                            "Access-Control-Allow-Credentials: true."
                        ),
                    )]

                # Reflected origin without credentials is still notable.
                if evil_origin in acao:
                    await ctx.facts.add(
                        "vuln.http.cors",
                        {"reflected_origin": True, "credentials": False,
                         "port": port.port},
                        self.name,
                        host_id=port.host_id,
                    )
                    return [Finding(
                        title=(
                            f"CORS reflects arbitrary origin on {base_url}"
                        ),
                        description=(
                            "The server reflects the Origin header in "
                            "Access-Control-Allow-Origin. While credentials "
                            "are not allowed, this may still permit "
                            "unintended cross-origin data access."
                        ),
                        severity=Severity.MEDIUM,
                        host_id=port.host_id,
                        port_id=port.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[Evidence(
                            kind="http_header",
                            data=f"Origin: {evil_origin} -> ACAO: {acao}",
                        )],
                        remediation=(
                            "Restrict Access-Control-Allow-Origin to a "
                            "specific allowlist of trusted domains instead "
                            "of reflecting the request Origin."
                        ),
                    )]

        except (TimeoutError, aiohttp.ClientError, OSError):
            pass

        return []

    # ------------------------------------------------------------------
    # 4. Information disclosure
    # ------------------------------------------------------------------

    def _check_info_disclosure(
        self,
        headers: aiohttp.multidict.CIMultiDictProxy,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Server header with version information.
        server = headers.get("Server", "")
        if server and any(ch.isdigit() for ch in server):
            findings.append(Finding(
                title=f"Server version disclosed on {base_url}",
                description=(
                    f"The Server header reveals version information: "
                    f"'{server}'. This helps attackers identify known "
                    f"vulnerabilities for this specific version."
                ),
                severity=Severity.LOW,
                host_id=port.host_id,
                port_id=port.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="http_header",
                    data=f"Server: {server}",
                )],
                remediation=(
                    "Configure the web server to suppress or generalise "
                    "the Server header. For nginx: 'server_tokens off;'. "
                    "For Apache: 'ServerTokens Prod'."
                ),
            ))

        # X-Powered-By header.
        powered_by = headers.get("X-Powered-By")
        if powered_by:
            findings.append(Finding(
                title=f"X-Powered-By disclosed on {base_url}: '{powered_by}'",
                description=(
                    f"The X-Powered-By header reveals the backend "
                    f"technology: '{powered_by}'. This aids attackers in "
                    f"fingerprinting the technology stack."
                ),
                severity=Severity.LOW,
                host_id=port.host_id,
                port_id=port.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="http_header",
                    data=f"X-Powered-By: {powered_by}",
                )],
                remediation=(
                    "Remove the X-Powered-By header. In Express.js: "
                    "'app.disable(\"x-powered-by\")'. In PHP: "
                    "'expose_php = Off' in php.ini."
                ),
            ))

        return findings

    # ------------------------------------------------------------------
    # 5. Dangerous HTTP methods
    # ------------------------------------------------------------------

    async def _check_http_methods(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        await ctx.rate_limiter.acquire()
        try:
            async with session.options(
                base_url, allow_redirects=False,
            ) as resp:
                allow = resp.headers.get("Allow", "")
                if not allow:
                    return []

                methods = {
                    m.strip().upper() for m in allow.split(",") if m.strip()
                }
                dangerous = methods & DANGEROUS_METHODS

                if dangerous:
                    sorted_dangerous = sorted(dangerous)
                    await ctx.facts.add(
                        "vuln.http.methods",
                        {"dangerous": sorted_dangerous, "port": port.port},
                        self.name,
                        host_id=port.host_id,
                    )
                    return [Finding(
                        title=(
                            f"Dangerous HTTP methods enabled on {base_url}: "
                            f"{', '.join(sorted_dangerous)}"
                        ),
                        description=(
                            f"The server allows the following potentially "
                            f"dangerous HTTP methods: "
                            f"{', '.join(sorted_dangerous)}. PUT may allow "
                            f"file upload, DELETE may allow file removal, "
                            f"and TRACE can enable cross-site tracing (XST) "
                            f"attacks."
                        ),
                        severity=Severity.MEDIUM,
                        host_id=port.host_id,
                        port_id=port.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[Evidence(
                            kind="http_header",
                            data=f"Allow: {allow}",
                        )],
                        remediation=(
                            "Disable unnecessary HTTP methods in your web "
                            "server configuration. Only allow GET, POST, "
                            "HEAD, and OPTIONS unless specifically required."
                        ),
                    )]

        except (TimeoutError, aiohttp.ClientError, OSError):
            pass

        return []

    # ------------------------------------------------------------------
    # 6. Mixed content (HTTPS loading HTTP resources)
    # ------------------------------------------------------------------

    def _check_mixed_content(
        self,
        body: str,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        """Scan the HTML body for http:// references on an HTTPS page."""
        # Simple heuristic: look for common HTML attributes loading http://.
        patterns = [
            'src="http://',
            "src='http://",
            'href="http://',
            "href='http://",
            'action="http://',
            "action='http://",
        ]

        found_refs: list[str] = []
        lower_body = body.lower()
        for pattern in patterns:
            idx = 0
            while True:
                idx = lower_body.find(pattern, idx)
                if idx == -1:
                    break
                # Extract the URL (up to the closing quote).
                start = idx + len(pattern) - len("http://")
                end = body.find(
                    pattern[-1],  # matching quote character
                    start + 8,    # skip past "http://"
                )
                if end != -1:
                    ref = body[start:end]
                    if len(ref) < 300:  # sanity limit
                        found_refs.append(ref)
                idx += 1
                if len(found_refs) >= 10:
                    break
            if len(found_refs) >= 10:
                break

        if found_refs:
            unique_refs = sorted(set(found_refs))[:10]
            return [Finding(
                title=f"Mixed content on {base_url}",
                description=(
                    f"This HTTPS page loads resources over plain HTTP, "
                    f"which can be intercepted or modified by a "
                    f"man-in-the-middle attacker. Found {len(unique_refs)} "
                    f"insecure reference(s)."
                ),
                severity=Severity.MEDIUM,
                host_id=port.host_id,
                port_id=port.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="mixed_content",
                    data="\n".join(unique_refs),
                )],
                remediation=(
                    "Update all resource references to use HTTPS or "
                    "protocol-relative URLs. Add 'Content-Security-Policy: "
                    "upgrade-insecure-requests' as a transitional measure."
                ),
            )]

        return []
