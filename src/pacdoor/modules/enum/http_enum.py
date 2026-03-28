"""HTTP enumeration — directory bruteforce and technology fingerprinting."""

from __future__ import annotations

import asyncio
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

# Top ~100 most common web directories for bruteforce enumeration.
COMMON_DIRS: list[str] = [
    "admin", "administrator", "api", "app", "assets", "auth",
    "backup", "backups", "bin", "blog", "build",
    "cache", "cgi-bin", "cms", "conf", "config", "console", "content",
    "cp", "cpanel", "css",
    "dashboard", "data", "db", "debug", "demo", "dev", "dist", "doc",
    "docs", "download", "downloads",
    "editor", "email", "error", "errors",
    "files", "fonts", "forum",
    "graphql", "grpc",
    "health", "help", "home", "html",
    "images", "img", "include", "includes", "info", "install",
    "js", "json",
    "lib", "libs", "log", "login", "logs",
    "mail", "main", "manage", "manager", "media", "members", "misc",
    "modules", "monitor",
    "new", "node_modules",
    "old", "ops", "out",
    "panel", "pages", "php", "phpmyadmin", "plugins", "portal",
    "private", "public",
    "release", "reports", "resources", "rest", "root",
    "scripts", "search", "secret", "secure", "server", "service",
    "services", "setup", "shared", "shell", "site", "sites",
    "src", "staff", "static", "stats", "status", "storage", "store",
    "system",
    "temp", "template", "templates", "test", "testing", "tmp",
    "tools",
    "upload", "uploads", "user", "users", "usr",
    "v1", "v2", "var", "vendor", "version",
    "web", "webmail", "wp-content", "wp-includes",
]

# Sensitive paths that frequently indicate misconfigurations or leaks.
SENSITIVE_PATHS: list[str] = [
    "/.git/HEAD",
    "/.env",
    "/robots.txt",
    "/sitemap.xml",
    "/.htaccess",
    "/wp-admin",
    "/admin",
    "/api",
    "/swagger.json",
    "/openapi.json",
    "/actuator",
    "/_debug",
    "/console",
    "/phpinfo.php",
    "/server-status",
    "/elmah.axd",
    "/web.config",
]

# HTTP header names used for technology fingerprinting.
TECH_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-Generator",
]

# Ports that use HTTPS by default.
HTTPS_PORTS: set[int] = {443, 8443}

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=5) if _aiohttp_available else None


def _scheme_for_port(port: int) -> str:
    """Return 'https' for known TLS ports, 'http' otherwise."""
    return "https" if port in HTTPS_PORTS else "http"


class HttpEnumModule(BaseModule):
    name = "enum.http_enum"
    description = "HTTP directory bruteforce and technology fingerprinting"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1595.003"]
    required_facts = ["service.http"]
    produced_facts = ["http.paths", "http.technology", "http.directory_listing"]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _aiohttp_available:
            log.debug("aiohttp not installed — skipping HTTP enumeration")
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        http_ports: list[Port] = await ctx.facts.get_values("service.http")
        findings: list[Finding] = []

        # Limit concurrent connections to avoid overwhelming targets.
        sem = asyncio.Semaphore(20)

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

                port_findings = await self._enumerate_service(
                    ctx, session, sem, base_url, port,
                )
                findings.extend(port_findings)

        return findings

    async def _enumerate_service(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        """Run all enumeration checks against a single HTTP service."""
        findings: list[Finding] = []

        # 1. Technology fingerprinting from root page headers.
        tech_findings = await self._fingerprint_technology(
            ctx, session, sem, base_url, port,
        )
        findings.extend(tech_findings)

        # 2. Check known sensitive paths.
        sensitive_findings = await self._check_sensitive_paths(
            ctx, session, sem, base_url, port,
        )
        findings.extend(sensitive_findings)

        # 3. Directory bruteforce with the embedded wordlist.
        dir_findings = await self._bruteforce_directories(
            ctx, session, sem, base_url, port,
        )
        findings.extend(dir_findings)

        return findings

    # ------------------------------------------------------------------
    # Technology fingerprinting
    # ------------------------------------------------------------------

    async def _fingerprint_technology(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        findings: list[Finding] = []
        await ctx.rate_limiter.acquire()

        try:
            async with sem, session.get(base_url, allow_redirects=False) as resp:
                headers = resp.headers

                for header_name in TECH_HEADERS:
                    value = headers.get(header_name)
                    if value:
                        await ctx.facts.add(
                            "http.technology",
                            {"header": header_name, "value": value,
                             "port": port.port},
                            self.name,
                            host_id=port.host_id,
                        )
                        findings.append(Finding(
                            title=f"Technology detected: {header_name}: {value}",
                            description=(
                                f"{base_url} exposes {header_name} header "
                                f"with value '{value}'. This reveals server "
                                f"technology information to attackers."
                            ),
                            severity=Severity.INFO,
                            host_id=port.host_id,
                            port_id=port.id,
                            module_name=self.name,
                            attack_technique_ids=self.attack_technique_ids,
                            evidence=[Evidence(
                                kind="http_header",
                                data=f"{header_name}: {value}",
                            )],
                            remediation=(
                                f"Remove or suppress the {header_name} header "
                                f"to reduce information disclosure."
                            ),
                        ))
        except (TimeoutError, aiohttp.ClientError, OSError):
            pass

        return findings

    # ------------------------------------------------------------------
    # Sensitive path checks
    # ------------------------------------------------------------------

    async def _check_sensitive_paths(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        """Probe known sensitive paths and flag anything accessible."""
        findings: list[Finding] = []

        async def probe(path: str) -> None:
            await ctx.rate_limiter.acquire()
            try:
                async with sem:
                    url = f"{base_url}{path}"
                    async with session.get(
                        url, allow_redirects=False,
                    ) as resp:
                        if resp.status >= 400:
                            return

                        body = await resp.text(errors="replace")

                        # -- Exposed .git repository ----------------------
                        if path == "/.git/HEAD" and body.startswith("ref:"):
                            await ctx.facts.add(
                                "http.paths",
                                {"path": path, "type": "git_repo",
                                 "port": port.port},
                                self.name,
                                host_id=port.host_id,
                            )
                            findings.append(Finding(
                                title=f"Exposed .git repository at {url}",
                                description=(
                                    "The .git directory is publicly accessible. "
                                    "An attacker can reconstruct source code, "
                                    "commit history, and potentially extract "
                                    "secrets from the repository."
                                ),
                                severity=Severity.HIGH,
                                host_id=port.host_id,
                                port_id=port.id,
                                module_name=self.name,
                                attack_technique_ids=self.attack_technique_ids,
                                evidence=[Evidence(
                                    kind="http_response",
                                    data=f"GET {url} -> {resp.status}: "
                                         f"{body[:200]}",
                                )],
                                remediation=(
                                    "Block access to the .git directory via "
                                    "web server configuration. For nginx: "
                                    "'location ~ /\\.git { deny all; }'. "
                                    "For Apache: "
                                    "'RedirectMatch 404 /\\.git'."
                                ),
                            ))
                            return

                        # -- Directory listing ----------------------------
                        if "Index of" in body:
                            await ctx.facts.add(
                                "http.directory_listing",
                                {"path": path, "port": port.port},
                                self.name,
                                host_id=port.host_id,
                            )
                            findings.append(Finding(
                                title=f"Directory listing enabled at {url}",
                                description=(
                                    "Directory listing is enabled, exposing "
                                    "file and directory names to anyone. This "
                                    "can leak sensitive file paths, backup "
                                    "files, and internal structure."
                                ),
                                severity=Severity.MEDIUM,
                                host_id=port.host_id,
                                port_id=port.id,
                                module_name=self.name,
                                attack_technique_ids=self.attack_technique_ids,
                                evidence=[Evidence(
                                    kind="http_response",
                                    data=f"GET {url} -> {resp.status}: "
                                         f"contains 'Index of'",
                                )],
                                remediation=(
                                    "Disable directory listing in your web "
                                    "server configuration. For nginx: "
                                    "'autoindex off;'. For Apache: "
                                    "'Options -Indexes'."
                                ),
                            ))
                            return

                        # -- .env file ------------------------------------
                        if path == "/.env":
                            await ctx.facts.add(
                                "http.paths",
                                {"path": path, "type": "env_file",
                                 "port": port.port},
                                self.name,
                                host_id=port.host_id,
                            )
                            findings.append(Finding(
                                title=f"Exposed .env file at {url}",
                                description=(
                                    "The .env file is publicly accessible and "
                                    "may contain database credentials, API "
                                    "keys, and other secrets."
                                ),
                                severity=Severity.HIGH,
                                host_id=port.host_id,
                                port_id=port.id,
                                module_name=self.name,
                                attack_technique_ids=self.attack_technique_ids,
                                evidence=[Evidence(
                                    kind="http_response",
                                    data=f"GET {url} -> {resp.status}",
                                )],
                                remediation=(
                                    "Block access to .env files in web server "
                                    "configuration and ensure they are not in "
                                    "the web root."
                                ),
                            ))
                            return

                        # -- Generic accessible sensitive path ------------
                        severity = _sensitive_path_severity(path)
                        await ctx.facts.add(
                            "http.paths",
                            {"path": path, "type": "sensitive",
                             "port": port.port},
                            self.name,
                            host_id=port.host_id,
                        )
                        findings.append(Finding(
                            title=f"Accessible sensitive path: {url}",
                            description=(
                                f"The path {path} is accessible and may "
                                f"expose configuration, debug endpoints, "
                                f"or administrative interfaces."
                            ),
                            severity=severity,
                            host_id=port.host_id,
                            port_id=port.id,
                            module_name=self.name,
                            attack_technique_ids=self.attack_technique_ids,
                            evidence=[Evidence(
                                kind="http_response",
                                data=f"GET {url} -> {resp.status}",
                            )],
                            remediation=(
                                f"Restrict access to {path} by IP "
                                f"allowlisting or authentication, or remove "
                                f"it from the web root if not needed."
                            ),
                        ))

            except (TimeoutError, aiohttp.ClientError, OSError):
                pass

        tasks = [probe(path) for path in SENSITIVE_PATHS]
        await asyncio.gather(*tasks)

        return findings

    # ------------------------------------------------------------------
    # Directory bruteforce
    # ------------------------------------------------------------------

    async def _bruteforce_directories(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        port: Port,
    ) -> list[Finding]:
        """Bruteforce common directory names and report those found."""
        findings: list[Finding] = []
        discovered: list[str] = []

        async def try_dir(dirname: str) -> None:
            await ctx.rate_limiter.acquire()
            try:
                async with sem:
                    url = f"{base_url}/{dirname}/"
                    async with session.get(
                        url, allow_redirects=False,
                    ) as resp:
                        # Accept 200 and 3xx redirects as indicators
                        # that the directory exists.
                        if resp.status >= 400:
                            return

                        body = await resp.text(errors="replace")

                        await ctx.facts.add(
                            "http.paths",
                            {"path": f"/{dirname}/", "type": "directory",
                             "status": resp.status, "port": port.port},
                            self.name,
                            host_id=port.host_id,
                        )
                        discovered.append(f"/{dirname}/ ({resp.status})")

                        # Check for directory listing on this directory.
                        if "Index of" in body:
                            await ctx.facts.add(
                                "http.directory_listing",
                                {"path": f"/{dirname}/", "port": port.port},
                                self.name,
                                host_id=port.host_id,
                            )
                            findings.append(Finding(
                                title=f"Directory listing at {url}",
                                description=(
                                    f"Directory listing is enabled at "
                                    f"/{dirname}/, exposing file names."
                                ),
                                severity=Severity.MEDIUM,
                                host_id=port.host_id,
                                port_id=port.id,
                                module_name=self.name,
                                attack_technique_ids=self.attack_technique_ids,
                                evidence=[Evidence(
                                    kind="http_response",
                                    data=f"GET {url} -> {resp.status}: "
                                         f"contains 'Index of'",
                                )],
                                remediation=(
                                    "Disable directory listing. "
                                    "nginx: 'autoindex off;', "
                                    "Apache: 'Options -Indexes'."
                                ),
                            ))
            except (TimeoutError, aiohttp.ClientError, OSError):
                pass

        tasks = [try_dir(d) for d in COMMON_DIRS]
        await asyncio.gather(*tasks)

        if discovered:
            findings.append(Finding(
                title=(
                    f"Directory bruteforce: {len(discovered)} paths found "
                    f"on {base_url}"
                ),
                description=(
                    "Discovered accessible directories via wordlist scan:\n"
                    + "\n".join(f"  {p}" for p in sorted(discovered))
                ),
                severity=Severity.INFO,
                host_id=port.host_id,
                port_id=port.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="directory_bruteforce",
                    data=", ".join(sorted(discovered)),
                )],
                remediation=(
                    "Review each discovered path and remove or restrict "
                    "access to any that should not be publicly available."
                ),
            ))

        return findings


def _sensitive_path_severity(path: str) -> Severity:
    """Assign a severity based on the nature of the sensitive path."""
    high_paths = {"/.env", "/.git/HEAD", "/.htaccess", "/web.config"}
    medium_paths = {
        "/wp-admin", "/admin", "/console", "/_debug",
        "/phpinfo.php", "/server-status", "/elmah.axd",
        "/actuator",
    }
    if path in high_paths:
        return Severity.HIGH
    if path in medium_paths:
        return Severity.MEDIUM
    # robots.txt, sitemap.xml, swagger.json, openapi.json, /api
    return Severity.LOW
