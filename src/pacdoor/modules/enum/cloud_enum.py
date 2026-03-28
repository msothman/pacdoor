"""Cloud infrastructure enumeration — detect cloud misconfigurations.

Identifies cloud provider type, checks for accessible metadata services
(IMDS), public storage buckets, and exposed container orchestration APIs.
Each of these represents a distinct class of misconfiguration that could
lead to credential theft, data exfiltration, or full cluster compromise.

Produces ``cloud.imds``, ``cloud.storage``, and ``cloud.provider`` facts
for downstream modules.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

try:
    import aiohttp
    _aiohttp_available = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    _aiohttp_available = False

import contextlib

from pacdoor.core.models import Evidence, Finding, Phase, Port, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────

_REQUEST_TIMEOUT = 8  # seconds
_MAX_CONCURRENT = 10
_IMDS_IP = "169.254.169.254"

# Cloud provider banner / header indicators
_AWS_INDICATORS = {"amazons3", "awselb", "x-amz-", "amazonaws.com"}
_AZURE_INDICATORS = {"azure", "microsoft", ".azurewebsites.net", "x-ms-"}
_GCP_INDICATORS = {"google", "gws", ".googleapis.com", "x-goog-"}

# Storage bucket name permutations
_BUCKET_SUFFIXES = ["", "-backup", "-backups", "-dev", "-data", "-staging",
                     "-prod", "-assets", "-static", "-media", "-logs",
                     "-private", "-public", "-internal"]


# ── IMDS probes ───────────────────────────────────────────────────────────


async def _probe_aws_imds(
    session: aiohttp.ClientSession, ip: str,
) -> dict[str, Any] | None:
    """Check for AWS EC2 Instance Metadata Service (IMDSv1)."""
    url = f"http://{ip}/latest/meta-data/"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT)) as resp:
            if resp.status == 200:
                body = await resp.text()
                return {
                    "provider": "AWS",
                    "url": url,
                    "status": resp.status,
                    "sample": body[:500],
                }
    except Exception:
        pass
    return None


async def _probe_azure_imds(
    session: aiohttp.ClientSession, ip: str,
) -> dict[str, Any] | None:
    """Check for Azure Instance Metadata Service."""
    url = f"http://{ip}/metadata/instance?api-version=2021-02-01"
    headers = {"Metadata": "true"}
    try:
        async with session.get(
            url, headers=headers,
            timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
        ) as resp:
            if resp.status == 200:
                body = await resp.text()
                return {
                    "provider": "Azure",
                    "url": url,
                    "status": resp.status,
                    "sample": body[:500],
                }
    except Exception:
        pass
    return None


async def _probe_gcp_imds(
    session: aiohttp.ClientSession, ip: str,
) -> dict[str, Any] | None:
    """Check for GCP Compute Metadata Service."""
    url = f"http://{ip}/computeMetadata/v1/"
    headers = {"Metadata-Flavor": "Google"}
    try:
        async with session.get(
            url, headers=headers,
            timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
        ) as resp:
            if resp.status == 200:
                body = await resp.text()
                return {
                    "provider": "GCP",
                    "url": url,
                    "status": resp.status,
                    "sample": body[:500],
                }
    except Exception:
        pass
    return None


async def _check_imds(
    session: aiohttp.ClientSession, ip: str,
) -> list[dict[str, Any]]:
    """Probe all cloud IMDS endpoints for a given IP.

    Targets the well-known link-local address 169.254.169.254 and the
    host itself (for SSRF scenarios where the host proxies to IMDS).
    """
    results: list[dict[str, Any]] = []

    targets = [_IMDS_IP]
    if ip != _IMDS_IP:
        targets.append(ip)

    probes = [_probe_aws_imds, _probe_azure_imds, _probe_gcp_imds]

    for target_ip in targets:
        for probe_fn in probes:
            hit = await probe_fn(session, target_ip)
            if hit:
                hit["target_ip"] = target_ip
                hit["host_ip"] = ip
                results.append(hit)

    return results


# ── Cloud provider detection ──────────────────────────────────────────────


async def _detect_provider_from_http(
    session: aiohttp.ClientSession, ip: str,
) -> str | None:
    """Detect cloud provider from HTTP response headers and banners."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{ip}/"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
                ssl=False,
                allow_redirects=False,
            ) as resp:
                # Collect all header values into a single string for matching
                header_blob = " ".join(
                    f"{k}:{v}" for k, v in resp.headers.items()
                ).lower()
                body = ""
                with contextlib.suppress(Exception):
                    body = (await resp.text())[:2000].lower()

                combined = header_blob + " " + body

                for indicator in _AWS_INDICATORS:
                    if indicator in combined:
                        return "AWS"
                for indicator in _AZURE_INDICATORS:
                    if indicator in combined:
                        return "Azure"
                for indicator in _GCP_INDICATORS:
                    if indicator in combined:
                        return "GCP"
        except Exception:
            continue

    return None


def _detect_provider_from_hostname(hostname: str | None) -> str | None:
    """Detect cloud provider from hostname patterns."""
    if not hostname:
        return None
    h = hostname.lower()

    if any(p in h for p in (".amazonaws.com", ".aws.", "ec2-", "ec2.")):
        return "AWS"
    if any(p in h for p in (".azure.", ".azurewebsites.net", ".cloudapp.net",
                             ".windows.net")):
        return "Azure"
    if any(p in h for p in (".googleapis.com", ".googleusercontent.com",
                             ".run.app", ".appspot.com")):
        return "GCP"
    if any(p in h for p in (".digitalocean.com", ".ondigitalocean.app")):
        return "DigitalOcean"
    return None


# ── Public storage checks ─────────────────────────────────────────────────


async def _check_s3_bucket(
    session: aiohttp.ClientSession, name: str,
) -> dict[str, Any] | None:
    """Check if an S3 bucket exists and its accessibility."""
    url = f"https://{name}.s3.amazonaws.com"
    try:
        async with session.head(
            url, timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status in (200, 403):
                result: dict[str, Any] = {
                    "provider": "AWS",
                    "bucket": name,
                    "url": url,
                    "status": resp.status,
                    "public": resp.status == 200,
                }
                # Try listing if accessible
                if resp.status == 200:
                    try:
                        list_url = f"{url}?list-type=2&max-keys=5"
                        async with session.get(
                            list_url,
                            timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
                        ) as list_resp:
                            if list_resp.status == 200:
                                result["listable"] = True
                                result["listing_sample"] = (await list_resp.text())[:500]
                    except Exception:
                        pass
                return result
    except Exception:
        pass
    return None


async def _check_azure_blob(
    session: aiohttp.ClientSession, name: str,
) -> dict[str, Any] | None:
    """Check if an Azure Blob Storage container exists."""
    url = f"https://{name}.blob.core.windows.net"
    try:
        async with session.head(
            url, timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status in (200, 400, 403):
                return {
                    "provider": "Azure",
                    "container": name,
                    "url": url,
                    "status": resp.status,
                    "public": resp.status == 200,
                }
    except Exception:
        pass
    return None


async def _check_gcp_bucket(
    session: aiohttp.ClientSession, name: str,
) -> dict[str, Any] | None:
    """Check if a GCP Storage bucket exists."""
    url = f"https://storage.googleapis.com/{name}"
    try:
        async with session.head(
            url, timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status in (200, 403):
                return {
                    "provider": "GCP",
                    "bucket": name,
                    "url": url,
                    "status": resp.status,
                    "public": resp.status == 200,
                }
    except Exception:
        pass
    return None


async def _check_public_storage(
    session: aiohttp.ClientSession,
    base_name: str,
    semaphore: asyncio.Semaphore,
) -> list[dict[str, Any]]:
    """Check for public cloud storage buckets across providers."""
    results: list[dict[str, Any]] = []

    async def _check(coro: Any) -> dict[str, Any] | None:
        async with semaphore:
            return await coro

    tasks = []
    for suffix in _BUCKET_SUFFIXES:
        name = f"{base_name}{suffix}"
        tasks.append(_check(_check_s3_bucket(session, name)))
        tasks.append(_check(_check_azure_blob(session, name)))
        tasks.append(_check(_check_gcp_bucket(session, name)))

    completed = await asyncio.gather(*tasks, return_exceptions=True)
    for result in completed:
        if isinstance(result, dict):
            results.append(result)

    return results


# ── Container / orchestration checks ──────────────────────────────────────


async def _check_docker_api(
    session: aiohttp.ClientSession, ip: str,
) -> dict[str, Any] | None:
    """Check for exposed Docker daemon API (port 2375)."""
    url = f"http://{ip}:2375/v1.24/containers/json"
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
        ) as resp:
            if resp.status == 200:
                body = await resp.text()
                return {
                    "type": "docker_api",
                    "url": url,
                    "status": resp.status,
                    "sample": body[:500],
                }
    except Exception:
        pass
    return None


async def _check_k8s_api(
    session: aiohttp.ClientSession, ip: str,
) -> dict[str, Any] | None:
    """Check for unauthenticated Kubernetes API (port 6443)."""
    url = f"https://{ip}:6443/api/v1/namespaces"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
            ssl=False,
        ) as resp:
            if resp.status == 200:
                body = await resp.text()
                return {
                    "type": "k8s_api",
                    "url": url,
                    "status": resp.status,
                    "sample": body[:500],
                }
    except Exception:
        pass
    return None


async def _check_container_indicators(
    session: aiohttp.ClientSession, ip: str,
) -> list[dict[str, Any]]:
    """Check for container/orchestration indicators on a host."""
    results: list[dict[str, Any]] = []

    # Docker API
    docker = await _check_docker_api(session, ip)
    if docker:
        results.append(docker)

    # Kubernetes API
    k8s = await _check_k8s_api(session, ip)
    if k8s:
        results.append(k8s)

    # Check for dockerenv or K8s service account via HTTP probes
    # (useful if host has an HTTP service that serves local files via SSRF)
    for path, indicator in [
        ("/.dockerenv", "docker_container"),
        ("/var/run/secrets/kubernetes.io/serviceaccount/token", "k8s_serviceaccount"),
    ]:
        for scheme in ("http", "https"):
            url = f"{scheme}://{ip}{path}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        results.append({
                            "type": indicator,
                            "url": url,
                            "status": resp.status,
                            "sample": body[:200],
                        })
                        break  # Found on one scheme, skip the other
            except Exception:
                continue

    return results


# ── Port relevance helpers ────────────────────────────────────────────────


def _has_open_port(ports: list[Any], target_port: int) -> bool:
    """Check if a specific port is open for a host."""
    for p in ports:
        port_obj = p if isinstance(p, Port) else p
        port_num = port_obj.port if hasattr(port_obj, "port") else port_obj.get("port", 0)
        if port_num == target_port:
            return True
    return False


# ── Module ────────────────────────────────────────────────────────────────


class CloudEnumModule(BaseModule):
    """Cloud infrastructure enumeration and misconfiguration detection.

    Detects cloud metadata services (IMDS), identifies cloud providers
    from HTTP headers/banners, checks for public storage buckets, and
    probes for exposed container orchestration APIs.
    """

    name = "enum.cloud_enum"
    description = "Cloud infrastructure enumeration (IMDS, storage, containers)"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1580", "T1538"]
    required_facts = ["host"]
    produced_facts = [
        "cloud.imds",
        "cloud.storage",
        "cloud.provider",
    ]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _aiohttp_available:
            log.debug("aiohttp not installed — cloud enumeration unavailable")
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _aiohttp_available:
            return findings

        hosts = await ctx.facts.get_values("host")
        if not hosts:
            return findings

        semaphore = asyncio.Semaphore(_MAX_CONCURRENT)

        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=_MAX_CONCURRENT,
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT * 2)

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout,
        ) as session:

            for host in hosts:
                ip = host.ip if hasattr(host, "ip") else str(host.get("ip", ""))
                host_id = host.id if hasattr(host, "id") else str(host.get("id", ""))
                hostname = (
                    host.hostname if hasattr(host, "hostname")
                    else host.get("hostname")
                )
                domain = (
                    host.domain if hasattr(host, "domain")
                    else host.get("domain")
                )

                if not ip:
                    continue

                await ctx.rate_limiter.acquire()

                # ── 1. IMDS detection ───────────────────────────────
                async with semaphore:
                    imds_results = await _check_imds(session, ip)

                for imds in imds_results:
                    findings.append(Finding(
                        title=(
                            f"Cloud metadata service accessible — "
                            f"{imds['provider']} IMDS on {imds['target_ip']}"
                        ),
                        description=(
                            f"The {imds['provider']} Instance Metadata Service "
                            f"is accessible from host {ip} at {imds['url']}. "
                            f"An attacker can steal IAM credentials, access "
                            f"tokens, and instance configuration data. This "
                            f"enables privilege escalation to cloud-level access."
                        ),
                        severity=Severity.CRITICAL,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1552.005"],
                        evidence=[Evidence(
                            kind="cloud_imds",
                            data=(
                                f"Provider: {imds['provider']}\n"
                                f"URL: {imds['url']}\n"
                                f"Status: {imds['status']}\n"
                                f"Response sample:\n{imds.get('sample', '')[:300]}"
                            ),
                        )],
                        remediation=(
                            f"For {imds['provider']}: "
                            + {
                                "AWS": (
                                    "Enforce IMDSv2 (require token-based "
                                    "authentication) by setting HttpTokens=required. "
                                    "Restrict metadata access via iptables or "
                                    "security groups."
                                ),
                                "Azure": (
                                    "Use Managed Identities with least-privilege "
                                    "roles. Restrict metadata endpoint access via "
                                    "NSG rules."
                                ),
                                "GCP": (
                                    "Use Workload Identity Federation. Disable "
                                    "legacy metadata endpoints. Restrict service "
                                    "account permissions."
                                ),
                            }.get(imds["provider"], "Restrict metadata endpoint access.")
                        ),
                    ))
                    await ctx.facts.add(
                        "cloud.imds", imds, self.name, host_id=host_id,
                    )

                # ── 2. Cloud provider detection ─────────────────────
                async with semaphore:
                    provider = await _detect_provider_from_http(session, ip)

                if not provider:
                    provider = _detect_provider_from_hostname(hostname)

                if provider:
                    findings.append(Finding(
                        title=f"Cloud provider identified — {provider} ({ip})",
                        description=(
                            f"Host {ip}"
                            f"{' (' + hostname + ')' if hostname else ''} "
                            f"is running on {provider} cloud infrastructure, "
                            f"detected via HTTP headers/banners or hostname "
                            f"patterns. This informs further cloud-specific "
                            f"attack paths."
                        ),
                        severity=Severity.INFO,
                        host_id=host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1580"],
                        evidence=[Evidence(
                            kind="cloud_provider",
                            data=f"Provider: {provider}\nHost: {ip}\nHostname: {hostname}",
                        )],
                        remediation=(
                            "Ensure cloud security best practices are followed: "
                            "enforce least-privilege IAM, enable cloud audit "
                            "logging, and restrict network exposure."
                        ),
                    ))
                    await ctx.facts.add(
                        "cloud.provider", {"provider": provider, "ip": ip},
                        self.name, host_id=host_id,
                    )

                # ── 3. Public storage checks ────────────────────────
                # Derive a base name from the domain or hostname.
                base_names: set[str] = set()
                if domain:
                    # "corp.example.com" -> "corp", "example"
                    parts = domain.lower().split(".")
                    for part in parts:
                        if part not in ("com", "net", "org", "io", "co", "www"):
                            base_names.add(part)
                if hostname:
                    parts = hostname.lower().split(".")
                    for part in parts:
                        if (part not in ("com", "net", "org", "io", "co", "www")
                                and not part.replace("-", "").isdigit()):
                            base_names.add(part)

                for base_name in base_names:
                    if len(base_name) < 3:
                        continue

                    await ctx.rate_limiter.acquire()
                    storage_results = await _check_public_storage(
                        session, base_name, semaphore,
                    )

                    for bucket in storage_results:
                        is_public = bucket.get("public", False)
                        is_listable = bucket.get("listable", False)
                        bucket_name = bucket.get("bucket") or bucket.get("container", "")
                        severity = Severity.HIGH if is_public else Severity.MEDIUM

                        listing_note = ""
                        if is_listable:
                            severity = Severity.CRITICAL
                            listing_note = (
                                " The bucket is publicly listable — "
                                "all objects can be enumerated."
                            )

                        findings.append(Finding(
                            title=(
                                f"{'Public' if is_public else 'Existing'} "
                                f"{bucket['provider']} storage: {bucket_name}"
                            ),
                            description=(
                                f"Cloud storage bucket '{bucket_name}' on "
                                f"{bucket['provider']} "
                                f"{'is publicly accessible' if is_public else 'exists (access restricted)'}"
                                f" (HTTP {bucket['status']}).{listing_note} "
                                f"Associated with {base_name} derived from "
                                f"host {ip}."
                            ),
                            severity=severity,
                            host_id=host_id,
                            module_name=self.name,
                            attack_technique_ids=["T1530"],
                            evidence=[Evidence(
                                kind="cloud_storage",
                                data=(
                                    f"Provider: {bucket['provider']}\n"
                                    f"URL: {bucket['url']}\n"
                                    f"Status: {bucket['status']}\n"
                                    f"Public: {is_public}\n"
                                    f"Listable: {is_listable}"
                                    + (
                                        f"\nListing sample:\n"
                                        f"{bucket.get('listing_sample', '')[:300]}"
                                        if is_listable else ""
                                    )
                                ),
                            )],
                            remediation=(
                                f"Review {bucket['provider']} storage permissions "
                                f"for '{bucket_name}'. Block public access: "
                                + {
                                    "AWS": (
                                        "enable S3 Block Public Access at "
                                        "account and bucket level."
                                    ),
                                    "Azure": (
                                        "disable anonymous access on the blob "
                                        "container and storage account."
                                    ),
                                    "GCP": (
                                        "remove allUsers and allAuthenticatedUsers "
                                        "from bucket IAM bindings."
                                    ),
                                }.get(bucket["provider"], "restrict public access.")
                            ),
                        ))
                        await ctx.facts.add(
                            "cloud.storage", bucket, self.name,
                            host_id=host_id,
                        )

                # ── 4. Container / orchestration checks ─────────────
                # Only probe container endpoints if relevant ports are open
                # or if no port info is available (best-effort).
                port_facts = await ctx.facts.get_for_host("port.open", host_id)

                should_check_docker = (
                    not port_facts or _has_open_port(port_facts, 2375)
                )
                should_check_k8s = (
                    not port_facts or _has_open_port(port_facts, 6443)
                )

                if should_check_docker or should_check_k8s:
                    await ctx.rate_limiter.acquire()
                    async with semaphore:
                        container_results = await _check_container_indicators(
                            session, ip,
                        )

                    for container in container_results:
                        c_type = container["type"]

                        if c_type == "docker_api":
                            findings.append(Finding(
                                title=f"Docker API exposed ({ip}:2375)",
                                description=(
                                    f"The Docker daemon API is accessible "
                                    f"without authentication on host {ip}. "
                                    f"This allows full container management "
                                    f"including creating privileged containers "
                                    f"that escape to the host OS, reading "
                                    f"secrets from existing containers, and "
                                    f"lateral movement."
                                ),
                                severity=Severity.CRITICAL,
                                host_id=host_id,
                                module_name=self.name,
                                attack_technique_ids=["T1610"],
                                evidence=[Evidence(
                                    kind="docker_api_exposed",
                                    data=(
                                        f"URL: {container['url']}\n"
                                        f"Status: {container['status']}\n"
                                        f"Response sample:\n"
                                        f"{container.get('sample', '')[:300]}"
                                    ),
                                )],
                                remediation=(
                                    "Disable the Docker TCP socket (port 2375). "
                                    "Use the Unix socket (/var/run/docker.sock) "
                                    "with appropriate file permissions. If remote "
                                    "access is required, use TLS client "
                                    "certificates (port 2376)."
                                ),
                            ))

                        elif c_type == "k8s_api":
                            findings.append(Finding(
                                title=f"Kubernetes API unauthenticated ({ip}:6443)",
                                description=(
                                    f"The Kubernetes API server on host {ip} "
                                    f"allows unauthenticated access. This "
                                    f"enables full cluster enumeration, secret "
                                    f"extraction, pod creation with host mounts, "
                                    f"and complete cluster compromise."
                                ),
                                severity=Severity.CRITICAL,
                                host_id=host_id,
                                module_name=self.name,
                                attack_technique_ids=["T1613"],
                                evidence=[Evidence(
                                    kind="k8s_api_exposed",
                                    data=(
                                        f"URL: {container['url']}\n"
                                        f"Status: {container['status']}\n"
                                        f"Response sample:\n"
                                        f"{container.get('sample', '')[:300]}"
                                    ),
                                )],
                                remediation=(
                                    "Enable RBAC and disable anonymous auth on "
                                    "the API server (--anonymous-auth=false). "
                                    "Restrict API server network access via "
                                    "firewall rules. Use NetworkPolicies to "
                                    "limit pod-to-API-server traffic."
                                ),
                            ))

                        elif c_type == "docker_container":
                            findings.append(Finding(
                                title=f"Host is a Docker container ({ip})",
                                description=(
                                    f"Host {ip} appears to be running inside "
                                    f"a Docker container (/.dockerenv detected). "
                                    f"Container escape techniques may be "
                                    f"applicable."
                                ),
                                severity=Severity.INFO,
                                host_id=host_id,
                                module_name=self.name,
                                attack_technique_ids=["T1610"],
                                evidence=[Evidence(
                                    kind="container_indicator",
                                    data=(
                                        f"Indicator: /.dockerenv accessible\n"
                                        f"URL: {container['url']}"
                                    ),
                                )],
                                remediation=(
                                    "Ensure container runtime is up to date. "
                                    "Use read-only root filesystems, drop "
                                    "unnecessary capabilities, and avoid "
                                    "running as root inside containers."
                                ),
                            ))

                        elif c_type == "k8s_serviceaccount":
                            findings.append(Finding(
                                title=(
                                    f"Kubernetes service account token "
                                    f"accessible ({ip})"
                                ),
                                description=(
                                    f"A Kubernetes service account token is "
                                    f"accessible on host {ip} at the standard "
                                    f"mount path. This token may grant API "
                                    f"access to the Kubernetes cluster."
                                ),
                                severity=Severity.HIGH,
                                host_id=host_id,
                                module_name=self.name,
                                attack_technique_ids=["T1528"],
                                evidence=[Evidence(
                                    kind="k8s_token",
                                    data=(
                                        f"URL: {container['url']}\n"
                                        f"Token sample: "
                                        f"{container.get('sample', '')[:50]}..."
                                    ),
                                )],
                                remediation=(
                                    "Use projected service account tokens "
                                    "(automountServiceAccountToken: false) "
                                    "and bind minimal RBAC roles. Avoid "
                                    "mounting tokens into pods that do not "
                                    "need Kubernetes API access."
                                ),
                            ))

        # Persist all findings to the database.
        if ctx.db is not None:
            for finding in findings:
                await ctx.db.insert_finding(finding)

        return findings
