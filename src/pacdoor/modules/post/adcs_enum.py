"""Active Directory Certificate Services vulnerability detection.

Detects misconfigured AD CS certificate templates that enable privilege
escalation (ESC1-ESC8).  This is pure LDAP-based detection — we query AD
for certificate template misconfigurations, we do not exploit them.

Requires valid domain credentials and an LDAP service.  Produces
``vuln.adcs.*`` facts for each ESC finding so the planner can chain
downstream modules.

References:
    - SpecterOps "Certified Pre-Owned" whitepaper
    - https://posts.specterops.io/certified-pre-owned-d95910965cd2
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
    Evidence,
    ExploitSafety,
    Finding,
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# ── Lazy import for ldap3 ─────────────────────────────────────────────────

_ldap3_available: bool | None = None


def _ensure_ldap3() -> bool:
    global _ldap3_available  # noqa: PLW0603
    if _ldap3_available is not None:
        return _ldap3_available
    try:
        import ldap3  # type: ignore[import-untyped]  # noqa: F401

        _ldap3_available = True
    except ImportError:
        log.debug("ldap3 not installed — ADCS enumeration unavailable")
        _ldap3_available = False
    return _ldap3_available


# ── OID / flag constants ──────────────────────────────────────────────────

# Extended Key Usage OIDs
_EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
_EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
_EKU_ANY_PURPOSE = "2.5.29.37.0"
_EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

# Certificate name flags
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001

# Well-known SIDs for low-privilege principals
_LOW_PRIV_SIDS = {
    "S-1-1-0",          # Everyone
    "S-1-5-11",         # Authenticated Users
    "S-1-5-32-545",     # BUILTIN\Users
    "S-1-5-9",          # Enterprise Domain Controllers
}
# Domain-relative RIDs for Domain Users (513) and Domain Computers (515)
_LOW_PRIV_RIDS = {513, 515}

# ACE rights masks
_ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100  # Extended rights (enroll)
_WRITE_DACL = 0x00040000
_WRITE_OWNER = 0x00080000
_WRITE_PROPERTY = 0x00000020
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000

# Certificate enrollment extended right GUID
_ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
_AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"


# ── Synchronous LDAP helpers ──────────────────────────────────────────────


def _ldap_connect(
    server_ip: str,
    domain: str,
    username: str,
    password: str,
    use_ssl: bool = False,
) -> Any | None:
    """Establish an authenticated LDAP connection."""
    try:
        import ldap3  # type: ignore[import-untyped]

        port = 636 if use_ssl else 389
        server = ldap3.Server(server_ip, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

        if "\\" not in username and "@" not in username:
            bind_dn = f"{domain}\\{username}"
        else:
            bind_dn = username

        conn = ldap3.Connection(
            server, user=bind_dn, password=password,
            authentication=ldap3.NTLM if "\\" in bind_dn else ldap3.SIMPLE,
            auto_bind=True,
            read_only=True,
            receive_timeout=30,
        )
        return conn
    except Exception as e:
        log.debug("LDAP bind to %s failed: %s", server_ip, e)
        return None


def _get_base_dn(domain: str) -> str:
    """Convert 'corp.local' to 'DC=corp,DC=local'."""
    return ",".join(f"DC={part}" for part in domain.split("."))


def _get_config_dn(conn: Any) -> str | None:
    """Retrieve the Configuration naming context from rootDSE."""
    try:
        if conn.server.info and conn.server.info.other:
            ctx = conn.server.info.other.get("configurationNamingContext")
            if ctx:
                return ctx[0] if isinstance(ctx, list) else str(ctx)
        # Fallback: query rootDSE manually
        import ldap3  # type: ignore[import-untyped]
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["configurationNamingContext"],
        )
        if conn.entries:
            val = conn.entries[0]["configurationNamingContext"]
            return str(val) if val else None
    except Exception as e:
        log.debug("Failed to retrieve Configuration DN: %s", e)
    return None


def _get_attr(entry: Any, attr: str, default: Any = None) -> Any:
    """Safely extract an attribute from an ldap3 entry."""
    try:
        val = getattr(entry, attr, default)
        if val is None:
            return default
        if hasattr(val, "value"):
            return val.value
        if hasattr(val, "values"):
            return val.values
        return val
    except Exception:
        return default


def _get_attr_list(entry: Any, attr: str) -> list[str]:
    """Extract a multi-valued attribute as a list of strings."""
    try:
        val = getattr(entry, attr, None)
        if val is None:
            return []
        if hasattr(val, "values"):
            return [str(v) for v in val.values]
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)]
    except Exception:
        return []


def _search_paged(
    conn: Any,
    base_dn: str,
    search_filter: str,
    attributes: list[str],
    size_limit: int = 0,
) -> list[Any]:
    """Perform a paged LDAP search and return all entries."""
    import ldap3  # type: ignore[import-untyped]

    entries: list[Any] = []
    try:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            paged_size=500,
            size_limit=size_limit,
        )
        entries.extend(conn.entries)

        cookie = conn.result.get("controls", {}).get(
            "1.2.840.113556.1.4.319", {}
        ).get("value", {}).get("cookie")

        while cookie:
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=500,
                paged_cookie=cookie,
                size_limit=size_limit,
            )
            entries.extend(conn.entries)
            cookie = conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}
            ).get("value", {}).get("cookie")
    except Exception as e:
        log.debug("Paged LDAP search failed: %s", e)

    return entries


# ── Security descriptor parsing ───────────────────────────────────────────


def _parse_sid(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a Windows SID from raw bytes.  Returns (sid_string, bytes_consumed)."""
    if offset + 8 > len(data):
        return ("S-0-0", 0)

    revision = data[offset]
    sub_authority_count = data[offset + 1]
    # 6-byte big-endian identifier authority
    authority = int.from_bytes(data[offset + 2:offset + 8], byteorder="big")

    end = offset + 8 + 4 * sub_authority_count
    if end > len(data):
        return ("S-0-0", 0)

    subs = []
    for i in range(sub_authority_count):
        sub_offset = offset + 8 + 4 * i
        sub = struct.unpack_from("<I", data, sub_offset)[0]
        subs.append(str(sub))

    sid_str = f"S-{revision}-{authority}" + ("".join(f"-{s}" for s in subs))
    return (sid_str, end - offset)


def _sid_is_low_priv(sid: str) -> bool:
    """Check if a SID represents a low-privilege principal."""
    if sid in _LOW_PRIV_SIDS:
        return True
    # Check domain-relative RIDs (last component)
    parts = sid.split("-")
    if len(parts) >= 4:
        try:
            rid = int(parts[-1])
            if rid in _LOW_PRIV_RIDS:
                return True
        except ValueError:
            pass
    return False


def _parse_acl_for_rights(
    sd_bytes: bytes,
) -> dict[str, set[int]]:
    """Parse a raw nTSecurityDescriptor and extract per-SID access rights.

    Returns a dict mapping SID strings to sets of ACCESS_MASK bits.
    This is a simplified parser covering the common DACL layout.
    """
    result: dict[str, set[int]] = {}
    if not sd_bytes or len(sd_bytes) < 20:
        return result

    try:
        # SECURITY_DESCRIPTOR header (self-relative form)
        # Offset 0: revision (1), Sbz1 (1), Control (2)
        # Offset 4: OffsetOwner (4), OffsetGroup (4), OffsetSacl (4), OffsetDacl (4)
        dacl_offset = struct.unpack_from("<I", sd_bytes, 16)[0]
        if dacl_offset == 0 or dacl_offset + 8 > len(sd_bytes):
            return result

        # ACL header: revision (1), Sbz1 (1), AclSize (2), AceCount (2), Sbz2 (2)
        _acl_rev, _, _acl_size, ace_count, _ = struct.unpack_from(
            "<BBHHH", sd_bytes, dacl_offset,
        )

        pos = dacl_offset + 8  # first ACE

        for _ in range(ace_count):
            if pos + 4 > len(sd_bytes):
                break

            ace_type = sd_bytes[pos]
            _ace_flags = sd_bytes[pos + 1]
            ace_size = struct.unpack_from("<H", sd_bytes, pos + 2)[0]

            if ace_size < 4 or pos + ace_size > len(sd_bytes):
                break

            # ACCESS_ALLOWED_ACE (type 0) and ACCESS_ALLOWED_OBJECT_ACE (type 5)
            if ace_type in (0, 5):
                mask = struct.unpack_from("<I", sd_bytes, pos + 4)[0]

                if ace_type == 0:
                    # Standard ACE: mask (4) + SID
                    sid_start = pos + 8
                elif ace_type == 5:
                    # Object ACE: mask (4) + flags (4) + optional GUIDs + SID
                    obj_flags = struct.unpack_from("<I", sd_bytes, pos + 8)[0]
                    sid_start = pos + 12
                    if obj_flags & 0x1:  # ObjectType present
                        sid_start += 16
                    if obj_flags & 0x2:  # InheritedObjectType present
                        sid_start += 16
                else:
                    sid_start = pos + 8

                if sid_start < pos + ace_size:
                    sid_str, _ = _parse_sid(sd_bytes, sid_start)
                    if sid_str not in result:
                        result[sid_str] = set()
                    result[sid_str].add(mask)

            pos += ace_size

    except Exception as e:
        log.debug("Failed to parse security descriptor: %s", e)

    return result


def _low_priv_can_enroll(sd_bytes: bytes) -> bool:
    """Check if low-privilege principals have enrollment rights."""
    acl = _parse_acl_for_rights(sd_bytes)
    for sid, masks in acl.items():
        if not _sid_is_low_priv(sid):
            continue
        for mask in masks:
            if mask & (_ADS_RIGHT_DS_CONTROL_ACCESS | _GENERIC_ALL | _GENERIC_WRITE):
                return True
    return False


def _low_priv_can_write(sd_bytes: bytes) -> bool:
    """Check if low-privilege principals have dangerous write rights."""
    acl = _parse_acl_for_rights(sd_bytes)
    for sid, masks in acl.items():
        if not _sid_is_low_priv(sid):
            continue
        for mask in masks:
            if mask & (_WRITE_DACL | _WRITE_OWNER | _WRITE_PROPERTY
                       | _GENERIC_ALL | _GENERIC_WRITE):
                return True
    return False


# ── Certificate template queries ──────────────────────────────────────────


def _query_cert_templates(conn: Any, config_dn: str) -> list[Any]:
    """Fetch all pKICertificateTemplate objects from the configuration NC."""
    templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}"
    return _search_paged(
        conn, templates_dn,
        search_filter="(objectClass=pKICertificateTemplate)",
        attributes=[
            "cn", "displayName", "distinguishedName",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "pKIExtendedKeyUsage",
            "msPKI-RA-Signature",
            "nTSecurityDescriptor",
        ],
    )


def _query_enrollment_services(conn: Any, config_dn: str) -> list[Any]:
    """Fetch all pKIEnrollmentService (CA) objects."""
    es_dn = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}"
    return _search_paged(
        conn, es_dn,
        search_filter="(objectClass=pKIEnrollmentService)",
        attributes=[
            "cn", "displayName", "distinguishedName",
            "dNSHostName",
            "certificateTemplates",
            "flags",
            "msPKI-Enrollment-Servers",
        ],
    )


# ── ESC check functions ──────────────────────────────────────────────────


def _check_esc1(templates: list[Any]) -> list[dict[str, Any]]:
    """ESC1: Template allows enrollee-supplied SAN + client auth + low-priv enroll."""
    vulns: list[dict[str, Any]] = []

    for tmpl in templates:
        name = str(_get_attr(tmpl, "cn", ""))
        display_name = str(_get_attr(tmpl, "displayName", name))

        # Check CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        name_flag = int(_get_attr(tmpl, "msPKI-Certificate-Name-Flag", 0) or 0)
        if not (name_flag & _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT):
            continue

        # Check EKU for Client Authentication or Smart Card Logon
        ekus = _get_attr_list(tmpl, "pKIExtendedKeyUsage")
        has_client_auth = (
            _EKU_CLIENT_AUTH in ekus
            or _EKU_SMART_CARD_LOGON in ekus
            or _EKU_ANY_PURPOSE in ekus
            or not ekus  # No EKU = effectively any purpose
        )
        if not has_client_auth:
            continue

        # Check ACL for low-privilege enrollment
        sd_raw = _get_attr(tmpl, "nTSecurityDescriptor", None)
        if sd_raw and isinstance(sd_raw, bytes) and not _low_priv_can_enroll(sd_raw):
            continue

        vulns.append({
            "template": name,
            "display_name": display_name,
            "dn": str(_get_attr(tmpl, "distinguishedName", "")),
            "name_flag": hex(name_flag),
            "ekus": ekus or ["(none — SubCA)"],
        })

    return vulns


def _check_esc2(templates: list[Any]) -> list[dict[str, Any]]:
    """ESC2: Template has Any Purpose EKU or no EKU (SubCA) + low-priv enroll."""
    vulns: list[dict[str, Any]] = []

    for tmpl in templates:
        name = str(_get_attr(tmpl, "cn", ""))
        display_name = str(_get_attr(tmpl, "displayName", name))

        ekus = _get_attr_list(tmpl, "pKIExtendedKeyUsage")
        has_any_purpose = _EKU_ANY_PURPOSE in ekus
        has_no_eku = not ekus  # SubCA

        if not (has_any_purpose or has_no_eku):
            continue

        sd_raw = _get_attr(tmpl, "nTSecurityDescriptor", None)
        if sd_raw and isinstance(sd_raw, bytes) and not _low_priv_can_enroll(sd_raw):
            continue

        vulns.append({
            "template": name,
            "display_name": display_name,
            "dn": str(_get_attr(tmpl, "distinguishedName", "")),
            "ekus": ekus or ["(none — SubCA)"],
            "reason": "Any Purpose EKU" if has_any_purpose else "No EKU (SubCA)",
        })

    return vulns


def _check_esc3(templates: list[Any]) -> list[dict[str, Any]]:
    """ESC3: Enrollment agent template + second template allowing on-behalf-of."""
    vulns: list[dict[str, Any]] = []

    agent_templates: list[str] = []
    onbehalf_templates: list[str] = []

    for tmpl in templates:
        name = str(_get_attr(tmpl, "cn", ""))
        ekus = _get_attr_list(tmpl, "pKIExtendedKeyUsage")

        sd_raw = _get_attr(tmpl, "nTSecurityDescriptor", None)
        can_enroll = True
        if sd_raw and isinstance(sd_raw, bytes):
            can_enroll = _low_priv_can_enroll(sd_raw)

        if not can_enroll:
            continue

        # Certificate Request Agent EKU
        if _EKU_CERT_REQUEST_AGENT in ekus:
            agent_templates.append(name)

        # Template that allows enrollment on behalf of:
        # msPKI-RA-Signature > 0 means an enrollment agent signature is accepted
        ra_sig = int(_get_attr(tmpl, "msPKI-RA-Signature", 0) or 0)
        if ra_sig > 0:
            # And it has client auth EKU
            if _EKU_CLIENT_AUTH in ekus or _EKU_SMART_CARD_LOGON in ekus:
                onbehalf_templates.append(name)

    if agent_templates and onbehalf_templates:
        vulns.append({
            "agent_templates": agent_templates,
            "onbehalf_templates": onbehalf_templates,
        })

    return vulns


def _check_esc4(templates: list[Any]) -> list[dict[str, Any]]:
    """ESC4: Low-privilege principals have dangerous write rights on template ACL."""
    vulns: list[dict[str, Any]] = []

    for tmpl in templates:
        name = str(_get_attr(tmpl, "cn", ""))
        display_name = str(_get_attr(tmpl, "displayName", name))

        sd_raw = _get_attr(tmpl, "nTSecurityDescriptor", None)
        if not sd_raw or not isinstance(sd_raw, bytes):
            continue

        if _low_priv_can_write(sd_raw):
            vulns.append({
                "template": name,
                "display_name": display_name,
                "dn": str(_get_attr(tmpl, "distinguishedName", "")),
            })

    return vulns


def _check_esc6(enrollment_services: list[Any]) -> list[dict[str, Any]]:
    """ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA.

    The flag value is 0x00040000 (262144).  When set, ANY template on
    this CA allows the requester to specify a SAN, regardless of the
    template configuration.
    """
    _EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000  # noqa: N806
    vulns: list[dict[str, Any]] = []

    for es in enrollment_services:
        ca_name = str(_get_attr(es, "cn", ""))
        ca_host = str(_get_attr(es, "dNSHostName", ""))
        flags = int(_get_attr(es, "flags", 0) or 0)

        if flags & _EDITF_ATTRIBUTESUBJECTALTNAME2:
            vulns.append({
                "ca_name": ca_name,
                "ca_host": ca_host,
                "dn": str(_get_attr(es, "distinguishedName", "")),
                "flags": hex(flags),
            })

    return vulns


def _check_esc8(enrollment_services: list[Any]) -> list[dict[str, Any]]:
    """ESC8: HTTP enrollment endpoint (NTLM relay to AD CS web enrollment).

    Checks whether enrollment services advertise HTTP endpoints via
    the msPKI-Enrollment-Servers attribute.
    """
    vulns: list[dict[str, Any]] = []

    for es in enrollment_services:
        ca_name = str(_get_attr(es, "cn", ""))
        ca_host = str(_get_attr(es, "dNSHostName", ""))

        # msPKI-Enrollment-Servers contains newline-separated URI entries
        enroll_servers = _get_attr_list(es, "msPKI-Enrollment-Servers")
        http_endpoints: list[str] = []
        for srv in enroll_servers:
            for part in str(srv).split("\n"):
                part = part.strip()
                if part.lower().startswith("http://"):
                    http_endpoints.append(part)

        # Also check if CA hostname suggests web enrollment
        if ca_host and not http_endpoints:
            http_endpoints.append(f"http://{ca_host}/certsrv/")

        if http_endpoints:
            vulns.append({
                "ca_name": ca_name,
                "ca_host": ca_host,
                "dn": str(_get_attr(es, "distinguishedName", "")),
                "http_endpoints": http_endpoints,
            })

    return vulns


# ── Synchronous scan entry point ──────────────────────────────────────────


def _scan_adcs(
    conn: Any, config_dn: str,
) -> dict[str, list[dict[str, Any]]]:
    """Run all ESC checks.  Returns dict keyed by ESC identifier."""
    templates = _query_cert_templates(conn, config_dn)
    enrollment_services = _query_enrollment_services(conn, config_dn)

    return {
        "ESC1": _check_esc1(templates),
        "ESC2": _check_esc2(templates),
        "ESC3": _check_esc3(templates),
        "ESC4": _check_esc4(templates),
        "ESC6": _check_esc6(enrollment_services),
        "ESC8": _check_esc8(enrollment_services),
        "templates_total": [{"count": len(templates)}],
        "cas_total": [{"count": len(enrollment_services)}],
    }


# ── Module ────────────────────────────────────────────────────────────────


class ADCSEnumModule(BaseModule):
    """Active Directory Certificate Services vulnerability detection.

    Queries AD via LDAP for certificate template misconfigurations that
    enable privilege escalation (ESC1-ESC8).  This is read-only detection
    — no certificates are requested or exploited.
    """

    name = "post.adcs_enum"
    description = "AD CS certificate template misconfiguration detection (ESC1-ESC8)"
    phase = Phase.POST_EXPLOIT
    attack_technique_ids = ["T1649"]
    required_facts = ["credential.valid", "service.ldap"]
    produced_facts = [
        "vuln.adcs.esc1",
        "vuln.adcs.esc2",
        "vuln.adcs.esc3",
        "vuln.adcs.esc4",
        "vuln.adcs.esc6",
        "vuln.adcs.esc8",
    ]
    safety = ExploitSafety.SAFE

    async def check(self, ctx: ModuleContext) -> bool:
        if not _ensure_ldap3():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if not _ensure_ldap3():
            return findings

        # Get LDAP service endpoints.
        ldap_services = await ctx.facts.get_all("service.ldap")
        if not ldap_services:
            return findings

        # Get available credentials.
        creds = await ctx.facts.get_all("credential.valid")
        if not creds:
            return findings

        # Try each LDAP endpoint with each credential until one works.
        conn = None
        bound_host_id: str | None = None
        bound_domain: str = ""

        for ldap_fact in ldap_services:
            host_id = ldap_fact.host_id
            if host_id is None:
                continue
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue

            for cred_fact in creds:
                cred = cred_fact.value
                username = (
                    cred.username if hasattr(cred, "username")
                    else str(cred.get("username", ""))
                )
                password = (
                    cred.value if hasattr(cred, "value")
                    else str(cred.get("value", ""))
                )
                domain = (
                    cred.domain if hasattr(cred, "domain")
                    else str(cred.get("domain", ""))
                )

                if not username or not domain:
                    continue

                await ctx.rate_limiter.acquire()

                for use_ssl in (True, False):
                    conn = await asyncio.to_thread(
                        _ldap_connect, ip, domain, username, password, use_ssl,
                    )
                    if conn is not None:
                        bound_host_id = host_id
                        bound_domain = domain
                        break

                if conn is not None:
                    break

            if conn is not None:
                break

        if conn is None:
            log.debug("adcs_enum: could not bind to any LDAP endpoint")
            return findings

        try:
            # Discover the Configuration naming context.
            config_dn = await asyncio.to_thread(_get_config_dn, conn)
            if config_dn is None:
                # Fallback: synthesise from domain
                config_dn = f"CN=Configuration,{_get_base_dn(bound_domain)}"

            # Run all ESC checks.
            results = await asyncio.to_thread(_scan_adcs, conn, config_dn)

            tmpl_count = results.get("templates_total", [{}])[0].get("count", 0)
            ca_count = results.get("cas_total", [{}])[0].get("count", 0)

            log.debug(
                "adcs_enum: scanned %d templates across %d CAs in %s",
                tmpl_count, ca_count, bound_domain,
            )

            # ── ESC1 ────────────────────────────────────────────────
            esc1 = results.get("ESC1", [])
            if esc1:
                lines = "\n".join(
                    f"  - {v['template']} ({v['display_name']}) — "
                    f"name_flag={v['name_flag']}, EKUs={v['ekus']}"
                    for v in esc1
                )
                findings.append(Finding(
                    title=f"ESC1 — Enrollee-supplied SAN with client auth ({len(esc1)} templates)",
                    description=(
                        f"Found {len(esc1)} certificate template(s) in domain "
                        f"{bound_domain} where CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT "
                        f"is set, the template has Client Authentication (or "
                        f"equivalent) EKU, and low-privilege users can enroll. "
                        f"An attacker can request a certificate with an arbitrary "
                        f"SAN (e.g. Domain Admin UPN) and authenticate as that user."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1649"],
                    evidence=[Evidence(
                        kind="adcs_esc1",
                        data=f"Vulnerable templates:\n{lines}",
                    )],
                    remediation=(
                        "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from the "
                        "msPKI-Certificate-Name-Flag attribute on affected templates. "
                        "Use 'Supply in the request' only when absolutely necessary "
                        "and restrict enrollment to authorized groups. Enable "
                        "CA certificate manager approval for these templates."
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ))
                await ctx.facts.add(
                    "vuln.adcs.esc1", esc1, self.name,
                    host_id=bound_host_id,
                )

            # ── ESC2 ────────────────────────────────────────────────
            esc2 = results.get("ESC2", [])
            if esc2:
                lines = "\n".join(
                    f"  - {v['template']} ({v['display_name']}) — {v['reason']}"
                    for v in esc2
                )
                findings.append(Finding(
                    title=f"ESC2 — Any Purpose / SubCA template ({len(esc2)} templates)",
                    description=(
                        f"Found {len(esc2)} certificate template(s) in domain "
                        f"{bound_domain} with Any Purpose EKU or no EKU (SubCA) "
                        f"that low-privilege users can enroll in. Certificates "
                        f"from these templates can be used for any purpose "
                        f"including client authentication and code signing."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1649"],
                    evidence=[Evidence(
                        kind="adcs_esc2",
                        data=f"Vulnerable templates:\n{lines}",
                    )],
                    remediation=(
                        "Remove the Any Purpose EKU (OID 2.5.29.37.0) and add "
                        "specific EKUs matching the template's intended use. "
                        "For SubCA templates, restrict enrollment to CA "
                        "administrators only."
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ))
                await ctx.facts.add(
                    "vuln.adcs.esc2", esc2, self.name,
                    host_id=bound_host_id,
                )

            # ── ESC3 ────────────────────────────────────────────────
            esc3 = results.get("ESC3", [])
            if esc3:
                for vuln in esc3:
                    agents = ", ".join(vuln["agent_templates"])
                    targets = ", ".join(vuln["onbehalf_templates"])
                    findings.append(Finding(
                        title="ESC3 — Enrollment agent abuse chain",
                        description=(
                            f"Enrollment agent template(s) [{agents}] can be "
                            f"used to request certificates on behalf of other "
                            f"users via template(s) [{targets}] in domain "
                            f"{bound_domain}. An attacker obtains an enrollment "
                            f"agent certificate, then uses it to request a "
                            f"certificate for a privileged user."
                        ),
                        severity=Severity.HIGH,
                        host_id=bound_host_id,
                        module_name=self.name,
                        attack_technique_ids=["T1649"],
                        evidence=[Evidence(
                            kind="adcs_esc3",
                            data=(
                                f"Agent templates: {agents}\n"
                                f"On-behalf-of templates: {targets}"
                            ),
                        )],
                        remediation=(
                            "Restrict enrollment in Certificate Request Agent "
                            "templates to trusted administrators. Enable 'This "
                            "number of authorized signatures' on templates that "
                            "accept enrollment agent requests and set the "
                            "issuance requirement appropriately."
                        ),
                        references=[
                            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                        ],
                    ))
                await ctx.facts.add(
                    "vuln.adcs.esc3", esc3, self.name,
                    host_id=bound_host_id,
                )

            # ── ESC4 ────────────────────────────────────────────────
            esc4 = results.get("ESC4", [])
            if esc4:
                lines = "\n".join(
                    f"  - {v['template']} ({v['display_name']})" for v in esc4
                )
                findings.append(Finding(
                    title=f"ESC4 — Writable certificate template ACL ({len(esc4)} templates)",
                    description=(
                        f"Found {len(esc4)} certificate template(s) in domain "
                        f"{bound_domain} where low-privilege principals have "
                        f"WriteDacl, WriteOwner, or WriteProperty rights. An "
                        f"attacker can modify the template to enable ESC1/ESC2 "
                        f"conditions, then enroll for a privileged certificate."
                    ),
                    severity=Severity.HIGH,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1649"],
                    evidence=[Evidence(
                        kind="adcs_esc4",
                        data=f"Templates with dangerous ACLs:\n{lines}",
                    )],
                    remediation=(
                        "Remove WriteDacl, WriteOwner, and WriteProperty ACEs "
                        "for low-privilege groups on certificate templates. Use "
                        "the 'Security' tab in certtmpl.msc to audit and "
                        "restrict template permissions."
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ))
                await ctx.facts.add(
                    "vuln.adcs.esc4", esc4, self.name,
                    host_id=bound_host_id,
                )

            # ── ESC6 ────────────────────────────────────────────────
            esc6 = results.get("ESC6", [])
            if esc6:
                lines = "\n".join(
                    f"  - {v['ca_name']} ({v['ca_host']}) — flags={v['flags']}"
                    for v in esc6
                )
                findings.append(Finding(
                    title=f"ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA ({len(esc6)} CAs)",
                    description=(
                        f"Found {len(esc6)} CA(s) in domain {bound_domain} with "
                        f"the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled. This "
                        f"allows ANY certificate request to specify a Subject "
                        f"Alternative Name regardless of template settings, "
                        f"effectively making every template vulnerable to ESC1."
                    ),
                    severity=Severity.CRITICAL,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1649"],
                    evidence=[Evidence(
                        kind="adcs_esc6",
                        data=f"CAs with EDITF_ATTRIBUTESUBJECTALTNAME2:\n{lines}",
                    )],
                    remediation=(
                        "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA by "
                        "running: certutil -config \"CA\\Name\" -setreg "
                        "policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 "
                        "then restart the CertSvc service."
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ))
                await ctx.facts.add(
                    "vuln.adcs.esc6", esc6, self.name,
                    host_id=bound_host_id,
                )

            # ── ESC8 ────────────────────────────────────────────────
            esc8 = results.get("ESC8", [])
            if esc8:
                lines = "\n".join(
                    f"  - {v['ca_name']} ({v['ca_host']}) — "
                    f"endpoints: {', '.join(v['http_endpoints'])}"
                    for v in esc8
                )
                findings.append(Finding(
                    title=f"ESC8 — HTTP enrollment endpoint (NTLM relay) ({len(esc8)} CAs)",
                    description=(
                        f"Found {len(esc8)} CA(s) in domain {bound_domain} with "
                        f"HTTP-based enrollment endpoints. These are vulnerable "
                        f"to NTLM relay attacks (PetitPotam/DFSCoerce -> AD CS "
                        f"web enrollment) which can yield a Domain Admin certificate."
                    ),
                    severity=Severity.HIGH,
                    host_id=bound_host_id,
                    module_name=self.name,
                    attack_technique_ids=["T1649"],
                    evidence=[Evidence(
                        kind="adcs_esc8",
                        data=f"CAs with HTTP enrollment:\n{lines}",
                    )],
                    remediation=(
                        "Disable HTTP enrollment and use HTTPS only. Enable "
                        "EPA (Extended Protection for Authentication) on the "
                        "CertSrv IIS site. Require channel binding on all "
                        "AD CS web enrollment endpoints. Alternatively, disable "
                        "web enrollment entirely if not needed."
                    ),
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ))
                await ctx.facts.add(
                    "vuln.adcs.esc8", esc8, self.name,
                    host_id=bound_host_id,
                )

        finally:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(conn.unbind)

        # Persist all findings to the database.
        if ctx.db is not None:
            for finding in findings:
                await ctx.db.insert_finding(finding)

        return findings
