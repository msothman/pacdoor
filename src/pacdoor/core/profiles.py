"""Predefined scan profiles for common penetration testing scenarios.

Each profile defines sensible defaults for rate limiting, concurrency,
port selection, safety level, and module exclusions.  CLI flags always
take precedence — a profile just sets the baseline.

Usage:
    pacdoor 10.0.0.1 --profile stealth
    pacdoor 10.0.0.1 --profile stealth --rate-limit 20   # override rate limit
"""

from __future__ import annotations

from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "stealth": {
        "description": "Slow, quiet scan — minimize detection",
        "rate_limit": 10,
        "concurrency": 5,
        "ports": "top1000",
        "max_safety": "safe",
        "no_exploit": True,
        "module_timeout": 600,
        "excluded_modules": [
            "exploit.*",
            "post.*",
            "vuln.web_vulns",
            "exploit.ssh_brute",
        ],
    },
    "aggressive": {
        "description": "Full speed, all modules, all exploits",
        "rate_limit": 500,
        "concurrency": 50,
        "ports": "all",
        "max_safety": "dangerous",
        "no_exploit": False,
        "module_timeout": 300,
        "excluded_modules": [],
    },
    "web": {
        "description": "Web application focused — HTTP/HTTPS only",
        "rate_limit": 100,
        "concurrency": 20,
        "ports": "80,443,8080,8443,8000,8888,3000,5000,9090",
        "max_safety": "moderate",
        "no_exploit": False,
        "module_timeout": 300,
        "excluded_modules": [
            "enum.smb*",
            "enum.ldap*",
            "enum.snmp*",
            "enum.ftp*",
            "enum.dns*",
            "enum.mssql*",
            "enum.mysql*",
            "enum.redis*",
            "enum.mongo*",
            "vuln.smb*",
            "post.ad_enum",
            "exploit.kerberoast",
        ],
    },
    "ad": {
        "description": "Active Directory focused — domain compromise",
        "rate_limit": 100,
        "concurrency": 20,
        "ports": "22,53,88,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389",
        "max_safety": "moderate",
        "no_exploit": False,
        "module_timeout": 300,
        "excluded_modules": [
            "vuln.web_vulns",
            "vuln.http_vulns",
            "enum.http_enum",
            "vuln.template_scanner",
            "vuln.nuclei_scan",
        ],
    },
    "quick": {
        "description": "Fast recon only — discovery and basic enum",
        "rate_limit": 200,
        "concurrency": 30,
        "ports": "22,80,135,139,443,445,3306,3389,5432,8080",
        "max_safety": "safe",
        "recon_only": False,
        "no_exploit": True,
        "module_timeout": 120,
        "excluded_modules": [
            "exploit.*",
            "post.*",
        ],
    },
}


# Argument names that map directly from profile dict keys to argparse dest names.
# Only these keys are applied as CLI defaults.
_PROFILE_CLI_KEYS = {
    "rate_limit",
    "concurrency",
    "ports",
    "max_safety",
    "no_exploit",
    "recon_only",
    "module_timeout",
}


def apply_profile(args: Any, profile_name: str) -> None:
    """Overlay profile defaults onto *args* without clobbering explicit CLI flags.

    The heuristic for "was this flag explicitly set?" relies on argparse
    defaults: if the attribute still holds the parser default we treat it
    as unset and overwrite it with the profile value.  For boolean flags
    the default is always ``False``, so any ``True`` value means the user
    set it explicitly.

    ``excluded_modules`` and ``module_timeout`` are NOT standard argparse
    attributes — they are injected onto *args* so that downstream code
    (engine / planner) can read them.
    """
    profile = PROFILES[profile_name]

    # Map of argparse defaults so we can detect explicit overrides
    _DEFAULTS = {
        "rate_limit": 100,
        "concurrency": 20,
        "ports": "top1000",
        "max_safety": "moderate",
        "no_exploit": False,
        "recon_only": False,
    }

    for key in _PROFILE_CLI_KEYS:
        if key not in profile:
            continue
        current = getattr(args, key, _DEFAULTS.get(key))
        default = _DEFAULTS.get(key)
        # If current value matches the parser default, the user did NOT
        # explicitly set it — safe to overwrite with profile value.
        if current == default:
            setattr(args, key, profile[key])

    # Always inject these (not standard CLI flags, no collision risk)
    if "excluded_modules" in profile:
        args.excluded_modules = profile["excluded_modules"]
    else:
        args.excluded_modules = []

    if "module_timeout" in profile:
        args.module_timeout = profile["module_timeout"]
    else:
        args.module_timeout = 300
