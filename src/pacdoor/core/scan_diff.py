"""Compare two scan databases and generate a delta report.

Loads findings, hosts, and credentials from two pacdoor SQLite databases
(old scan vs. new scan) and produces a structured diff showing what changed:
new hosts, removed hosts, new findings, fixed findings, persistent findings,
and new credentials.

Usage:
    diff = ScanDiff(old_db_path, new_db_path)
    result = await diff.compare()
"""

from __future__ import annotations

import logging
from pathlib import Path

from pacdoor.core.models import DiffResult
from pacdoor.db.database import Database

log = logging.getLogger(__name__)


def _finding_key(f: dict) -> tuple[str, str, str]:
    """Produce a dedup key for a finding: (title, host_ip, severity)."""
    return (
        str(f.get("title", "")),
        str(f.get("host_id", "")),
        str(f.get("severity", "info")).lower(),
    )


def _credential_key(c: dict) -> tuple[str, str]:
    """Produce a dedup key for a credential: (host_id, username)."""
    return (
        str(c.get("host_id", "")),
        str(c.get("username", "")),
    )


class ScanDiff:
    """Compare two pacdoor scan databases and produce a delta report."""

    def __init__(self, db_path_old: Path, db_path_new: Path) -> None:
        self.db_path_old = db_path_old
        self.db_path_new = db_path_new

    async def compare(self) -> DiffResult:
        """Load both databases and compute the diff.

        Returns a DiffResult with new/removed/fixed/persistent findings,
        host changes, and credential changes.
        """
        db_old = Database(self.db_path_old)
        db_new = Database(self.db_path_new)

        try:
            await db_old.initialize()
            await db_new.initialize()

            # ── Load data ─────────────────────────────────────────────
            old_hosts = await db_old.get_all_hosts()
            new_hosts = await db_new.get_all_hosts()

            old_findings = await db_old.get_all_findings()
            new_findings = await db_new.get_all_findings()

            old_credentials = await db_old.get_all_credentials()
            new_credentials = await db_new.get_all_credentials()

            # ── Host comparison ───────────────────────────────────────
            old_host_ips = {h.get("ip", "") for h in old_hosts}
            new_host_ips = {h.get("ip", "") for h in new_hosts}

            added_hosts = sorted(new_host_ips - old_host_ips)
            removed_hosts = sorted(old_host_ips - new_host_ips)

            # ── Finding comparison ────────────────────────────────────
            # Build host_id -> IP maps for both databases so finding keys
            # are based on IP rather than opaque UUIDs.
            old_host_ip_map: dict[str, str] = {
                h.get("id", ""): h.get("ip", "") for h in old_hosts
            }
            new_host_ip_map: dict[str, str] = {
                h.get("id", ""): h.get("ip", "") for h in new_hosts
            }

            def _normalize_finding(f: dict, ip_map: dict[str, str]) -> dict:
                """Return a copy with host_id replaced by IP for comparison."""
                out = dict(f)
                out["host_ip"] = ip_map.get(f.get("host_id", ""), f.get("host_id", ""))
                return out

            old_findings_norm = [_normalize_finding(f, old_host_ip_map) for f in old_findings]
            new_findings_norm = [_normalize_finding(f, new_host_ip_map) for f in new_findings]

            def _finding_key_normalized(f: dict) -> tuple[str, str, str]:
                return (
                    str(f.get("title", "")),
                    str(f.get("host_ip", "")),
                    str(f.get("severity", "info")).lower(),
                )

            old_finding_keys = {_finding_key_normalized(f) for f in old_findings_norm}
            new_finding_keys = {_finding_key_normalized(f) for f in new_findings_norm}

            # Index findings by their key for result building.
            old_by_key: dict[tuple, dict] = {}
            for f in old_findings_norm:
                key = _finding_key_normalized(f)
                if key not in old_by_key:
                    old_by_key[key] = f

            new_by_key: dict[tuple, dict] = {}
            for f in new_findings_norm:
                key = _finding_key_normalized(f)
                if key not in new_by_key:
                    new_by_key[key] = f

            # Fixed: in old but not in new (remediated).
            fixed_keys = old_finding_keys - new_finding_keys
            fixed_findings = [old_by_key[k] for k in sorted(fixed_keys)]

            # New: in new but not in old (regression or new discovery).
            new_keys = new_finding_keys - old_finding_keys
            new_finding_dicts = [new_by_key[k] for k in sorted(new_keys)]

            # Persistent: in both scans (not yet remediated).
            persistent_keys = old_finding_keys & new_finding_keys
            persistent_findings = [new_by_key[k] for k in sorted(persistent_keys)]

            # ── Credential comparison ─────────────────────────────────
            old_cred_keys = {_credential_key(c) for c in old_credentials}
            new_cred_keys = {_credential_key(c) for c in new_credentials}
            new_cred_only = new_cred_keys - old_cred_keys

            new_cred_by_key: dict[tuple, dict] = {}
            for c in new_credentials:
                key = _credential_key(c)
                if key not in new_cred_by_key:
                    new_cred_by_key[key] = c

            new_credential_dicts = [new_cred_by_key[k] for k in sorted(new_cred_only)]

            # ── Summary stats ─────────────────────────────────────────
            stats = {
                "old_host_count": len(old_host_ips),
                "new_host_count": len(new_host_ips),
                "hosts_added": len(added_hosts),
                "hosts_removed": len(removed_hosts),
                "old_finding_count": len(old_findings),
                "new_finding_count": len(new_findings),
                "findings_fixed": len(fixed_findings),
                "findings_new": len(new_finding_dicts),
                "findings_persistent": len(persistent_findings),
                "old_credential_count": len(old_credentials),
                "new_credential_count": len(new_credentials),
                "credentials_new": len(new_credential_dicts),
            }

            return DiffResult(
                new_hosts=added_hosts,
                removed_hosts=removed_hosts,
                new_findings=new_finding_dicts,
                fixed_findings=fixed_findings,
                persistent_findings=persistent_findings,
                new_credentials=new_credential_dicts,
                stats=stats,
            )
        finally:
            await db_old.close()
            await db_new.close()
