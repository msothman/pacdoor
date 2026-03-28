"""Save and restore scan state so interrupted scans can resume.

The key insight: we do NOT serialize the full fact store.  The SQLite
database already persists all important data (hosts, ports, findings,
credentials, module runs).  A checkpoint only needs to record:

  1. Which module signatures have already completed (planner._completed)
  2. The original target list and scan configuration
  3. Timing metadata (start time, checkpoint time, current phase)

On resume the engine:
  - Re-opens the existing DB (already populated from the prior run)
  - Restores planner._completed so finished modules are skipped
  - Re-seeds the fact store from DB rows (hosts, ports)
  - Continues from where it left off
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pacdoor.core.engine import Engine

log = logging.getLogger(__name__)

CHECKPOINT_FILE = "checkpoint.json"


class CheckpointManager:
    """Persist and restore scan state across process restarts."""

    @staticmethod
    def can_resume(output_dir: Path) -> bool:
        """Return True if a checkpoint file exists in *output_dir*."""
        return (output_dir / CHECKPOINT_FILE).is_file()

    @staticmethod
    async def save(engine: Engine, planner_completed: set[str] | None = None) -> Path:
        """Serialize current scan state to a JSON checkpoint.

        Parameters
        ----------
        engine:
            The running Engine instance.
        planner_completed:
            The planner's ``_completed`` set (module eligibility signatures
            that have already run).  If *None*, an empty set is saved.

        Returns
        -------
        Path to the written checkpoint file.
        """
        output_dir = engine.db_path.parent
        fact_summary = await engine.facts.summary()
        start_iso = (
            engine._start_time.isoformat() if engine._start_time else None
        )

        data: dict[str, Any] = {
            "version": 1,
            "targets": engine.targets_raw,
            "scan_start": start_iso,
            "checkpoint_time": datetime.now(UTC).isoformat(),
            "completed_signatures": sorted(planner_completed or set()),
            "fact_summary": fact_summary,
            "config": {
                "max_concurrency": engine.max_concurrency,
                "max_safety": engine.max_safety,
                "no_exploit": engine.no_exploit,
                "recon_only": engine.recon_only,
                "ports": engine.ports,
                "exclude": engine.exclude,
                "timeout": engine.timeout,
            },
        }

        path = output_dir / CHECKPOINT_FILE
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        log.info("Checkpoint saved to %s (%d completed signatures)",
                 path, len(data["completed_signatures"]))
        return path

    @staticmethod
    def load(output_dir: Path) -> dict[str, Any]:
        """Deserialize a checkpoint file.

        Returns the raw dict.  Raises FileNotFoundError if missing.
        """
        path = output_dir / CHECKPOINT_FILE
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
        log.info(
            "Loaded checkpoint from %s (version=%s, %d completed signatures)",
            path,
            data.get("version"),
            len(data.get("completed_signatures", [])),
        )
        return data

    @staticmethod
    async def restore_facts(engine: Engine) -> None:
        """Re-seed the fact store from the existing database.

        Called during resume so the planner sees all previously-discovered
        hosts, ports, and credentials.  The DB is the source of truth —
        we just need to push the rows back into the in-memory FactStore.
        """
        from pacdoor.core.models import Host, Port

        if engine.db is None:
            return

        # Restore hosts
        host_rows = await engine.db.get_all_hosts()
        for row in host_rows:
            host = Host(
                id=row["id"],
                ip=row["ip"],
                hostname=row.get("hostname"),
                os=row.get("os"),
                os_version=row.get("os_version"),
                mac=row.get("mac"),
                domain=row.get("domain"),
                alive=bool(row.get("alive", True)),
            )
            await engine.facts.add("host", host, "checkpoint_restore")

        # Restore open ports
        port_rows = await engine.db.get_all_ports()
        for row in port_rows:
            port = Port(
                id=row["id"],
                host_id=row["host_id"],
                port=row["port"],
                protocol=row.get("protocol", "tcp"),
                service_name=row.get("service_name"),
                service_version=row.get("service_version"),
                banner=row.get("banner"),
                product=row.get("product"),
            )
            await engine.facts.add(
                "port.open", port, "checkpoint_restore", host_id=row["host_id"]
            )

        # Restore service facts from port service_name so enum modules
        # that require service.smb, service.http etc. become eligible.
        _SVC_MAP = {
            "smb": "service.smb", "microsoft-ds": "service.smb",
            "ssh": "service.ssh", "ftp": "service.ftp",
            "http": "service.http", "https": "service.http",
            "http-proxy": "service.http",
            "dns": "service.dns", "domain": "service.dns",
            "ldap": "service.ldap", "ldaps": "service.ldap",
            "ms-sql-s": "service.mssql", "mssql": "service.mssql",
            "mysql": "service.mysql",
            "redis": "service.redis",
            "mongodb": "service.mongo", "mongod": "service.mongo",
            "snmp": "service.snmp",
        }
        svc_count = 0
        for row in port_rows:
            svc = (row.get("service_name") or "").lower()
            fact_type = _SVC_MAP.get(svc)
            if fact_type:
                await engine.facts.add(
                    fact_type, row, "checkpoint_restore",
                    host_id=row["host_id"],
                )
                svc_count += 1

        # Restore validated credentials
        cred_rows = await engine.db.get_all_credentials()
        for row in cred_rows:
            if row.get("valid"):
                await engine.facts.add(
                    "credential.valid", row, "checkpoint_restore",
                    host_id=row.get("host_id"),
                )
            if row.get("admin"):
                await engine.facts.add(
                    "credential.admin", row, "checkpoint_restore",
                    host_id=row.get("host_id"),
                )

        log.info(
            "Restored facts from DB: %d hosts, %d ports, %d services, %d credentials",
            len(host_rows), len(port_rows), svc_count, len(cred_rows),
        )

    @staticmethod
    def delete(output_dir: Path) -> None:
        """Remove the checkpoint file (called on successful scan completion)."""
        path = output_dir / CHECKPOINT_FILE
        if path.is_file():
            path.unlink()
            log.debug("Deleted checkpoint file %s", path)
