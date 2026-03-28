"""Async SQLite database layer with batched commits and credential encryption."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import aiosqlite
from cryptography.fernet import Fernet, InvalidToken

from pacdoor.core.models import (
    AttackPath,
    Credential,
    Finding,
    Host,
    ModuleRun,
    ModuleStatus,
    Port,
)

log = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# Commit after this many pending writes instead of every single row.
_COMMIT_THRESHOLD = 100


class Database:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._pending_writes = 0
        self._fernet: Fernet | None = None

    async def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.db_path))
        self._conn.row_factory = aiosqlite.Row
        # Enable foreign keys and WAL mode for better concurrency
        await self._conn.execute("PRAGMA foreign_keys = ON")
        await self._conn.execute("PRAGMA journal_mode = WAL")
        await self._conn.executescript(_SCHEMA_PATH.read_text())
        await self._conn.commit()
        self._init_encryption()

    # -- Encryption ----------------------------------------------------

    def _init_encryption(self) -> None:
        """Load or generate a Fernet key for credential-at-rest encryption."""
        key_path = self.db_path.with_suffix(".key")
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
        self._fernet = Fernet(key)

    def _encrypt(self, plaintext: str) -> str:
        if self._fernet and plaintext:
            return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return plaintext

    def _decrypt(self, ciphertext: str) -> str:
        if self._fernet and ciphertext:
            try:
                return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
            except (InvalidToken, Exception):
                return ciphertext  # legacy unencrypted data
        return ciphertext

    # -- Batched commits -----------------------------------------------

    async def _maybe_commit(self) -> None:
        """Commit when pending writes exceed the threshold."""
        self._pending_writes += 1
        if self._pending_writes >= _COMMIT_THRESHOLD:
            await self._conn.commit()
            self._pending_writes = 0

    async def flush(self) -> None:
        """Force-commit all pending writes."""
        if self._conn and self._pending_writes > 0:
            await self._conn.commit()
            self._pending_writes = 0

    async def close(self) -> None:
        if self._conn:
            await self.flush()
            await self._conn.close()
            self._conn = None

    # -- Batch support (legacy alias) ----------------------------------

    async def batch_commit(self) -> None:
        await self.flush()

    # -- Hosts ---------------------------------------------------------

    async def insert_host(self, host: Host) -> None:
        await self._conn.execute(
            "INSERT INTO hosts (id, ip, hostname, os, os_version, mac, domain, profile, alive) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "  hostname = COALESCE(excluded.hostname, hosts.hostname), "
            "  os = COALESCE(excluded.os, hosts.os), "
            "  os_version = COALESCE(excluded.os_version, hosts.os_version), "
            "  mac = COALESCE(excluded.mac, hosts.mac), "
            "  domain = COALESCE(excluded.domain, hosts.domain), "
            "  profile = excluded.profile, "
            "  alive = excluded.alive",
            (host.id, host.ip, host.hostname, host.os, host.os_version,
             host.mac, host.domain, host.profile.value, int(host.alive)),
        )
        await self._maybe_commit()

    async def get_all_hosts(self) -> list[dict]:
        cursor = await self._conn.execute("SELECT * FROM hosts")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def count_hosts(self) -> int:
        cursor = await self._conn.execute("SELECT COUNT(*) FROM hosts")
        row = await cursor.fetchone()
        return row[0]

    # -- Ports ---------------------------------------------------------

    async def insert_port(self, port: Port) -> None:
        await self._conn.execute(
            "INSERT INTO ports (id, host_id, port, protocol, state, "
            "service_name, service_version, banner, product) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(host_id, port, protocol) DO UPDATE SET "
            "  state = excluded.state, "
            "  service_name = COALESCE(excluded.service_name, ports.service_name), "
            "  service_version = COALESCE(excluded.service_version, ports.service_version), "
            "  banner = COALESCE(excluded.banner, ports.banner), "
            "  product = COALESCE(excluded.product, ports.product)",
            (port.id, port.host_id, port.port, port.protocol, port.state.value,
             port.service_name, port.service_version, port.banner, port.product),
        )
        await self._maybe_commit()

    async def get_all_ports(self) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM ports ORDER BY host_id, port"
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # -- Findings ------------------------------------------------------

    async def insert_finding(self, finding: Finding) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO findings (id, host_id, port_id, title, description, "
            "severity, cvss_score, cvss_vector, cve_id, attack_technique_ids, "
            "module_name, remediation, refs, verified, evidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id, finding.host_id, finding.port_id, finding.title,
                finding.description, finding.severity.value, finding.cvss_score,
                finding.cvss_vector, finding.cve_id,
                json.dumps(finding.attack_technique_ids),
                finding.module_name, finding.remediation,
                json.dumps(finding.references), int(finding.verified),
                json.dumps([e.model_dump() for e in finding.evidence], default=str),
            ),
        )
        await self._maybe_commit()

    async def get_all_findings(self) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM findings ORDER BY "
            "CASE severity "
            "  WHEN 'critical' THEN 0 "
            "  WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 "
            "  WHEN 'low' THEN 3 "
            "  ELSE 4 END"
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def count_findings(self) -> int:
        cursor = await self._conn.execute("SELECT COUNT(*) FROM findings")
        row = await cursor.fetchone()
        return row[0]

    async def count_findings_by_severity(self) -> dict[str, int]:
        cursor = await self._conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        )
        rows = await cursor.fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    # -- Credentials ---------------------------------------------------

    async def insert_credential(self, cred: Credential) -> None:
        encrypted_value = self._encrypt(cred.value)
        await self._conn.execute(
            "INSERT INTO credentials (id, host_id, username, cred_type, "
            "value, domain, source_module, valid, admin) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(host_id, username, cred_type) DO UPDATE SET "
            "  value = excluded.value, "
            "  domain = COALESCE(excluded.domain, credentials.domain), "
            "  source_module = excluded.source_module, "
            "  valid = excluded.valid, "
            "  admin = excluded.admin",
            (cred.id, cred.host_id, cred.username, cred.cred_type.value,
             encrypted_value, cred.domain, cred.source_module,
             int(cred.valid), int(cred.admin)),
        )
        await self._maybe_commit()

    async def get_all_credentials(self) -> list[dict]:
        cursor = await self._conn.execute("SELECT * FROM credentials")
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["value"] = self._decrypt(d.get("value", ""))
            result.append(d)
        return result

    # -- Module Runs ---------------------------------------------------

    async def insert_module_run(self, run: ModuleRun) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO module_runs (id, module_name, host_id, status, "
            "started_at, completed_at, error, findings_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run.id, run.module_name, run.host_id, run.status.value,
             run.started_at.isoformat() if run.started_at else None,
             run.completed_at.isoformat() if run.completed_at else None,
             run.error, run.findings_count),
        )
        await self._maybe_commit()

    async def update_module_run(
        self, run_id: str, status: ModuleStatus,
        completed_at: datetime | None = None,
        error: str | None = None, findings_count: int = 0,
    ) -> None:
        await self._conn.execute(
            "UPDATE module_runs SET status=?, completed_at=?, error=?, findings_count=? WHERE id=?",
            (status.value, completed_at.isoformat() if completed_at else None,
             error, findings_count, run_id),
        )
        await self._maybe_commit()

    async def get_all_module_runs(self) -> list[dict]:
        cursor = await self._conn.execute("SELECT * FROM module_runs ORDER BY started_at")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # -- Attack Paths --------------------------------------------------

    async def insert_attack_path(self, path: AttackPath) -> None:
        """Persist a single attack path step to the database."""
        await self._conn.execute(
            "INSERT OR REPLACE INTO attack_paths "
            "(id, from_host_id, to_host_id, technique_id, credential_id, description, step_order) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (path.id, path.from_host_id, path.to_host_id, path.technique_id,
             path.credential_id, path.description, path.step_order),
        )
        await self._maybe_commit()

    async def get_all_attack_paths(self) -> list[dict]:
        cursor = await self._conn.execute("SELECT * FROM attack_paths ORDER BY step_order")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
