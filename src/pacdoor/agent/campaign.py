"""Cross-run campaign tracker for PACDOOR's autonomous agent mode.

Maintains a persistent SQLite database that tracks findings across multiple
scan runs, deduplicates via stable fingerprints, and classifies each finding
as new, persistent, or fixed.
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
from pydantic import BaseModel, Field

from pacdoor.db.database import Database

log = logging.getLogger(__name__)

# -- Models ----------------------------------------------------------------

class RunRecord(BaseModel):
    """Metadata for a single scan run."""
    run_id: int
    schedule_name: str
    db_path: str
    started_at: datetime
    duration_secs: float
    finding_count: int
    host_count: int

class DeltaReport(BaseModel):
    """Result of comparing a scan's findings against the master index."""
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    fixed_findings: list[dict[str, Any]] = Field(default_factory=list)
    persistent_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

class TrendData(BaseModel):
    """Finding counts over time for trend analysis."""
    daily_counts: list[dict[str, Any]] = Field(default_factory=list)
    severity_over_time: list[dict[str, Any]] = Field(default_factory=list)
    total_unique_findings: int = 0
    currently_open: int = 0
    fixed_all_time: int = 0

# -- Schema ----------------------------------------------------------------

_CAMPAIGN_SCHEMA = """\
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, schedule_name TEXT NOT NULL,
    db_path TEXT, started_at TEXT NOT NULL, duration_secs REAL DEFAULT 0,
    finding_count INTEGER DEFAULT 0, host_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS finding_index (
    fingerprint TEXT PRIMARY KEY, title TEXT NOT NULL, host_ip TEXT,
    severity TEXT, module_name TEXT, first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new',
    first_run_id INTEGER REFERENCES runs(id),
    last_run_id INTEGER REFERENCES runs(id), raw TEXT);
CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL REFERENCES finding_index(fingerprint),
    run_id INTEGER NOT NULL REFERENCES runs(id),
    seen INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS idx_fi_status ON finding_index(status);
CREATE INDEX IF NOT EXISTS idx_fi_first_seen ON finding_index(first_seen);
CREATE INDEX IF NOT EXISTS idx_fi_last_seen ON finding_index(last_seen);
CREATE INDEX IF NOT EXISTS idx_fh_run ON finding_history(run_id);
CREATE INDEX IF NOT EXISTS idx_fh_fp ON finding_history(fingerprint);
"""

# -- Helpers ---------------------------------------------------------------

def _utcnow() -> str:
    return datetime.now(UTC).isoformat()

def _fingerprint(title: str, host_ip: str, severity: str, module_name: str) -> str:
    """Produce a stable SHA-256 fingerprint for deduplication."""
    raw = f"{title}\x00{host_ip}\x00{severity}\x00{module_name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

async def _resolve_host_ip_map(scan_db: Database) -> dict[str, str]:
    """Build a host_id -> IP lookup from a scan database."""
    hosts = await scan_db.get_all_hosts()
    return {h.get("id", ""): h.get("ip", "") for h in hosts}

# -- CampaignTracker -------------------------------------------------------

class CampaignTracker:
    """Persistent cross-run finding tracker.

    Stores all scan metadata and a master finding index in a dedicated SQLite
    database separate from the per-scan databases.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Open (or create) the campaign database and apply the schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.db_path))
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode = WAL")
        await self._conn.execute("PRAGMA foreign_keys = ON")
        await self._conn.executescript(_CAMPAIGN_SCHEMA)
        await self._conn.commit()
        log.debug("Campaign database initialized at %s", self.db_path)

    async def close(self) -> None:
        """Flush and close the database connection."""
        if self._conn:
            await self._conn.commit()
            await self._conn.close()
            self._conn = None

    # -- Run registration --------------------------------------------------

    async def register_run(
        self, schedule_name: str, db_path: Path, summary: dict[str, Any],
    ) -> RunRecord:
        """Record a completed scan run and return its metadata.

        *summary* may contain ``duration_secs``, ``finding_count``, and
        ``host_count`` (all default to 0).
        """
        now = _utcnow()
        dur = summary.get("duration_secs", 0.0)
        fc = summary.get("finding_count", 0)
        hc = summary.get("host_count", 0)
        cursor = await self._conn.execute(
            "INSERT INTO runs (schedule_name, db_path, started_at, "
            "duration_secs, finding_count, host_count) VALUES (?, ?, ?, ?, ?, ?)",
            (schedule_name, str(db_path), now, dur, fc, hc),
        )
        await self._conn.commit()
        rid = cursor.lastrowid
        log.debug("Registered run %d (%s) -- %d findings, %d hosts",
                   rid, schedule_name, fc, hc)
        return RunRecord(run_id=rid, schedule_name=schedule_name,
                         db_path=str(db_path), started_at=datetime.fromisoformat(now),
                         duration_secs=dur, finding_count=fc, host_count=hc)

    # -- Finding processing ------------------------------------------------

    async def process_findings(
        self, run_id: int, findings: list[dict[str, Any]],
    ) -> DeltaReport:
        """Compare *findings* against the master index and classify each one.

        Each finding dict must contain ``title``, ``host_ip``, ``severity``,
        and ``module_name``.  Use :meth:`load_findings_from_scan` to resolve
        host_id to IP first if needed.
        """
        now = _utcnow()
        seen_fps: set[str] = set()
        new_findings: list[dict[str, Any]] = []
        persistent_count = 0

        for f in findings:
            fp = _fingerprint(
                f.get("title", ""), f.get("host_ip", ""),
                str(f.get("severity", "info")).lower(), f.get("module_name", ""),
            )
            seen_fps.add(fp)
            cursor = await self._conn.execute(
                "SELECT fingerprint, status FROM finding_index "
                "WHERE fingerprint = ?", (fp,),
            )
            row = await cursor.fetchone()

            if row is None:
                await self._conn.execute(
                    "INSERT INTO finding_index (fingerprint, title, host_ip, "
                    "severity, module_name, first_seen, last_seen, status, "
                    "first_run_id, last_run_id, raw) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)",
                    (fp, f.get("title", ""), f.get("host_ip", ""),
                     str(f.get("severity", "info")).lower(),
                     f.get("module_name", ""), now, now, run_id, run_id, str(f)),
                )
                new_findings.append(f)
            else:
                status = "persistent" if row["status"] != "new" else "new"
                await self._conn.execute(
                    "UPDATE finding_index SET last_seen=?, last_run_id=?, "
                    "status=? WHERE fingerprint=?", (now, run_id, status, fp),
                )
                persistent_count += 1

            await self._conn.execute(
                "INSERT INTO finding_history (fingerprint, run_id, seen) "
                "VALUES (?, ?, 1)", (fp, run_id),
            )

        # Mark open findings NOT seen in this scan as fixed.
        cursor = await self._conn.execute(
            "SELECT fingerprint, title, host_ip, severity, module_name "
            "FROM finding_index WHERE status IN ('new', 'persistent')",
        )
        fixed_findings: list[dict[str, Any]] = []
        for row in await cursor.fetchall():
            if row["fingerprint"] not in seen_fps:
                await self._conn.execute(
                    "UPDATE finding_index SET status='fixed', last_seen=? "
                    "WHERE fingerprint=?", (now, row["fingerprint"]),
                )
                fixed_findings.append(dict(row))

        await self._conn.commit()
        stats = {"total_in_scan": len(findings), "new": len(new_findings),
                 "persistent": persistent_count, "fixed": len(fixed_findings)}
        log.debug("Delta: %s", stats)
        return DeltaReport(new_findings=new_findings, fixed_findings=fixed_findings,
                           persistent_count=persistent_count, stats=stats)

    # -- Queries -----------------------------------------------------------

    async def get_new_findings(self, since_hours: int = 24) -> list[dict]:
        """Return findings first seen within the last *since_hours* hours."""
        cutoff = datetime.now(UTC).isoformat()
        cursor = await self._conn.execute(
            "SELECT * FROM finding_index WHERE status = 'new' "
            "AND first_seen >= datetime(?, '-' || ? || ' hours') "
            "ORDER BY first_seen DESC", (cutoff, since_hours),
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_trends(self, days: int = 30) -> TrendData:
        """Aggregate finding counts over the last *days* days."""
        cutoff = datetime.now(UTC).isoformat()
        cursor = await self._conn.execute(
            "SELECT date(started_at) AS day, SUM(finding_count) AS total "
            "FROM runs WHERE started_at >= datetime(?, '-' || ? || ' days') "
            "GROUP BY day ORDER BY day", (cutoff, days),
        )
        daily = [dict(r) for r in await cursor.fetchall()]
        cursor = await self._conn.execute(
            "SELECT date(first_seen) AS day, severity, COUNT(*) AS cnt "
            "FROM finding_index WHERE first_seen >= datetime(?, '-' || ? || ' days') "
            "GROUP BY day, severity ORDER BY day", (cutoff, days),
        )
        sev = [dict(r) for r in await cursor.fetchall()]

        cursor = await self._conn.execute("SELECT COUNT(*) FROM finding_index")
        total = (await cursor.fetchone())[0]
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM finding_index WHERE status IN ('new','persistent')")
        currently_open = (await cursor.fetchone())[0]
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM finding_index WHERE status = 'fixed'")
        fixed = (await cursor.fetchone())[0]
        return TrendData(daily_counts=daily, severity_over_time=sev,
                         total_unique_findings=total, currently_open=currently_open,
                         fixed_all_time=fixed)

    # -- Housekeeping ------------------------------------------------------

    async def cleanup_old_runs(self, retain_count: int) -> int:
        """Delete the oldest runs, keeping the most recent *retain_count*.

        Removes associated history rows and on-disk scan database files.
        Returns the number of runs removed.
        """
        cursor = await self._conn.execute("SELECT COUNT(*) FROM runs")
        total = (await cursor.fetchone())[0]
        if total <= retain_count:
            return 0
        cursor = await self._conn.execute(
            "SELECT id, db_path FROM runs ORDER BY started_at ASC LIMIT ?",
            (total - retain_count,),
        )
        removed = 0
        for run in await cursor.fetchall():
            run_id, db_path = run["id"], run["db_path"]
            await self._conn.execute(
                "DELETE FROM finding_history WHERE run_id = ?", (run_id,))
            await self._conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            if db_path:
                try:
                    p = Path(db_path)
                    if p.exists():
                        os.remove(p)
                        log.debug("Deleted old scan DB: %s", p)
                except OSError as exc:
                    log.debug("Could not delete %s: %s", db_path, exc)
            removed += 1
        await self._conn.commit()
        log.debug("Cleaned up %d old run(s), retained %d", removed, retain_count)
        return removed

    # -- Convenience -------------------------------------------------------

    @staticmethod
    async def load_findings_from_scan(db_path: Path) -> list[dict[str, Any]]:
        """Read findings from a scan DB, resolving host_id to IP.

        Returns dicts ready for :meth:`process_findings` with ``host_ip``.
        """
        scan_db = Database(db_path)
        try:
            await scan_db.initialize()
            ip_map = await _resolve_host_ip_map(scan_db)
            raw = await scan_db.get_all_findings()
        finally:
            await scan_db.close()
        return [{**f, "host_ip": ip_map.get(f.get("host_id", ""), "")} for f in raw]
