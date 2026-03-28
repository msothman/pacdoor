"""Scan scheduler for PACDOOR's autonomous agent mode.

Runs scan jobs on configurable intervals with concurrency limits and
graceful shutdown.  Each schedule gets its own watcher coroutine.
Scans still in progress when the next interval fires are skipped.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pacdoor.agent.adaptive import AdaptivePlanner
    from pacdoor.agent.campaign import CampaignTracker
    from pacdoor.agent.config import ScheduleConfig
    from pacdoor.core.engine import Engine

log = logging.getLogger(__name__)

# How often (in seconds) we check the shutdown event during a sleep interval.
_SHUTDOWN_CHECK_INTERVAL = 5.0


@dataclass
class _ScheduleStats:
    """Accumulated run statistics for a single schedule."""

    run_count: int = 0
    total_findings: int = 0
    total_errors: int = 0
    last_run_at: datetime | None = None
    last_duration_seconds: float = 0.0
    last_findings: int = 0
    in_progress: bool = False


class ScanScheduler:
    """Run multiple scan schedules concurrently with configurable limits."""

    def __init__(
        self,
        schedules: list[ScheduleConfig],
        engine_factory: Callable[..., Engine],
        campaign: CampaignTracker,
        adaptive: AdaptivePlanner,
        max_concurrent: int = 1,
        shutdown_event: asyncio.Event | None = None,
        on_scan_complete: Callable[..., Any] | None = None,
    ) -> None:
        self._schedules = schedules
        self._engine_factory = engine_factory
        self._campaign = campaign
        self._adaptive = adaptive
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._shutdown = shutdown_event or asyncio.Event()
        self._on_scan_complete = on_scan_complete

        # Per-schedule tracking
        self._stats: dict[str, _ScheduleStats] = {
            s.name: _ScheduleStats() for s in schedules
        }

    async def run(self) -> None:
        """Main scheduler loop.  Spawns a watcher task per schedule,
        blocks until shutdown fires or all watchers exit.
        """
        log.info(
            "Scheduler starting — %d schedule(s), max %d concurrent",
            len(self._schedules),
            self._max_concurrent,
        )

        tasks: list[asyncio.Task[None]] = [
            asyncio.create_task(
                self._run_schedule(schedule),
                name=f"schedule-{schedule.name}",
            )
            for schedule in self._schedules
        ]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            # Cancel any stragglers on unexpected exit
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            log.info("Scheduler stopped")

    async def drain(self) -> None:
        """Wait for all in-progress scans to finish.

        Signals shutdown and waits until no schedule has ``in_progress`` set.
        """
        if not self._shutdown.is_set():
            self._shutdown.set()
        # Wait until nothing is in progress
        while any(s.in_progress for s in self._stats.values()):
            await asyncio.sleep(1.0)

    def summary(self) -> dict[str, Any]:
        """Return a snapshot of accumulated stats for all schedules."""
        return {
            name: {
                "run_count": stats.run_count,
                "total_findings": stats.total_findings,
                "total_errors": stats.total_errors,
                "last_run_at": (
                    stats.last_run_at.isoformat() if stats.last_run_at else None
                ),
                "last_duration_seconds": stats.last_duration_seconds,
            }
            for name, stats in self._stats.items()
        }

    async def _run_schedule(self, schedule: ScheduleConfig) -> None:
        """Watch loop for a single schedule.  Sleeps for the configured
        interval, then fires a scan.  Skips if previous scan is still running.
        """
        interval = schedule.interval_seconds
        log.info(
            "Schedule '%s' active — profile=%s, interval=%ss",
            schedule.name,
            schedule.profile,
            interval,
        )

        while not self._shutdown.is_set():
            # -- interruptible sleep ---
            if not await self._sleep(interval):
                break  # shutdown requested

            stats = self._stats[schedule.name]
            if stats.in_progress:
                log.info(
                    "Schedule '%s' — previous scan still running, skipping interval",
                    schedule.name,
                )
                continue

            # -- acquire concurrency slot ---
            async with self._semaphore:
                if self._shutdown.is_set():
                    break
                try:
                    result = await self._execute_scan(schedule)
                    findings_count = result.get("findings", 0)
                    log.info(
                        "Schedule '%s' — scan complete: %d findings",
                        schedule.name,
                        findings_count,
                    )
                except Exception:
                    log.exception(
                        "Schedule '%s' — scan failed, will retry next interval",
                        schedule.name,
                    )

    async def _execute_scan(self, schedule: ScheduleConfig) -> dict[str, Any]:
        """Build an Engine from the schedule config and run a single scan.

        Returns the engine summary dict.  After scan completes, passes
        results through the campaign tracker and adaptive planner.
        """
        stats = self._stats[schedule.name]
        stats.in_progress = True
        start = time.monotonic()

        log.info("Schedule '%s' — starting scan", schedule.name)

        try:
            # Build engine via factory (accepts schedule + optional safety override)
            safety_override = None
            if self._adaptive:
                safety_override = self._adaptive.get_current_safety()

            engine: Engine = self._engine_factory(schedule, safety_override=safety_override)
            result = await engine.run()

            # -- post-scan pipeline --
            elapsed = time.monotonic() - start
            findings_count = result.get("findings", 0)

            # 1. Campaign tracker — register run and process findings
            run_record = None
            try:
                run_record = await self._campaign.register_run(
                    schedule.name,
                    Path(f"{schedule.name}.db"),
                    result,
                )
                findings_list = result.get("findings_list", [])
                if findings_list and run_record:
                    await self._campaign.process_findings(
                        run_record.run_id, findings_list,
                    )
            except Exception:
                log.exception(
                    "Schedule '%s' — campaign tracker failed",
                    schedule.name,
                )

            # 2. Adaptive planner — analyze results for next run
            try:
                summary = result
                facts_summary = result.get("facts_summary", {})
                self._adaptive.analyze(summary, facts_summary)
            except Exception:
                log.exception(
                    "Schedule '%s' — adaptive planner failed",
                    schedule.name,
                )

            # 3. Update schedule stats
            stats.run_count += 1
            stats.total_findings += findings_count
            stats.last_run_at = datetime.now(UTC)
            stats.last_duration_seconds = round(elapsed, 1)
            stats.last_findings = findings_count

            # 4. Notify callback
            if self._on_scan_complete is not None:
                try:
                    self._on_scan_complete(schedule.name, stats.run_count, result)
                except Exception:
                    log.exception("on_scan_complete callback failed")

            return result

        except Exception:
            stats.total_errors += 1
            raise

        finally:
            stats.in_progress = False

    async def _sleep(self, seconds: float) -> bool:
        """Sleep for *seconds*, checking shutdown every 5s.  Returns True
        if the full duration elapsed, False if shutdown was requested.
        """
        remaining = seconds
        while remaining > 0:
            if self._shutdown.is_set():
                return False
            chunk = min(remaining, _SHUTDOWN_CHECK_INTERVAL)
            await asyncio.sleep(chunk)
            remaining -= chunk
        return not self._shutdown.is_set()
