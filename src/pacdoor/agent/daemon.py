"""Main daemon process for PACDOOR's autonomous agent mode.

Ties together the config, scheduler, campaign tracker, and adaptive planner
into a single long-running process with graceful shutdown, PID-file
management, and per-scan summary logging.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import platform
import signal
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pacdoor.agent.adaptive import AdaptivePlanner
from pacdoor.agent.campaign import CampaignTracker
from pacdoor.agent.config import AgentConfig, ScheduleConfig, load_config
from pacdoor.agent.scheduler import ScanScheduler
from pacdoor.core.engine import Engine
from pacdoor.core.profiles import PROFILES

log = logging.getLogger(__name__)

_VERSION = "0.1.0"
_PID_FILENAME = "pacdoor-agent.pid"
_SHUTDOWN_GRACE_SECONDS = 60


# -- PID-file helpers -------------------------------------------------------

def _pid_path(output_dir: Path) -> Path:
    return output_dir / _PID_FILENAME


def _check_stale_pid(output_dir: Path) -> None:
    """Warn if another agent appears to be running (stale PID file)."""
    pidfile = _pid_path(output_dir)
    if not pidfile.exists():
        return
    try:
        old_pid = int(pidfile.read_text().strip())
    except (ValueError, OSError):
        log.warning("Corrupt PID file at %s — removing", pidfile)
        pidfile.unlink(missing_ok=True)
        return
    try:
        os.kill(old_pid, 0)  # signal 0 = existence check
        log.warning(
            "Another agent may be running (PID %d from %s). "
            "If this is stale, delete the file and restart.",
            old_pid, pidfile,
        )
    except OSError:
        log.info("Removing stale PID file (PID %d no longer running)", old_pid)
        pidfile.unlink(missing_ok=True)


def _write_pid(output_dir: Path) -> Path:
    pidfile = _pid_path(output_dir)
    pidfile.write_text(str(os.getpid()))
    log.debug("Wrote PID %d to %s", os.getpid(), pidfile)
    return pidfile


def _remove_pid(output_dir: Path) -> None:
    _pid_path(output_dir).unlink(missing_ok=True)


# -- Startup banner ---------------------------------------------------------

def _print_banner(config: AgentConfig) -> None:
    """Print a startup summary to stderr."""
    schedules = "; ".join(
        f"{s.name}({s.profile} @{s.interval})" for s in config.schedules
    )
    lines = [
        "",
        "=" * 60,
        f"  PACDOOR Agent v{_VERSION}",
        "=" * 60,
        f"  Targets     : {', '.join(config.targets)}",
        f"  Excludes    : {', '.join(config.exclude) or '(none)'}",
        f"  Schedules   : {schedules}",
        f"  Safety      : {config.behavior.max_safety}",
        f"  Adaptive    : {config.behavior.adaptive}",
        f"  Escalation  : {config.behavior.escalation}",
        f"  Concurrency : {config.behavior.concurrent_scans}",
        f"  Output      : {config.output.dir}",
        "=" * 60,
        "",
    ]
    sys.stderr.write("\n".join(lines) + "\n")
    sys.stderr.flush()


# -- Engine factory ---------------------------------------------------------

def _build_engine_factory(
    config: AgentConfig,
    output_dir: Path,
) -> Callable[..., Engine]:
    """Return a callable that creates a fresh Engine for each scan run."""

    def factory(
        schedule: ScheduleConfig,
        safety_override: str | None = None,
    ) -> Engine:
        prof = PROFILES.get(schedule.profile, {})
        safety = safety_override or config.behavior.max_safety
        creds = schedule.credentials

        return Engine(
            targets=list(config.targets),
            db_path=output_dir / f"{schedule.name}.db",
            max_concurrency=prof.get("concurrency", 20),
            rate_limit=prof.get("rate_limit", 100),
            max_safety=safety,
            no_exploit=prof.get("no_exploit", False),
            recon_only=prof.get("recon_only", False),
            exclude=list(config.exclude),
            ports=prof.get("ports", "top1000"),
            username=creds.username if creds else None,
            password=creds.password if creds else None,
            domain=creds.domain if creds else None,
            excluded_modules=prof.get("excluded_modules", []),
            module_timeout=prof.get("module_timeout", 300),
        )

    return factory


# -- Per-scan summary -------------------------------------------------------

def _log_scan_summary(name: str, run_no: int, s: dict[str, Any]) -> None:
    """Log a one-line summary after each scan completes."""
    hosts, total = s.get("hosts", 0), s.get("findings", 0)
    new, elapsed = s.get("new_findings", total), s.get("elapsed_seconds", 0)
    mins, secs = divmod(int(elapsed), 60)
    log.info(
        "Scan '%s' #%d: %d hosts, %d findings (%d new), %dm%02ds",
        name, run_no, hosts, total, new, mins, secs,
    )


# -- Signal handler installation --------------------------------------------

def _install_signal_handlers(shutdown_event: asyncio.Event) -> None:
    """Register OS signal handlers to trigger graceful shutdown."""

    def _on_signal(*_args: Any) -> None:
        if not shutdown_event.is_set():
            log.info("Received shutdown signal")
            shutdown_event.set()

    if platform.system() == "Windows":
        signal.signal(signal.SIGINT, _on_signal)
        with contextlib.suppress(AttributeError):
            signal.signal(signal.SIGBREAK, _on_signal)  # type: ignore[attr-defined]
    else:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _on_signal)


# -- Campaign summary -------------------------------------------------------

def _print_campaign_summary(summary: dict[str, Any]) -> None:
    """Print a final campaign summary to stderr on shutdown."""
    g = summary.get
    lines = [
        "", "-" * 60, "  Campaign Summary", "-" * 60,
        f"  Total scans     : {g('total_scans', 0)}",
        f"  Total findings  : {g('total_findings', 0)}",
        f"  Unique findings : {g('unique_findings', 0)}",
        f"  Critical        : {g('critical', 0)}",
        f"  High            : {g('high', 0)}",
        f"  Medium          : {g('medium', 0)}",
        f"  Low / Info      : {g('low', 0)}",
        f"  Runtime         : {g('total_runtime', 'N/A')}",
        "-" * 60, "",
    ]
    sys.stderr.write("\n".join(lines) + "\n")
    sys.stderr.flush()


# -- Main daemon coroutine --------------------------------------------------

async def run_agent(config_path: Path) -> None:
    """Main entry point for the agent daemon."""
    config = load_config(config_path)
    log.info("Loaded config from %s", config_path)

    output_dir = Path(config.output.dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # PID file
    _check_stale_pid(output_dir)
    _write_pid(output_dir)

    _print_banner(config)

    # Initialize persistent components
    campaign = CampaignTracker(output_dir / "campaign.db")
    await campaign.initialize()

    adaptive = AdaptivePlanner(
        escalation_mode=config.behavior.escalation,
        escalation_hours=config.behavior.escalation_after_hours,
    )

    shutdown_event = asyncio.Event()
    engine_factory = _build_engine_factory(config, output_dir)

    scheduler = ScanScheduler(
        schedules=config.schedules,
        engine_factory=engine_factory,
        campaign=campaign,
        adaptive=adaptive,
        max_concurrent=config.behavior.concurrent_scans,
        shutdown_event=shutdown_event,
        on_scan_complete=_log_scan_summary,
    )

    _install_signal_handlers(shutdown_event)

    log.info("Agent started (PID %d)", os.getpid())
    try:
        await scheduler.run()
    except asyncio.CancelledError:
        log.info("Agent cancelled")
    finally:
        if not shutdown_event.is_set():
            shutdown_event.set()

        log.info(
            "Shutting down — waiting up to %ds for running scans",
            _SHUTDOWN_GRACE_SECONDS,
        )
        try:
            await asyncio.wait_for(
                scheduler.drain(), timeout=_SHUTDOWN_GRACE_SECONDS,
            )
        except (TimeoutError, AttributeError):
            log.warning("Grace period expired; forcing shutdown")

        try:
            trends = await campaign.get_trends()
            sev_counts: dict[str, int] = {}
            for row in trends.severity_over_time:
                sev_counts[row["severity"]] = (
                    sev_counts.get(row["severity"], 0) + row["cnt"]
                )
            _print_campaign_summary({
                "total_scans": trends.total_unique_findings,
                "total_findings": trends.total_unique_findings,
                "unique_findings": trends.total_unique_findings,
                "critical": sev_counts.get("critical", 0),
                "high": sev_counts.get("high", 0),
                "medium": sev_counts.get("medium", 0),
                "low": sev_counts.get("low", 0),
                "total_runtime": "N/A",
            })
        except Exception as exc:
            log.error("Failed to retrieve campaign summary: %s", exc)

        await campaign.close()
        _remove_pid(output_dir)
        log.info("Agent stopped cleanly")


# -- Synchronous entry point (called from CLI) ------------------------------

def start_agent(config_path: Path) -> None:
    """Synchronous wrapper around :func:`run_agent`.

    Configures root logging and delegates to ``asyncio.run``.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    try:
        asyncio.run(run_agent(config_path))
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception:
        log.exception("Agent terminated with an unhandled error")
        sys.exit(1)
