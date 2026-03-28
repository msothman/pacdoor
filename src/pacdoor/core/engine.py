"""Main orchestration engine — ties everything together."""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import logging
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pacdoor.core.attack_graph import AttackGraph
from pacdoor.core.checkpoint import CheckpointManager
from pacdoor.core.connection_pool import ConnectionPool
from pacdoor.core.events import Event, EventBus
from pacdoor.core.fact_store import FactStore
from pacdoor.core.models import (
    ExploitSafety,
    Finding,
    Host,
    ModuleRun,
)
from pacdoor.core.module_registry import ModuleRegistry
from pacdoor.core.planner import Planner
from pacdoor.core.rate_limiter import TokenBucketRateLimiter
from pacdoor.core.scope import ScopeEnforcer
from pacdoor.core.target_profiler import TargetProfiler
from pacdoor.db.database import Database
from pacdoor.modules.base import ModuleContext, UserCredentials

log = logging.getLogger(__name__)


class Engine:
    """The central orchestrator. Initializes all components and drives execution."""

    def __init__(
        self,
        targets: list[str],
        db_path: Path,
        max_concurrency: int = 20,
        rate_limit: int = 100,
        max_safety: str = "moderate",
        no_exploit: bool = False,
        recon_only: bool = False,
        offline: bool = False,
        timeout: int = 0,
        exclude: list[str] | None = None,
        ports: str = "top1000",
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        resume: bool = False,
        excluded_modules: list[str] | None = None,
        module_timeout: int = 300,
        scope_file: str | None = None,
        module_dir: str | None = None,
    ):
        self.targets_raw = targets or []
        self.db_path = db_path
        self.max_concurrency = max_concurrency
        self.max_safety = max_safety
        self.no_exploit = no_exploit
        self.recon_only = recon_only
        self.offline = offline
        self.timeout = timeout
        self.exclude = exclude or []
        self.ports = ports
        self.resume = resume
        self.excluded_modules = excluded_modules or []
        self.module_timeout = module_timeout
        self.module_dir = module_dir

        self.facts = FactStore()
        self.events = EventBus()
        self.rate_limiter = TokenBucketRateLimiter(rate_limit)
        self.registry = ModuleRegistry()
        self.profiler = TargetProfiler()
        self.attack_graph = AttackGraph()
        self.pool = ConnectionPool()
        self.db: Database | None = None
        self._shutdown = asyncio.Event()
        self._start_time: datetime | None = None
        self._planner: Planner | None = None

        self.user_creds = UserCredentials(
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
        )

        # ── Scope enforcement ──
        # Build in-scope list from CLI targets + optional scope file
        in_scope_entries: list[str] = list(self.targets_raw)
        if scope_file:
            file_entries = ScopeEnforcer.from_file(Path(scope_file))
            in_scope_entries.extend(file_entries)
        self.scope = ScopeEnforcer(in_scope=in_scope_entries, exclude=self.exclude)

        # Validate ExploitSafety at init time (fail fast on bad CLI input)
        try:
            ExploitSafety(self.max_safety)
        except ValueError as exc:
            raise ValueError(
                f"Invalid --max-safety value '{self.max_safety}': "
                f"must be one of {[e.value for e in ExploitSafety]}"
            ) from exc

    def _build_module_context(self) -> ModuleContext:
        """Create a ModuleContext for passing to modules."""
        return ModuleContext(
            facts=self.facts,
            db=self.db,
            rate_limiter=self.rate_limiter,
            events=self.events,
            attack_graph=self.attack_graph,
            pool=self.pool,
            user_creds=self.user_creds,
            config={
                "timeout": self.timeout,
                "exclude": self.exclude,
                "ports": self.ports,
                "max_safety": self.max_safety,
                "scope": self.scope,
            },
        )

    async def initialize(self) -> None:
        """Set up DB, run updates, register modules, seed facts."""
        self.db = Database(self.db_path)
        await self.db.initialize()

        # Self-update (unless --offline)
        try:
            from pacdoor.updater.manager import UpdateManager
            updater = UpdateManager(offline=self.offline)
            await updater.check_all()
            self.events.emit(Event.UPDATE_COMPLETE)
        except Exception as exc:
            log.warning("Auto-update failed (continuing with local data): %s", exc)

        # Auto-discover and register all modules (including external dirs)
        ext_dirs = [self.module_dir] if self.module_dir else None
        self.registry.discover_modules(external_dirs=ext_dirs)
        log.info("Registered %d modules: %s", self.registry.count(),
                 ", ".join(self.registry.list_names()))

        # ── Profile-based module exclusions ──
        if self.excluded_modules:
            self._apply_module_exclusions()

        # Remove phases based on CLI flags
        if self.recon_only:
            for phase in ["enumeration", "vulnerability_scan", "exploitation",
                          "post_exploitation", "lateral_movement"]:
                self.registry.remove_phase(phase)
        elif self.no_exploit:
            for phase in ["exploitation", "post_exploitation", "lateral_movement"]:
                self.registry.remove_phase(phase)

        # ── Resume: restore facts from DB + checkpoint ──
        if self.resume:
            await self._restore_from_checkpoint()
        else:
            # Seed fact store with targets (fresh scan)
            await self._seed_targets()

    def _apply_module_exclusions(self) -> None:
        """Remove modules matching excluded_modules glob patterns.

        Patterns use fnmatch-style globs (e.g. ``exploit.*``, ``enum.smb*``).
        """
        all_names = self.registry.list_names()
        to_remove: set[str] = set()
        for pattern in self.excluded_modules:
            for name in all_names:
                if fnmatch.fnmatch(name, pattern):
                    to_remove.add(name)
        if to_remove:
            for name in to_remove:
                self.registry.remove_by_name(name)
            log.info("Excluded %d modules via profile: %s", len(to_remove),
                     ", ".join(sorted(to_remove)))

    async def _restore_from_checkpoint(self) -> None:
        """Restore scan state from a checkpoint file and the existing DB."""
        output_dir = self.db_path.parent
        if not CheckpointManager.can_resume(output_dir):
            log.warning("No checkpoint found in %s — starting fresh scan", output_dir)
            await self._seed_targets()
            return

        checkpoint = CheckpointManager.load(output_dir)

        # If targets weren't provided on CLI, restore from checkpoint
        if not self.targets_raw:
            self.targets_raw = checkpoint.get("targets", [])

        # Restore completed signatures (stored for planner injection later)
        self._resumed_completed: set[str] = set(
            checkpoint.get("completed_signatures", [])
        )

        # Re-seed fact store from the DB (hosts, ports, credentials)
        await CheckpointManager.restore_facts(self)

        log.info(
            "Resumed from checkpoint: %d completed signatures, %s",
            len(self._resumed_completed),
            checkpoint.get("checkpoint_time", "unknown"),
        )

    async def _seed_targets(self) -> None:
        """Parse user-provided targets into initial facts.

        Handles both IPv4 and IPv6 via ``ipaddress.ip_network``.
        Validates each target against the scope enforcer.
        """
        for raw in self.targets_raw:
            # Skip excluded targets
            if raw in self.exclude:
                continue

            # ── Scope validation ──
            if not self.scope.validate(raw):
                log.critical("SCOPE VIOLATION: target %s is out of scope — skipping", raw)
                continue

            try:
                network = ipaddress.ip_network(raw, strict=False)
                if network.num_addresses == 1:
                    host = Host(ip=str(network.network_address))
                    await self.facts.add("host", host, "user_input")
                    await self.db.insert_host(host)  # Persist immediately for FK refs
                    self.events.emit(Event.HOST_DISCOVERED, {"ip": host.ip})
                else:
                    await self.facts.add("cidr", str(network), "user_input")
            except ValueError:
                # Not a valid IP/CIDR — treat as a hostname and resolve it
                try:
                    loop = asyncio.get_running_loop()
                    results = await loop.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
                    if results:
                        resolved_ip = results[0][4][0]
                        # Validate resolved IP against scope
                        if not self.scope.is_in_scope(resolved_ip):
                            log.critical(
                                "SCOPE VIOLATION: %s resolved to %s which is out of scope — skipping",
                                raw, resolved_ip,
                            )
                            continue
                        host = Host(ip=resolved_ip, hostname=raw)
                        await self.facts.add("host", host, "user_input")
                        await self.db.insert_host(host)
                        self.events.emit(Event.HOST_DISCOVERED, {"ip": resolved_ip, "hostname": raw})
                        log.info("Resolved hostname %s -> %s", raw, resolved_ip)
                    else:
                        log.warning("Hostname %s resolved to no addresses", raw)
                        await self.facts.add("hostname", raw, "user_input")
                except (socket.gaierror, OSError) as resolve_err:
                    log.warning("Failed to resolve hostname %s: %s", raw, resolve_err)
                    await self.facts.add("hostname", raw, "user_input")

    async def run(self) -> dict[str, Any]:
        """Main execution loop. Returns summary dict.

        Wraps the planner in a timeout and always closes the DB in a
        finally block.  Checks ``self._shutdown`` in planner callbacks
        so a signal can abort mid-scan.
        """
        self._start_time = datetime.now(UTC)
        await self.initialize()

        ctx = self._build_module_context()

        planner = Planner(
            modules=self.registry.all_modules(),
            fact_store=self.facts,
            module_context=ctx,
            max_concurrency=self.max_concurrency,
            max_safety=ExploitSafety(self.max_safety),
            module_timeout=self.module_timeout,
        )
        self._planner = planner

        # ── Resume: inject completed signatures into planner ──
        resumed_sigs = getattr(self, "_resumed_completed", None)
        if resumed_sigs:
            planner._completed.update(resumed_sigs)
            log.info("Injected %d completed signatures into planner", len(resumed_sigs))

        try:
            planner_coro = planner.run(
                on_module_start=self._on_module_start,
                on_module_done=self._on_module_done,
                on_phase_change=self._on_phase_change,
            )

            if self.timeout > 0:
                try:
                    await asyncio.wait_for(planner_coro, timeout=self.timeout)
                except TimeoutError:
                    log.warning("Scan timed out after %d seconds", self.timeout)
                    # Auto-save checkpoint on timeout
                    await self._save_checkpoint()
            else:
                await planner_coro

            # Profile all discovered hosts (including laterally-moved) and persist
            all_hosts = await self.facts.get_values("host")
            all_hosts.extend(await self.facts.get_values("host.lateral"))
            for host in all_hosts:
                profile = await self.profiler.classify(host, self.facts)
                host.profile = profile
                await self.db.insert_host(host)
                self.events.emit(Event.PROFILE_DETECTED,
                                 {"ip": host.ip, "profile": profile.value})

            # Persist attack graph paths to the database
            for path in self.attack_graph.get_all():
                await self.db.insert_attack_path(path)

            await self.db.flush()

            self.events.emit(Event.SCAN_COMPLETE)

            # Successful completion — remove checkpoint
            CheckpointManager.delete(self.db_path.parent)

            return await self._build_summary()
        except (asyncio.CancelledError, KeyboardInterrupt):
            # Interrupted — save checkpoint for resume
            log.warning("Scan interrupted — saving checkpoint")
            await self._save_checkpoint()
            raise
        finally:
            # Clean up any SSH pivot tunnels.
            try:
                from pacdoor.modules.post.ssh_pivot import cleanup_all_tunnels
                cleanup_all_tunnels()
            except ImportError:
                pass
            await self.pool.close()
            if self.db:
                await self.db.close()

    async def _save_checkpoint(self) -> None:
        """Persist current scan state for later resume."""
        planner_completed = self._planner._completed if self._planner else set()
        try:
            await CheckpointManager.save(self, planner_completed=planner_completed)
        except Exception as exc:
            log.error("Failed to save checkpoint: %s", exc)

    async def _on_module_start(self, module_name: str, run: ModuleRun) -> None:
        if self._shutdown.is_set():
            raise asyncio.CancelledError("Engine shutdown requested")
        await self.db.insert_module_run(run)
        self.events.emit(Event.MODULE_STARTED, {"module": module_name})

    async def _on_module_done(
        self,
        module_name: str,
        run: ModuleRun,
        findings: list[Finding],
        error: str | None = None,
    ) -> None:
        if self._shutdown.is_set():
            # Still persist findings to DB before returning
            for f in findings:
                await self.db.insert_finding(f)
            await self.db.flush()
            return
        await self.db.update_module_run(
            run.id,
            status=run.status,
            completed_at=run.completed_at,
            error=error,
            findings_count=len(findings),
        )
        for f in findings:
            await self.db.insert_finding(f)
            self.events.emit(Event.FINDING_DISCOVERED, {
                "title": f.title, "severity": f.severity.value,
            })

        # Persist any newly discovered hosts to DB (for FK refs in ports/findings)
        if module_name in ("recon.host_discovery", "post.lateral_move"):
            for host in await self.facts.get_values("host"):
                # Scope check on newly discovered hosts
                if not self.scope.is_in_scope(host.ip):
                    log.critical(
                        "SCOPE VIOLATION: discovered host %s is out of scope — ignoring",
                        host.ip,
                    )
                    continue
                await self.db.insert_host(host)
            # Lateral moves store hosts under "host.lateral"
            for host in await self.facts.get_values("host.lateral"):
                if not self.scope.is_in_scope(host.ip):
                    log.critical(
                        "SCOPE VIOLATION: lateral host %s is out of scope — ignoring",
                        host.ip,
                    )
                    continue
                await self.db.insert_host(host)

        # Run profiler after port scan completes (not just at the end)
        if module_name == "recon.port_scan":
            for host in await self.facts.get_values("host"):
                profile = await self.profiler.classify(host, self.facts)
                host.profile = profile

        self.events.emit(Event.MODULE_COMPLETED, {
            "module": module_name,
            "findings": len(findings),
            "error": error,
        })

        await self.db.flush()

    async def _on_phase_change(self, phase_name: str) -> None:
        if self._shutdown.is_set():
            raise asyncio.CancelledError("Engine shutdown requested")
        self.events.emit(Event.PHASE_CHANGED, {"phase": phase_name})

    async def _build_summary(self) -> dict[str, Any]:
        elapsed = (datetime.now(UTC) - self._start_time).total_seconds()
        return {
            "hosts": await self.facts.count("host"),
            "ports": await self.facts.count("port.open"),
            "findings": await self.db.count_findings(),
            "findings_by_severity": await self.db.count_findings_by_severity(),
            "credentials": await self.facts.count("credential.valid"),
            "modules_run": len(await self.db.get_all_module_runs()),
            "elapsed_seconds": round(elapsed, 1),
            "fact_summary": await self.facts.summary(),
        }

    def shutdown(self) -> None:
        self._shutdown.set()
