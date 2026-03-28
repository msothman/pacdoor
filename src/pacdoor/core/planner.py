"""Fact-driven reactive planner — the brain of the auto-chaining pipeline.

Algorithm (v2 — per-host parallel pipeline):
  1. Run RECON phase globally to discover hosts (port scan, service detect).
  2. For each discovered host, spawn an independent async pipeline that runs
     ENUM -> VULN -> EXPLOIT -> POST for that specific host.  A semaphore
     limits total concurrent host pipelines (default 10).
  3. After all host pipelines finish, run LATERAL_MOVE globally.
  4. If lateral movement discovers new hosts, spawn host pipelines for them.
  5. Repeat lateral loop up to max_lateral_loops times.

This is the single biggest performance improvement: a /24 scan runs 10 hosts
through the full pipeline in parallel instead of waiting for every host's
enumeration to finish before any host starts vuln scanning.

Backward compatibility: fact-based chaining still works — modules declare
required_facts and produced_facts.  The planner just parallelizes by host.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pacdoor.core.models import (
    ExploitSafety,
    Finding,
    ModuleRun,
    ModuleStatus,
    Phase,
)

if TYPE_CHECKING:
    from pacdoor.core.attack_scorer import AttackScorer
    from pacdoor.core.fact_store import FactStore
    from pacdoor.modules.base import BaseModule, ModuleContext

log = logging.getLogger(__name__)

# Phases that run globally (not per-host).
GLOBAL_PHASES = [Phase.RECON, Phase.LATERAL_MOVE]

# Per-host pipeline phases, in order.
HOST_PIPELINE_PHASES = [
    Phase.ENUMERATION,
    Phase.VULN_SCAN,
    Phase.EXPLOITATION,
    Phase.POST_EXPLOIT,
]

# Full phase order (kept for backward compat with anything that imports it).
PHASE_ORDER = [
    Phase.RECON,
    Phase.ENUMERATION,
    Phase.VULN_SCAN,
    Phase.EXPLOITATION,
    Phase.POST_EXPLOIT,
    Phase.LATERAL_MOVE,
]

# Default per-module execution timeout (seconds).
MODULE_TIMEOUT = 300

# Default max concurrent host pipelines.
DEFAULT_MAX_HOST_PIPELINES = 10


class Planner:
    """Fact-driven reactive planner with per-host parallel pipelines."""

    def __init__(
        self,
        modules: list[BaseModule],
        fact_store: FactStore,
        module_context: ModuleContext,
        max_concurrency: int = 20,
        max_safety: ExploitSafety = ExploitSafety.MODERATE,
        priority_modules: list[str] | None = None,
        module_timeout: int = MODULE_TIMEOUT,
        max_host_pipelines: int = DEFAULT_MAX_HOST_PIPELINES,
        scorer: AttackScorer | None = None,
    ):
        self.modules = modules
        self.facts = fact_store
        self.ctx = module_context
        self.max_concurrency = max_concurrency
        self.max_safety = max_safety
        self.priority_modules = set(priority_modules or [])
        self.max_host_pipelines = max_host_pipelines
        self.scorer = scorer

        # Per-host tracking: (module_name, host_fact_signature)
        self._completed: set[str] = set()
        # Module-level concurrency (across all host pipelines).
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._running: set[str] = set()
        self._module_timeout = module_timeout

        # Host pipeline concurrency limiter.
        self._host_semaphore = asyncio.Semaphore(max_host_pipelines)

        # Track which hosts have had pipelines spawned (by host IP).
        self._pipeline_spawned: set[str] = set()

        # Lock for _completed and _running to avoid race conditions
        # when multiple host pipelines check/update simultaneously.
        self._state_lock = asyncio.Lock()

    def _safety_allowed(self, module: BaseModule) -> bool:
        order = list(ExploitSafety)
        return order.index(module.safety) <= order.index(self.max_safety)

    async def _eligible_modules(
        self,
        phase: Phase,
        host_id: str | None = None,
    ) -> list[tuple[BaseModule, str]]:
        """Find modules in this phase that can run now.

        When ``host_id`` is provided, only modules whose required_facts
        are satisfied for THAT specific host are returned.  This enables
        per-host pipeline progression.

        Returns (module, eligibility_signature) tuples.  The signature is
        captured at eligibility-check time and passed to ``_run_module`` so
        the EXACT same string is recorded in ``_completed``, avoiding the
        race where fact counts drift between check and completion.
        """
        eligible: list[tuple[BaseModule, str]] = []
        for mod in self.modules:
            if mod.phase != phase:
                continue
            if not self._safety_allowed(mod):
                continue

            async with self._state_lock:
                running_key = f"{mod.name}@{host_id}" if host_id is not None else mod.name
                if running_key in self._running:
                    continue

            available = await self.facts.all_fact_types()
            # "host.lateral" satisfies a "host" requirement so that
            # modules re-run on newly-compromised hosts after lateral moves.
            effective_available = set(available)
            if "host.lateral" in effective_available:
                effective_available.add("host")
            needed = set(mod.required_facts)
            if not needed.issubset(effective_available):
                continue

            # When filtering for a specific host, verify the host actually
            # has the required facts (e.g., port.open, service.smb for this host).
            if host_id is not None:
                host_facts_ok = await self._host_has_required_facts(mod, host_id)
                if not host_facts_ok:
                    continue

            # Fingerprint: module + count of each input fact type.
            # When host_id is set, include it in the signature so each host
            # gets its own eligibility tracking.
            counts = []
            for ft in sorted(needed):
                if host_id is not None:
                    c = len(await self.facts.get_for_host(ft, host_id))
                    if ft == "host":
                        c += len(await self.facts.get_for_host("host.lateral", host_id))
                    # Also count global facts of this type (modules may need
                    # both host-scoped and global facts).
                    if c == 0:
                        c = await self.facts.count(ft)
                        if ft == "host":
                            c += await self.facts.count("host.lateral")
                else:
                    c = await self.facts.count(ft)
                    if ft == "host":
                        c += await self.facts.count("host.lateral")
                counts.append(f"{ft}={c}")

            if host_id is not None:
                input_sig = f"{mod.name}@{host_id}:" + ",".join(counts) if needed else f"{mod.name}@{host_id}"
            else:
                input_sig = f"{mod.name}:" + ",".join(counts) if needed else mod.name

            async with self._state_lock:
                if input_sig in self._completed:
                    continue

            eligible.append((mod, input_sig))

        # Sort: use AttackScorer if available, otherwise fall back to
        # simple priority_modules ordering.
        if self.scorer is not None and eligible:
            ranked = await self.scorer.rank_modules(eligible, self.facts)
            # Apply widespread-vuln penalty.
            ranked = await self.scorer.apply_widespread_penalty(ranked, self.facts)
            # Log the top-scored module for visibility.
            if ranked:
                top_mod, top_sig, top_score = ranked[0]
                log.debug(
                    "Scorer: top module %s (score=%d) for phase=%s host=%s",
                    top_mod.name, top_score, phase.value,
                    host_id or "global",
                )
            # Strip score from result to match expected return type.
            eligible = [(mod, sig) for mod, sig, _score in ranked]
        else:
            # Legacy fallback: priority modules first.
            eligible.sort(
                key=lambda pair: 0 if pair[0].name in self.priority_modules else 1,
            )
        return eligible

    async def _host_has_required_facts(self, mod: BaseModule, host_id: str) -> bool:
        """Check whether a host has the facts this module requires.

        Some fact types are inherently host-scoped (port.open, service.*,
        vuln.*, credential.*).  Others are global (host, cidr).  For
        host-scoped types, we check that at least one fact exists for
        this specific host_id.  For global types, we just check existence.
        """
        # Fact type prefixes that are inherently per-host.
        host_scoped_prefixes = (
            "port.", "service.", "vuln.", "credential.", "share.",
            "webapp.", "domain.", "dns.",
        )
        for ft in mod.required_facts:
            is_host_scoped = any(ft.startswith(p) for p in host_scoped_prefixes)
            if is_host_scoped:
                host_facts = await self.facts.get_for_host(ft, host_id)
                if not host_facts:
                    return False
            else:
                if not await self.facts.has(ft):
                    return False
        return True

    async def run(
        self,
        on_module_start: Callable | None = None,
        on_module_done: Callable | None = None,
        on_phase_change: Callable | None = None,
    ) -> None:
        """Main planner loop — per-host parallel pipeline architecture.

        Phase 1: Run RECON modules globally (host discovery, port scan).
        Phase 2: For each host, spawn _run_host_pipeline() in parallel.
        Phase 3: Run LATERAL_MOVE globally.
        Phase 4: For new hosts from lateral move, spawn host pipelines.
        Phase 5: Repeat until no new hosts or max_lateral_loops reached.
        """
        max_lateral_loops = 3
        lateral_loop = 0

        # ── Phase 1: Global RECON ─────────────────────────────────────
        if on_phase_change:
            await on_phase_change(Phase.RECON.value)

        await self._run_phase_globally(
            Phase.RECON, on_module_start, on_module_done,
        )

        # ── Phase 2: Per-host parallel pipelines ──────────────────────
        await self._spawn_host_pipelines(
            on_module_start, on_module_done, on_phase_change,
        )

        # ── Phase 3+: Lateral movement loop ───────────────────────────
        while lateral_loop < max_lateral_loops:
            if on_phase_change:
                await on_phase_change(Phase.LATERAL_MOVE.value)

            lateral_eligible = await self._eligible_modules(Phase.LATERAL_MOVE)
            if not lateral_eligible:
                break

            lateral_loop += 1
            log.info("Lateral loop %d: running lateral movement modules", lateral_loop)

            await self._run_phase_globally(
                Phase.LATERAL_MOVE, on_module_start, on_module_done,
            )

            # Spawn pipelines for any newly discovered hosts.
            new_hosts = await self._spawn_host_pipelines(
                on_module_start, on_module_done, on_phase_change,
            )
            if not new_hosts:
                break

            log.info(
                "Lateral loop %d: %d new hosts discovered, pipelines spawned",
                lateral_loop, new_hosts,
            )

    async def _run_phase_globally(
        self,
        phase: Phase,
        on_start: Callable | None,
        on_done: Callable | None,
    ) -> None:
        """Run all eligible modules for a phase across all hosts.

        Used for RECON and LATERAL_MOVE which are inherently global.
        """
        changed = True
        while changed:
            changed = False
            eligible = await self._eligible_modules(phase)
            if not eligible:
                break

            tasks = []
            for mod, sig in eligible:
                tasks.append(
                    self._run_module(mod, sig, on_start, on_done)
                )
                changed = True

            if tasks:
                await asyncio.gather(*tasks)

    async def _spawn_host_pipelines(
        self,
        on_module_start: Callable | None,
        on_module_done: Callable | None,
        on_phase_change: Callable | None,
    ) -> int:
        """Spawn parallel pipelines for all discovered hosts not yet processed.

        Returns the number of NEW host pipelines spawned.
        """
        # Gather all known hosts (both directly discovered and lateral).
        all_hosts = await self.facts.get_values("host")
        lateral_hosts = await self.facts.get_values("host.lateral")
        all_hosts.extend(lateral_hosts)

        # Find hosts that haven't had a pipeline spawned yet.
        new_hosts = []
        for host in all_hosts:
            host_key = host.ip if hasattr(host, "ip") else str(host)
            if host_key not in self._pipeline_spawned:
                self._pipeline_spawned.add(host_key)
                new_hosts.append(host)

        if not new_hosts:
            return 0

        log.info(
            "Spawning parallel pipelines for %d hosts (max %d concurrent)",
            len(new_hosts), self.max_host_pipelines,
        )

        # Spawn all host pipelines concurrently, limited by _host_semaphore.
        tasks = []
        for host in new_hosts:
            host_id = host.id if hasattr(host, "id") else str(host)
            host_ip = host.ip if hasattr(host, "ip") else str(host)
            tasks.append(
                self._run_host_pipeline(
                    host_id, host_ip,
                    on_module_start, on_module_done, on_phase_change,
                )
            )

        # gather with return_exceptions=True so one host failure doesn't
        # abort all other hosts.
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                host_ip = new_hosts[i].ip if hasattr(new_hosts[i], "ip") else str(new_hosts[i])
                log.error(
                    "Host pipeline for %s failed: %s", host_ip, result,
                )

        return len(new_hosts)

    async def _run_host_pipeline(
        self,
        host_id: str,
        host_ip: str,
        on_module_start: Callable | None,
        on_module_done: Callable | None,
        on_phase_change: Callable | None,
    ) -> None:
        """Run the full ENUM -> VULN -> EXPLOIT -> POST pipeline for one host.

        Acquires the host semaphore so at most max_host_pipelines hosts
        run simultaneously.  Within each phase, eligible modules run
        concurrently (limited by the global _semaphore).
        """
        async with self._host_semaphore:
            log.info("Host pipeline started: %s (%s)", host_ip, host_id)

            for phase in HOST_PIPELINE_PHASES:
                # Emit phase change per host.  The event includes host_id
                # so TUI can show per-host progress.
                if on_phase_change:
                    await on_phase_change(
                        f"{phase.value}:{host_ip}"
                    )

                changed = True
                while changed:
                    changed = False
                    eligible = await self._eligible_modules(phase, host_id=host_id)
                    if not eligible:
                        break

                    tasks = []
                    for mod, sig in eligible:
                        tasks.append(
                            self._run_module(
                                mod, sig, on_module_start, on_module_done,
                                host_id=host_id,
                            )
                        )
                        changed = True

                    if tasks:
                        await asyncio.gather(*tasks)

            log.info("Host pipeline completed: %s (%s)", host_ip, host_id)

    async def _run_module(
        self,
        mod: BaseModule,
        eligibility_sig: str,
        on_start: Callable | None,
        on_done: Callable | None,
        host_id: str | None = None,
    ) -> None:
        async with self._semaphore:
            async with self._state_lock:
                running_key = f"{mod.name}@{host_id}" if host_id is not None else mod.name
                self._running.add(running_key)
                # Immediately mark as completed using the EXACT signature
                # from the eligibility check (prevents re-run race condition).
                self._completed.add(eligibility_sig)

            run_record = ModuleRun(
                module_name=mod.name,
                host_id=host_id,
                status=ModuleStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            if on_start:
                await on_start(mod.name, run_record)

            findings: list[Finding] = []
            error: str | None = None
            try:
                if not await mod.check(self.ctx):
                    log.debug("Module %s check() returned False, skipping", mod.name)
                    run_record.status = ModuleStatus.SKIPPED
                    run_record.completed_at = datetime.now(UTC)
                    if on_done:
                        await on_done(mod.name, run_record, [], None)
                    return

                findings = await asyncio.wait_for(
                    mod.run(self.ctx),
                    timeout=self._module_timeout,
                )
            except TimeoutError:
                log.error(
                    "Module %s timed out after %ds — facts from partial execution may be incomplete",
                    mod.name, self._module_timeout,
                )
                error = f"Timed out after {self._module_timeout}s"
            except Exception as exc:
                log.exception("Module %s failed: %s", mod.name, exc)
                error = str(exc)
            finally:
                async with self._state_lock:
                    running_key = f"{mod.name}@{host_id}" if host_id is not None else mod.name
                    self._running.discard(running_key)
                if run_record.status == ModuleStatus.RUNNING:
                    run_record.status = ModuleStatus.FAILED if error else ModuleStatus.COMPLETED
                run_record.completed_at = datetime.now(UTC)
                run_record.findings_count = len(findings)
                run_record.error = error
                if on_done and run_record.status != ModuleStatus.SKIPPED:
                    await on_done(mod.name, run_record, findings, error)
