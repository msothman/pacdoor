"""Central fact repository — the nervous system of the auto-chaining pipeline.

Modules push discovered facts here. The planner reads from here to decide
what to run next. Fact types form a dot-separated hierarchy:

    host                -> discovered live hosts
    port.open           -> open ports
    service.smb         -> SMB service detected
    service.http        -> HTTP service detected
    credential.valid    -> validated credential
    credential.admin    -> credential with admin access
    vuln.ms17_010       -> specific vulnerability confirmed
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from pacdoor.core.models import Credential, Host, Port

log = logging.getLogger(__name__)

# Severity tiers for eviction ordering (lowest priority evicted first).
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

# Number of concurrent read slots.
_MAX_READERS = 32


def _identity(value: Any) -> str:
    """Type-safe identity key for deduplication.

    Uses isinstance checks instead of duck-typing:
      - Host:       keyed by IP (not uuid), so same-IP hosts dedup
      - Port:       keyed by (host_id, port, protocol) to dedup same port
      - Credential: keyed by (host_id, username, cred_type) to dedup same cred
      - Everything else: falls back to .id or str()
    """
    if isinstance(value, Host):
        return f"host:{value.ip}"
    if isinstance(value, Port):
        return f"port:{value.host_id}:{value.port}:{value.protocol}"
    if isinstance(value, Credential):
        return f"cred:{value.host_id}:{value.username}:{value.cred_type}"
    if hasattr(value, "id"):
        return str(value.id)
    if hasattr(value, "ip"):
        return str(value.ip)
    return str(value)


def _fact_severity(fact: Fact) -> str:
    """Extract severity from a fact value, defaulting to ``'info'``."""
    return getattr(fact.value, "severity", "info")


class Fact:
    """A single discovered fact."""

    __slots__ = ("fact_type", "value", "source_module", "host_id", "timestamp")

    def __init__(
        self,
        fact_type: str,
        value: Any,
        source_module: str,
        host_id: str | None = None,
        timestamp: datetime | None = None,
    ):
        self.fact_type = fact_type
        self.value = value
        self.source_module = source_module
        self.host_id = host_id
        self.timestamp = timestamp or datetime.now(UTC)


class _RWLock:
    """Async reader-writer lock.

    Concurrent reads are allowed (up to ``_MAX_READERS``).  A write
    acquires *all* semaphore slots, guaranteeing exclusive access.

    A separate ``asyncio.Condition`` (with its own internal lock) is
    provided for new-fact signalling so that ``notify_all`` can be
    called while the write lock is already held without deadlocking.
    """

    def __init__(self) -> None:
        self._read_sem = asyncio.Semaphore(_MAX_READERS)
        self._write_lock = asyncio.Lock()
        # Condition uses its own lock — independent of the RW lock — so
        # writers can notify while holding the write guard.
        self.condition = asyncio.Condition()

    def read(self) -> _ReadGuard:
        return _ReadGuard(self._read_sem)

    def write(self) -> _WriteGuard:
        return _WriteGuard(self._read_sem, self._write_lock)


class _ReadGuard:
    """Context-manager that acquires one read slot."""

    def __init__(self, sem: asyncio.Semaphore) -> None:
        self._sem = sem

    async def __aenter__(self) -> None:
        await self._sem.acquire()

    async def __aexit__(self, *exc: object) -> None:
        self._sem.release()


class _WriteGuard:
    """Context-manager that drains all read slots then takes the write lock."""

    def __init__(self, sem: asyncio.Semaphore, lock: asyncio.Lock) -> None:
        self._sem = sem
        self._lock = lock
        self._acquired = 0

    async def __aenter__(self) -> None:
        await self._lock.acquire()
        for _ in range(_MAX_READERS):
            await self._sem.acquire()
            self._acquired += 1

    async def __aexit__(self, *exc: object) -> None:
        for _ in range(self._acquired):
            self._sem.release()
        self._acquired = 0
        self._lock.release()


class FactStore:
    """Thread-safe central repository of all discovered facts.

    The planner watches this for new facts and dispatches modules
    whose required_facts are now satisfied.

    Read operations acquire a single slot on a 32-slot semaphore,
    allowing up to 32 concurrent readers.  Write operations drain
    all 32 slots for exclusive access.

    ``wait_for_new_facts`` uses an ``asyncio.Condition`` (with its own
    internal lock) to eliminate the TOCTOU window between clear() and
    wait(), while allowing writers to signal without re-entrant deadlock.

    An optional *max_facts* ceiling (default 2 000 000) triggers
    intelligent eviction: lowest-severity facts are purged first.
    """

    def __init__(self, *, max_facts: int = 2_000_000) -> None:
        self._store: dict[str, list[Fact]] = defaultdict(list)
        self._rwlock = _RWLock()

        # set of (fact_type, host_id, value_identity) for dedup
        self._seen: set[tuple[str, str | None, str]] = set()
        self._subscribers: list[tuple[str, asyncio.Queue]] = []
        self._total_count = 0

        # Memory ceiling.
        self._max_facts = max_facts
        self._warn_thresholds = (0.25, 0.50, 0.75, 1.00)
        self._warned: set[float] = set()

        # Host-scoped secondary index: _host_index[fact_type][host_id] -> [Fact]
        self._host_index: dict[str, dict[str, list[Fact]]] = defaultdict(
            lambda: defaultdict(list)
        )

    # ------------------------------------------------------------------
    # Internal helpers (caller must already hold appropriate lock)
    # ------------------------------------------------------------------

    def _check_ceiling_warnings(self) -> None:
        """Emit log warnings as total_count crosses ceiling fractions."""
        for frac in self._warn_thresholds:
            threshold = int(self._max_facts * frac)
            if self._total_count >= threshold and frac not in self._warned:
                self._warned.add(frac)
                pct = int(frac * 100)
                log.warning(
                    "FactStore at %d%% capacity (%d / %d facts) — "
                    "consider reducing scan scope",
                    pct,
                    self._total_count,
                    self._max_facts,
                )

    def _evict_if_needed(self) -> None:
        """Evict oldest low-severity facts until below the ceiling."""
        if self._total_count <= self._max_facts:
            return

        target = int(self._max_facts * 0.90)  # free 10% headroom
        removed = 0

        for severity in _SEVERITY_ORDER:
            if self._total_count <= target:
                break

            # Collect (fact_type, index) pairs matching this severity,
            # sorted oldest-first by timestamp.
            candidates: list[tuple[str, int, Fact]] = []
            for ftype, facts in self._store.items():
                for idx, fact in enumerate(facts):
                    if _fact_severity(fact) == severity:
                        candidates.append((ftype, idx, fact))

            candidates.sort(key=lambda c: c[2].timestamp)

            # Walk candidates and remove until we hit the target.
            # Track indices to remove per fact_type to do bulk removal.
            to_remove: dict[str, list[int]] = defaultdict(list)
            for ftype, idx, fact in candidates:
                if self._total_count <= target:
                    break
                to_remove[ftype].append(idx)
                self._total_count -= 1
                removed += 1

                # Remove from dedup set.
                dedup_key = (fact.fact_type, fact.host_id, _identity(fact.value))
                self._seen.discard(dedup_key)

                # Remove from host index.
                if fact.host_id is not None:
                    host_list = self._host_index.get(fact.fact_type, {}).get(
                        fact.host_id
                    )
                    if host_list is not None:
                        with contextlib.suppress(ValueError):
                            host_list.remove(fact)

            # Bulk-remove from primary store (reverse order to preserve indices).
            for ftype, indices in to_remove.items():
                for idx in sorted(indices, reverse=True):
                    del self._store[ftype][idx]
                # Clean up empty lists.
                if not self._store[ftype]:
                    del self._store[ftype]

        if removed:
            log.warning(
                "FactStore evicted %d facts to stay within %d ceiling",
                removed,
                self._max_facts,
            )

    def _insert_fact(self, fact: Fact) -> None:
        """Insert a fact into all indices (caller holds write lock)."""
        self._store[fact.fact_type].append(fact)
        self._total_count += 1

        if fact.host_id is not None:
            self._host_index[fact.fact_type][fact.host_id].append(fact)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def add(
        self,
        fact_type: str,
        value: Any,
        source_module: str,
        host_id: str | None = None,
    ) -> None:
        """Add a new fact. Notifies the planner and all subscribers.

        Duplicate facts (same fact_type, host_id, value identity) are
        silently ignored.  Subscriber queues are filled *after* the lock
        is released so that a slow consumer cannot block the store.
        """
        dedup_key = (fact_type, host_id, _identity(value))
        to_notify: list[tuple[asyncio.Queue, Fact]] = []

        async with self._rwlock.write():
            if dedup_key in self._seen:
                return
            self._seen.add(dedup_key)

            fact = Fact(fact_type, value, source_module, host_id)
            self._insert_fact(fact)

            self._check_ceiling_warnings()
            self._evict_if_needed()

            # Collect subscribers to notify (but do NOT put yet)
            for pattern, queue in self._subscribers:
                if fact_type == pattern or fact_type.startswith(pattern + "."):
                    to_notify.append(
                        (queue, Fact(fact_type, value, source_module, host_id))
                    )

            # Wake anyone waiting in wait_for_new_facts()
            async with self._rwlock.condition:
                self._rwlock.condition.notify_all()

        # Put to subscriber queues outside the lock
        for queue, fact_copy in to_notify:
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(fact_copy)

    async def add_many(
        self,
        facts: list[tuple],
    ) -> None:
        """Batch-add multiple facts under a single write-lock acquisition.

        Each element of *facts* is a tuple of
        ``(fact_type, value, source_module)`` or
        ``(fact_type, value, source_module, host_id)``.

        Duplicates within the batch and against existing facts are
        silently ignored.  Subscribers and waiters are notified once
        after all insertions complete.
        """
        to_notify: list[tuple[asyncio.Queue, Fact]] = []
        added = 0

        async with self._rwlock.write():
            for entry in facts:
                if len(entry) == 4:
                    fact_type, value, source_module, host_id = entry
                elif len(entry) == 3:
                    fact_type, value, source_module = entry
                    host_id = None
                else:
                    continue  # skip malformed entries

                dedup_key = (fact_type, host_id, _identity(value))
                if dedup_key in self._seen:
                    continue
                self._seen.add(dedup_key)

                fact = Fact(fact_type, value, source_module, host_id)
                self._insert_fact(fact)
                added += 1

                for pattern, queue in self._subscribers:
                    if fact_type == pattern or fact_type.startswith(pattern + "."):
                        to_notify.append(
                            (queue, Fact(fact_type, value, source_module, host_id))
                        )

            if added:
                self._check_ceiling_warnings()
                self._evict_if_needed()

                async with self._rwlock.condition:
                    self._rwlock.condition.notify_all()

        # Put to subscriber queues outside the lock
        for queue, fact_copy in to_notify:
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(fact_copy)

    async def has(self, fact_type: str) -> bool:
        """Check if at least one fact of this type exists."""
        async with self._rwlock.read():
            return len(self._store.get(fact_type, [])) > 0

    async def get_all(self, fact_type: str) -> list[Fact]:
        """Return all facts of a given type."""
        async with self._rwlock.read():
            return list(self._store.get(fact_type, []))

    async def get_values(self, fact_type: str) -> list[Any]:
        """Return just the values (unwrapped) for a given type."""
        async with self._rwlock.read():
            return [f.value for f in self._store.get(fact_type, [])]

    async def get_for_host(self, fact_type: str, host_id: str) -> list[Any]:
        """Return fact values filtered to a specific host.

        Uses the host-scoped secondary index for O(1) lookup instead
        of scanning all facts of the given type.
        """
        async with self._rwlock.read():
            return [
                f.value
                for f in self._host_index.get(fact_type, {}).get(host_id, [])
            ]

    async def wait_for_new_facts(self) -> None:
        """Block until a new fact is added. Uses Condition to avoid TOCTOU."""
        async with self._rwlock.condition:
            await self._rwlock.condition.wait()

    def subscribe(self, fact_pattern: str) -> asyncio.Queue:
        """Subscribe to facts matching a pattern. Returns a queue to read from."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.append((fact_pattern, queue))
        return queue

    async def all_fact_types(self) -> set[str]:
        """Return all fact types currently in the store."""
        async with self._rwlock.read():
            return set(self._store.keys())

    async def count(self, fact_type: str) -> int:
        """Count facts of a given type."""
        async with self._rwlock.read():
            return len(self._store.get(fact_type, []))

    async def total_count(self) -> int:
        """Total facts across all types."""
        async with self._rwlock.read():
            return self._total_count

    async def summary(self) -> dict[str, int]:
        """Return {fact_type: count} for all types."""
        async with self._rwlock.read():
            return {k: len(v) for k, v in self._store.items()}
