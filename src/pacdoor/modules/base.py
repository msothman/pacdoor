"""Abstract base class for all modules.

Every module in the system implements this interface. The key design:
modules declare what fact types they require as input and what fact types
they produce as output. The planner uses this to auto-chain.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import ExploitSafety, Finding, Phase

if TYPE_CHECKING:
    from pacdoor.core.attack_graph import AttackGraph
    from pacdoor.core.connection_pool import ConnectionPool
    from pacdoor.core.events import EventBus
    from pacdoor.core.fact_store import FactStore
    from pacdoor.core.rate_limiter import TokenBucketRateLimiter
    from pacdoor.db.database import Database


@dataclass
class UserCredentials:
    """Credentials supplied via CLI flags."""
    username: str | None = None
    password: str | None = None
    ntlm_hash: str | None = None
    domain: str | None = None


@dataclass
class ModuleContext:
    """Everything a module needs to do its work.

    Passed to ``BaseModule.run()`` and ``BaseModule.check()`` so that
    modules have a single, well-typed handle to all engine services.
    """
    facts: FactStore
    db: Database
    rate_limiter: TokenBucketRateLimiter
    events: EventBus
    attack_graph: AttackGraph
    pool: ConnectionPool | None = None
    user_creds: UserCredentials = field(default_factory=UserCredentials)
    config: dict[str, Any] = field(default_factory=dict)


class BaseModule(abc.ABC):
    """Every module in the system implements this interface."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique module identifier, e.g. 'recon.port_scan'."""

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable one-liner."""

    @property
    @abc.abstractmethod
    def phase(self) -> Phase:
        """Which pipeline phase this module belongs to."""

    @property
    @abc.abstractmethod
    def attack_technique_ids(self) -> list[str]:
        """MITRE ATT&CK technique IDs, e.g. ['T1046']."""

    # -- Fact-based chaining -----------------------------------------------

    @property
    def required_facts(self) -> list[str]:
        """Fact types this module needs to run.

        Examples: 'host', 'port.open', 'service.smb',
        'credential.valid', 'credential.admin'
        An empty list means the module can run immediately (e.g. host discovery).
        """
        return []

    @property
    def produced_facts(self) -> list[str]:
        """Fact types this module produces when it runs.

        The planner uses this to know what becomes available after this module.
        """
        return []

    # -- Safety ------------------------------------------------------------

    @property
    def safety(self) -> ExploitSafety:
        """How dangerous is this module? The engine enforces policy."""
        return ExploitSafety.SAFE

    # -- Execution ---------------------------------------------------------

    @abc.abstractmethod
    async def run(self, ctx: ModuleContext) -> list[Finding]:
        """Execute the module. Read inputs from ctx.facts, produce Findings.

        The module should also push new facts into the store
        (new hosts, ports, credentials, etc.) via ctx.facts.add().
        """

    async def check(self, ctx: ModuleContext) -> bool:
        """Optional pre-check: can this module run given current facts?

        Default implementation checks that all required_facts exist.
        Override for more complex preconditions.
        """
        for fact_type in self.required_facts:
            if not await ctx.facts.has(fact_type):
                return False
        return True

    async def resolve_ip(self, ctx: ModuleContext, host_id: str) -> str | None:
        """Helper: look up IP address for a host_id from the fact store."""
        for host in await ctx.facts.get_values("host"):
            if host.id == host_id:
                return host.ip
        return None
