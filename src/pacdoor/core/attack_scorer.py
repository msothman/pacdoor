"""Heuristic-based attack path scorer — prioritizes high-value targets and modules.

No AI/LLM involved. Pure rule-based scoring that makes the planner smarter about
WHAT to attack first. Instead of running all eligible modules equally, it scores
and ranks them so crown-jewel hosts and credential-producing modules run first.

Scoring dimensions:
  1. Host value   — DC > DB > Web > File > Server > Desktop > Unknown
  2. Attack path  — Domain Admin chain > credential harvest > lateral > sensitive data
  3. Module priority — chains into downstream modules, targets high-value hosts,
                       produces credentials, enables lateral movement
"""

from __future__ import annotations

import ipaddress
import logging
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import TargetProfile

if TYPE_CHECKING:
    from pacdoor.core.attack_graph import AttackGraph
    from pacdoor.core.fact_store import FactStore
    from pacdoor.modules.base import BaseModule

log = logging.getLogger(__name__)


# ─── Host Value Scores ───────────────────────────────────────────────────

HOST_VALUE_SCORES: dict[TargetProfile, int] = {
    TargetProfile.WINDOWS_DC: 100,
    TargetProfile.DATABASE_SERVER: 80,
    TargetProfile.WEB_SERVER: 70,
    TargetProfile.MAIL_SERVER: 65,
    TargetProfile.LINUX_SERVER: 40,
    TargetProfile.WINDOWS_SERVER: 50,
    TargetProfile.WINDOWS_DESKTOP: 20,
    TargetProfile.DNS_SERVER: 30,
    TargetProfile.PROXY_LB: 35,
    TargetProfile.CLOUD_INSTANCE: 45,
    TargetProfile.CONTAINER: 25,
    TargetProfile.NETWORK_DEVICE: 30,
    TargetProfile.IOT_EMBEDDED: 15,
    TargetProfile.UNKNOWN: 10,
}

# Port sets for heuristic detection (mirrors target_profiler.py).
DC_PORTS = {88, 389, 636, 445, 464, 3268, 3269}
DB_PORTS = {1433, 3306, 5432, 1521, 6379, 27017, 9200, 5984}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
FILE_SHARE_PORTS = {445, 139, 2049}  # SMB + NFS

# Fact types that indicate credential production.
CREDENTIAL_FACT_TYPES = frozenset({
    "credential.valid",
    "credential.admin",
    "credential.ntlm",
    "credential.ticket",
    "credential.token",
    "credential.ssh_key",
    "credential.password",
})

# Fact types that indicate lateral movement capability.
LATERAL_FACT_TYPES = frozenset({
    "host.lateral",
    "credential.admin",
    "credential.ntlm",
    "credential.ticket",
})

# Module name substrings that strongly indicate credential harvesting.
CREDENTIAL_MODULE_HINTS = frozenset({
    "cred_harvest", "kerberoast", "dcsync", "mimikatz", "hashdump",
    "secretsdump", "lsass", "sam_dump", "credential_spray",
    "ssh_brute", "brute", "default_creds",
})

# Module name substrings that indicate lateral movement capability.
LATERAL_MODULE_HINTS = frozenset({
    "lateral", "psexec", "wmi_exec", "smbexec", "winrm",
    "pass_the_hash", "pass_the_ticket", "pivot",
})


# ─── Attack Path Scores ──────────────────────────────────────────────────

class AttackPathType:
    """Named constants for attack path value scoring."""
    DOMAIN_ADMIN = 1000
    SENSITIVE_DATA = 600
    CREDENTIAL_HARVEST = 500
    NEW_NETWORK_SEGMENT = 400
    LATERAL_MOVEMENT = 300


# ─── Scorer ──────────────────────────────────────────────────────────────


class AttackScorer:
    """Heuristic-based scorer that ranks hosts, modules, and attack paths.

    Designed to be instantiated once and reused across planner cycles.
    All scoring methods are async because they read from the async FactStore.
    The scorer is stateless between calls — all state lives in the FactStore
    and AttackGraph.
    """

    def __init__(self, modules: list[BaseModule] | None = None) -> None:
        # Pre-compute the downstream-chain map if modules are provided.
        # Maps a produced fact type -> list of module names that require it.
        self._downstream_map: dict[str, list[str]] = defaultdict(list)
        self._module_lookup: dict[str, BaseModule] = {}
        if modules:
            self._build_chain_map(modules)

    # ── Initialization ────────────────────────────────────────────────

    def _build_chain_map(self, modules: list[BaseModule]) -> None:
        """Build a mapping from produced facts to downstream consumers.

        This lets us score modules higher when they unlock many downstream
        modules (high chaining potential).
        """
        # First, collect all required facts across all modules.
        required_by: dict[str, list[str]] = defaultdict(list)
        for mod in modules:
            self._module_lookup[mod.name] = mod
            for ft in mod.required_facts:
                required_by[ft].append(mod.name)

        # For each module, see how many downstream modules its produced
        # facts unlock.
        for mod in modules:
            for ft in mod.produced_facts:
                # Exact match.
                if ft in required_by:
                    self._downstream_map[mod.name].extend(required_by[ft])
                # Hierarchical match: producing "credential.admin" satisfies
                # a requirement for "credential".
                for req_ft, consumers in required_by.items():
                    if ft.startswith(req_ft + ".") or req_ft.startswith(ft + "."):
                        self._downstream_map[mod.name].extend(consumers)

        # Deduplicate.
        for mod_name in self._downstream_map:
            self._downstream_map[mod_name] = list(
                set(self._downstream_map[mod_name])
            )

    # ── Host Scoring ──────────────────────────────────────────────────

    async def score_host(self, host: Any, facts: FactStore) -> int:
        """Score a host's value based on profile, open ports, and domain membership.

        Parameters
        ----------
        host : Host model instance (or any object with .id, .ip, .profile, .domain)
        facts : FactStore to query for port/service/credential facts

        Returns
        -------
        int : Value score (higher = more valuable target)
        """
        score = 0

        # Base score from profile classification.
        profile = getattr(host, "profile", TargetProfile.UNKNOWN)
        score += HOST_VALUE_SCORES.get(profile, 10)

        host_id = getattr(host, "id", str(host))
        open_ports = await self._get_open_ports(host_id, facts)

        # DC heuristic: if ports suggest DC but profile isn't set yet.
        if profile == TargetProfile.UNKNOWN:
            dc_match = {88, 389, 445} & open_ports
            if len(dc_match) >= 3:
                score += 90  # Almost certainly a DC.
                log.debug(
                    "Host %s has DC ports %s, boosting score by 90",
                    getattr(host, "ip", host_id), dc_match,
                )

        # Domain-joined hosts are higher value (potential lateral path).
        if getattr(host, "domain", None):
            score += 20

        # More open ports = more attack surface = higher enum priority.
        port_bonus = min(len(open_ports) * 3, 30)  # Cap at 30.
        score += port_bonus

        # Has database ports? Potential data exfil target.
        if open_ports & DB_PORTS:
            score += 15

        # Has file share ports? Potential sensitive docs.
        if open_ports & FILE_SHARE_PORTS:
            score += 10

        # Already have admin creds for this host? Massive priority for
        # post-exploitation.
        admin_creds = await facts.get_for_host("credential.admin", host_id)
        if admin_creds:
            score += 50
            log.debug(
                "Host %s has admin credentials, boosting score by 50",
                getattr(host, "ip", host_id),
            )

        # Already have valid (non-admin) creds? Still valuable.
        valid_creds = await facts.get_for_host("credential.valid", host_id)
        if valid_creds and not admin_creds:
            score += 25

        return score

    # ── Module Scoring ────────────────────────────────────────────────

    async def score_module(
        self,
        module: BaseModule,
        host_id: str | None,
        facts: FactStore,
    ) -> int:
        """Score the priority of running a specific module on a specific host.

        Parameters
        ----------
        module : The module to score.
        host_id : Target host (None for global modules).
        facts : FactStore for context.

        Returns
        -------
        int : Priority score (higher = run first).
        """
        score = 0

        # ── Chaining bonus: modules that unlock many downstream modules ──
        downstream_count = len(self._downstream_map.get(module.name, []))
        if downstream_count >= 3:
            score += 50
            log.debug(
                "Module %s chains into %d downstream modules (+50)",
                module.name, downstream_count,
            )
        elif downstream_count >= 1:
            score += downstream_count * 15

        # ── Credential production bonus ──
        produces_creds = any(
            ft in CREDENTIAL_FACT_TYPES or ft.startswith("credential.")
            for ft in module.produced_facts
        )
        if produces_creds:
            score += 100
        elif any(hint in module.name for hint in CREDENTIAL_MODULE_HINTS):
            score += 100

        # ── Lateral movement bonus ──
        produces_lateral = any(
            ft in LATERAL_FACT_TYPES for ft in module.produced_facts
        )
        if produces_lateral:
            score += 80
        elif any(hint in module.name for hint in LATERAL_MODULE_HINTS):
            score += 80

        # ── Host value bonus ──
        if host_id is not None:
            host_score = await self._get_host_score_by_id(host_id, facts)
            score += host_score

        # ── Success probability heuristic ──
        # If the facts needed for this module are richly populated (many
        # facts of each required type for this host), the module is more
        # likely to succeed.
        if host_id is not None:
            richness = await self._fact_richness(module, host_id, facts)
            if richness >= 3:
                score += 60  # High confidence — lots of input data.
            elif richness >= 2:
                score += 30

        # ── DC-specific chains ──
        # If targeting a DC and module is Kerberoast/DCSync, massive bonus.
        if host_id is not None:
            open_ports = await self._get_open_ports(host_id, facts)
            if {88, 389, 445}.issubset(open_ports):
                dc_modules = {"kerberoast", "dcsync", "ad_enum", "ldap"}
                if any(hint in module.name for hint in dc_modules):
                    score += 150
                    log.debug(
                        "Module %s targets DC host %s (+150)",
                        module.name, host_id,
                    )

        # ── Admin cred available → prioritize post-exploitation ──
        if host_id is not None:
            admin_creds = await facts.get_for_host("credential.admin", host_id)
            if admin_creds and module.name.startswith("post."):
                score += 120
                log.debug(
                    "Admin creds available for %s, prioritizing post-exploit %s (+120)",
                    host_id, module.name,
                )

        return score

    # ── Attack Path Scoring ───────────────────────────────────────────

    async def score_attack_path(
        self,
        path: Any,
        facts: FactStore,
    ) -> int:
        """Score the value of a discovered attack path.

        Parameters
        ----------
        path : AttackPath model instance.
        facts : FactStore for context.

        Returns
        -------
        int : Value score for this path.
        """
        score = 0
        technique = getattr(path, "technique_id", "")
        description = getattr(path, "description", "").lower()
        to_host_id = getattr(path, "to_host_id", "")

        # Path leads to Domain Admin.
        da_indicators = {"dcsync", "domain_admin", "golden_ticket", "T1003.006"}
        if any(ind in technique or ind in description for ind in da_indicators):
            score += AttackPathType.DOMAIN_ADMIN

        # Path harvests credentials.
        cred_indicators = {
            "credential", "hashdump", "mimikatz", "kerberoast", "secretsdump",
        }
        if any(ind in technique or ind in description for ind in cred_indicators):
            score += AttackPathType.CREDENTIAL_HARVEST

        # Path reaches a new network segment.
        if await self._is_new_segment(to_host_id, facts):
            score += AttackPathType.NEW_NETWORK_SEGMENT

        # Path leads to high-value host.
        host_score = await self._get_host_score_by_id(to_host_id, facts)
        score += host_score

        # Path accesses sensitive data.
        data_indicators = {"exfil", "database", "file_share", "sensitive"}
        if any(ind in technique or ind in description for ind in data_indicators):
            score += AttackPathType.SENSITIVE_DATA

        # Lateral movement.
        lateral_indicators = {"lateral", "pivot", "psexec", "wmi", "winrm"}
        if any(ind in technique or ind in description for ind in lateral_indicators):
            score += AttackPathType.LATERAL_MOVEMENT

        return score

    # ── Ranking / Recommendation ──────────────────────────────────────

    async def rank_modules(
        self,
        eligible_modules: list[tuple[BaseModule, str]],
        facts: FactStore,
    ) -> list[tuple[BaseModule, str, int]]:
        """Score and sort eligible modules by priority (descending).

        Parameters
        ----------
        eligible_modules : list of (module, eligibility_signature) tuples
                           from the planner's _eligible_modules().
        facts : FactStore for context.

        Returns
        -------
        list of (module, signature, score) tuples sorted by score descending.
        """
        scored: list[tuple[BaseModule, str, int]] = []
        for mod, sig in eligible_modules:
            # Extract host_id from signature if present (format: "name@host_id:...")
            host_id = self._extract_host_id(sig)
            module_score = await self.score_module(mod, host_id, facts)
            scored.append((mod, sig, module_score))

        scored.sort(key=lambda t: t[2], reverse=True)

        if scored:
            log.debug(
                "Module ranking: %s",
                ", ".join(f"{m.name}={s}" for m, _, s in scored[:10]),
            )

        return scored

    async def identify_crown_jewels(
        self,
        hosts: list[Any],
        facts: FactStore,
        top_n: int = 5,
    ) -> list[tuple[Any, int]]:
        """Find the highest-value targets in the discovered hosts.

        Parameters
        ----------
        hosts : list of Host model instances.
        facts : FactStore for context.
        top_n : Number of top targets to return.

        Returns
        -------
        list of (host, score) tuples sorted by score descending.
        """
        scored: list[tuple[Any, int]] = []
        for host in hosts:
            host_score = await self.score_host(host, facts)
            scored.append((host, host_score))

        scored.sort(key=lambda t: t[1], reverse=True)

        if scored:
            log.debug(
                "Crown jewels: %s",
                ", ".join(
                    f"{getattr(h, 'ip', '?')}={s}"
                    for h, s in scored[:top_n]
                ),
            )

        return scored[:top_n]

    async def suggest_next_targets(
        self,
        attack_graph: AttackGraph,
        facts: FactStore,
    ) -> list[tuple[str, int, str]]:
        """Recommend which hosts to pivot to next based on the attack graph.

        Analyzes the current attack graph to find hosts that are:
        1. Reachable from already-compromised hosts
        2. Not yet fully exploited
        3. High-value targets

        Parameters
        ----------
        attack_graph : Current attack graph.
        facts : FactStore for context.

        Returns
        -------
        list of (host_id, score, reason) tuples sorted by score descending.
        """
        suggestions: list[tuple[str, int, str]] = []
        all_paths = attack_graph.get_all()

        if not all_paths:
            return suggestions

        # Find all hosts we've reached.
        compromised_hosts: set[str] = set()
        reachable_hosts: set[str] = set()
        for path in all_paths:
            compromised_hosts.add(path.from_host_id)
            reachable_hosts.add(path.to_host_id)

        # Hosts we can reach but haven't fully exploited from.
        frontier = reachable_hosts - compromised_hosts

        # Also consider hosts adjacent to compromised hosts that we
        # haven't reached yet — these are "one hop away".
        all_known_hosts = await facts.get_values("host")
        all_known_ids = {
            getattr(h, "id", str(h)) for h in all_known_hosts
        }
        unexplored = all_known_ids - compromised_hosts - reachable_hosts

        # Score frontier hosts.
        for host_id in frontier:
            host_score = await self._get_host_score_by_id(host_id, facts)

            # Bonus for hosts with admin creds already available.
            admin_creds = await facts.get_for_host("credential.admin", host_id)
            if admin_creds:
                host_score += 200
                suggestions.append((host_id, host_score, "admin creds available"))
            else:
                suggestions.append((host_id, host_score, "reachable, not exploited"))

        # Score unexplored hosts (lower base priority since no path exists yet).
        for host_id in unexplored:
            host_score = await self._get_host_score_by_id(host_id, facts)

            # Check if it's in a new subnet.
            if await self._is_new_segment(host_id, facts):
                host_score += 100
                suggestions.append((host_id, host_score, "new network segment"))
            else:
                suggestions.append((host_id, host_score, "unexplored"))

        suggestions.sort(key=lambda t: t[1], reverse=True)

        if suggestions:
            log.debug(
                "Next target suggestions: %s",
                ", ".join(f"{hid}={s} ({r})" for hid, s, r in suggestions[:5]),
            )

        return suggestions

    # ── Vulnerability De-prioritization ───────────────────────────────

    async def apply_widespread_penalty(
        self,
        scored_modules: list[tuple[BaseModule, str, int]],
        facts: FactStore,
        threshold: int = 3,
    ) -> list[tuple[BaseModule, str, int]]:
        """Reduce priority of modules targeting widespread vulnerabilities.

        If the same vulnerability appears on 3+ hosts, individual exploitation
        of each host is less urgent — the vuln is already proven widespread.
        Focus effort on unique or high-value instances instead.

        Parameters
        ----------
        scored_modules : Output from rank_modules().
        facts : FactStore for context.
        threshold : Number of hosts with same vuln before penalty applies.

        Returns
        -------
        Adjusted list with penalties applied, re-sorted.
        """
        # Count how many hosts each vuln type appears on.
        vuln_host_count: Counter[str] = Counter()

        # Also check sub-types like vuln.ms17_010, vuln.cve_xxxx, etc.
        all_types = await facts.all_fact_types()
        vuln_types = [ft for ft in all_types if ft.startswith("vuln.")]

        for vt in vuln_types:
            host_ids: set[str] = set()
            all_vuln_facts = await facts.get_all(vt)
            for fact in all_vuln_facts:
                if fact.host_id:
                    host_ids.add(fact.host_id)
            if len(host_ids) >= threshold:
                vuln_host_count[vt] = len(host_ids)

        if not vuln_host_count:
            return scored_modules

        # Apply penalty to modules that target widespread vulns.
        adjusted: list[tuple[BaseModule, str, int]] = []
        for mod, sig, score in scored_modules:
            penalty = 0
            for req_ft in mod.required_facts:
                if req_ft in vuln_host_count:
                    count = vuln_host_count[req_ft]
                    penalty = max(penalty, min(count * 10, 50))

            if penalty > 0:
                log.debug(
                    "Module %s penalized by %d (widespread vuln)",
                    mod.name, penalty,
                )
            adjusted.append((mod, sig, score - penalty))

        adjusted.sort(key=lambda t: t[2], reverse=True)
        return adjusted

    # ── Private Helpers ───────────────────────────────────────────────

    async def _get_open_ports(self, host_id: str, facts: FactStore) -> set[int]:
        """Get open port numbers for a host."""
        ports = await facts.get_for_host("port.open", host_id)
        return {p.port for p in ports if hasattr(p, "port")}

    async def _get_host_score_by_id(
        self, host_id: str, facts: FactStore,
    ) -> int:
        """Look up a host by ID and return its value score."""
        all_hosts = await facts.get_values("host")
        for host in all_hosts:
            hid = getattr(host, "id", str(host))
            if hid == host_id:
                return await self.score_host(host, facts)

        # Host not found in store — return minimal score.
        return 10

    async def _fact_richness(
        self,
        module: BaseModule,
        host_id: str,
        facts: FactStore,
    ) -> int:
        """How many distinct required fact values exist for this host.

        A higher count means more input data is available, increasing
        the module's likely success.
        """
        total = 0
        for ft in module.required_facts:
            host_facts = await facts.get_for_host(ft, host_id)
            total += len(host_facts)
        return total

    async def _is_new_segment(self, host_id: str, facts: FactStore) -> bool:
        """Check if a host is in a different subnet from compromised hosts.

        Heuristic: extract /24 from IPs. If this host's /24 doesn't appear
        in any previously-known hosts, it's a new segment.
        """
        # Find this host's IP.
        target_ip: str | None = None
        all_hosts = await facts.get_values("host")
        known_subnets: set[str] = set()

        for host in all_hosts:
            hip = getattr(host, "ip", None)
            if hip is None:
                continue
            hid = getattr(host, "id", str(host))

            try:
                network = str(
                    ipaddress.ip_network(f"{hip}/24", strict=False)
                )
            except ValueError:
                continue

            if hid == host_id:
                target_ip = hip
            else:
                known_subnets.add(network)

        if target_ip is None:
            return False

        try:
            target_subnet = str(
                ipaddress.ip_network(f"{target_ip}/24", strict=False)
            )
        except ValueError:
            return False

        return target_subnet not in known_subnets

    @staticmethod
    def _extract_host_id(signature: str) -> str | None:
        """Extract host_id from an eligibility signature.

        Signatures have the format ``module_name@host_id:fact=count,...``
        or just ``module_name`` for global modules.
        """
        if "@" not in signature:
            return None
        # Split on @ and take everything after it, up to ':'
        after_at = signature.split("@", 1)[1]
        if ":" in after_at:
            return after_at.split(":", 1)[0]
        return after_at
