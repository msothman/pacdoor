"""Exploit safety policy enforcement."""

from __future__ import annotations

from pacdoor.core.models import ExploitSafety

_ORDER = list(ExploitSafety)


class SafetyPolicy:
    """Enforces a maximum safety level for exploit modules."""

    def __init__(self, max_safety: str = "moderate") -> None:
        self.max_safety = ExploitSafety(max_safety)

    def is_allowed(self, module_safety: ExploitSafety) -> bool:
        return _ORDER.index(module_safety) <= _ORDER.index(self.max_safety)
