"""Directed graph tracking attack paths through the network."""

from __future__ import annotations

from pacdoor.core.models import AttackPath


class AttackGraph:
    """Tracks lateral movement and exploit chains as a directed graph."""

    def __init__(self) -> None:
        self._paths: list[AttackPath] = []
        self._step_counter = 0

    def add_step(
        self,
        from_host_id: str,
        to_host_id: str,
        technique_id: str,
        description: str,
        credential_id: str | None = None,
    ) -> AttackPath:
        self._step_counter += 1
        path = AttackPath(
            from_host_id=from_host_id,
            to_host_id=to_host_id,
            technique_id=technique_id,
            credential_id=credential_id,
            description=description,
            step_order=self._step_counter,
        )
        self._paths.append(path)
        return path

    def get_all(self) -> list[AttackPath]:
        return list(self._paths)

    def get_paths_from(self, host_id: str) -> list[AttackPath]:
        return [p for p in self._paths if p.from_host_id == host_id]

    def get_paths_to(self, host_id: str) -> list[AttackPath]:
        return [p for p in self._paths if p.to_host_id == host_id]

    def unique_techniques(self) -> set[str]:
        return {p.technique_id for p in self._paths}
