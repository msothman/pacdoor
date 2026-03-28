"""Simple async event bus for TUI updates and inter-component communication."""

from __future__ import annotations

import asyncio
import enum
import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)


class Event(str, enum.Enum):
    MODULE_STARTED = "module_started"
    MODULE_COMPLETED = "module_completed"
    HOST_DISCOVERED = "host_discovered"
    PORT_DISCOVERED = "port_discovered"
    FINDING_DISCOVERED = "finding_discovered"
    CREDENTIAL_FOUND = "credential_found"
    LATERAL_HOP = "lateral_hop"
    PHASE_CHANGED = "phase_changed"
    HOST_PIPELINE_STARTED = "host_pipeline_started"
    HOST_PIPELINE_COMPLETED = "host_pipeline_completed"
    HOST_PHASE_CHANGED = "host_phase_changed"
    PROFILE_DETECTED = "profile_detected"
    SCAN_COMPLETE = "scan_complete"
    UPDATE_STARTED = "update_started"
    UPDATE_COMPLETE = "update_complete"


class EventBus:
    def __init__(self) -> None:
        self._listeners: dict[Event, list[Callable]] = defaultdict(list)

    def on(self, event: Event, callback: Callable) -> None:
        self._listeners[event].append(callback)

    def emit(self, event: Event, data: dict[str, Any] | None = None) -> None:
        for cb in self._listeners.get(event, []):
            try:
                result = cb(data or {})
                # Support async callbacks: schedule them on the running loop
                if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                    try:
                        loop = asyncio.get_running_loop()
                        task = loop.create_task(result)
                        task.add_done_callback(self._on_task_done)
                    except RuntimeError:
                        log.warning(
                            "Async callback for %s dropped: no running event loop",
                            event.value,
                        )
            except Exception:
                log.exception(
                    "EventBus callback failed for event %s (callback: %s)",
                    event.value,
                    getattr(cb, "__qualname__", repr(cb)),
                )

    @staticmethod
    def _on_task_done(task: asyncio.Task) -> None:
        """Log unhandled exceptions from async event callbacks."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            log.error("EventBus async callback failed: %s", exc, exc_info=exc)
