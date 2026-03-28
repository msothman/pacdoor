"""Token bucket rate limiter for controlling request rates."""

from __future__ import annotations

import asyncio


class TokenBucketRateLimiter:
    """Async token-bucket rate limiter.

    Modules call `await rate_limiter.acquire()` before each network request.

    Uses an ``asyncio.Condition`` so that waiters sleep efficiently until the
    background refill task adds tokens and notifies them, instead of polling.
    """

    def __init__(self, rate: int) -> None:
        self.rate = rate
        self.tokens = float(rate)
        self.max_tokens = float(rate)
        self._cond = asyncio.Condition()
        self._refill_task: asyncio.Task[None] | None = None

    # ── Internal: background refill ──────────────────────────────────────

    def _ensure_refill_running(self) -> None:
        """Lazily start the background refill task on the running loop."""
        if self._refill_task is None or self._refill_task.done():
            self._refill_task = asyncio.get_running_loop().create_task(
                self._refill_loop()
            )

    async def _refill_loop(self) -> None:
        """Periodically add a token and wake up any waiting acquirers."""
        interval = 1.0 / max(self.rate, 1)
        try:
            while True:
                await asyncio.sleep(interval)
                async with self._cond:
                    self.tokens = min(self.max_tokens, self.tokens + 1.0)
                    self._cond.notify(1)
        except asyncio.CancelledError:
            return

    # ── Public API ───────────────────────────────────────────────────────

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one."""
        self._ensure_refill_running()
        async with self._cond:
            # Wait until at least one token is available.
            while self.tokens < 1.0:
                await self._cond.wait()
            self.tokens -= 1.0
