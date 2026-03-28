"""HTTP/TCP connection pool manager for reuse across modules.

Provides cached ``aiohttp.ClientSession`` instances keyed by
(host, port, ssl) so that multiple modules scanning the same target
share connections instead of hammering it with fresh handshakes.
"""

from __future__ import annotations

import asyncio
import logging
import ssl as _ssl
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import aiohttp

log = logging.getLogger(__name__)


class ConnectionPool:
    """Shared HTTP/TCP connection pool for the engine.

    Parameters
    ----------
    max_per_host:
        Maximum simultaneous connections to a single (host, port, ssl) target.
    total_limit:
        Hard ceiling on total open connections across all hosts.
    connect_timeout:
        Seconds to wait for a TCP connect to succeed.
    request_timeout:
        Default whole-request timeout (connect + send + read).
    """

    def __init__(
        self,
        max_per_host: int = 10,
        total_limit: int = 200,
        connect_timeout: float = 5.0,
        request_timeout: float = 30.0,
    ) -> None:
        self.max_per_host = max_per_host
        self.total_limit = total_limit
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout

        # (host, port, ssl) -> ClientSession
        self._sessions: dict[tuple[str, int, bool], aiohttp.ClientSession] = {}
        self._session_lock = asyncio.Lock()

        # Shared connectors (one for SSL, one for non-SSL) so total_limit
        # is truly global instead of per-session.  Lazily created on first
        # use under ``_session_lock``.
        self._connector_ssl: aiohttp.TCPConnector | None = None
        self._connector_plain: aiohttp.TCPConnector | None = None
        self._ssl_ctx: _ssl.SSLContext | None = None

        # Per-host request statistics
        self._stats: dict[str, _HostStats] = defaultdict(_HostStats)

    # ------------------------------------------------------------------
    # HTTP session management
    # ------------------------------------------------------------------

    def _get_connector(self, ssl: bool) -> aiohttp.TCPConnector:
        """Return the shared ``TCPConnector`` for the given SSL mode.

        Must be called under ``_session_lock``.  Lazily creates the
        connector (and, for SSL, a permissive SSL context) on first use.
        """
        if ssl:
            if self._connector_ssl is None or self._connector_ssl.closed:
                if self._ssl_ctx is None:
                    self._ssl_ctx = _ssl.create_default_context()
                    self._ssl_ctx.check_hostname = False
                    self._ssl_ctx.verify_mode = _ssl.CERT_NONE
                self._connector_ssl = aiohttp.TCPConnector(
                    limit=self.total_limit,
                    limit_per_host=self.max_per_host,
                    ssl=self._ssl_ctx,
                    enable_cleanup_closed=True,
                )
            return self._connector_ssl

        if self._connector_plain is None or self._connector_plain.closed:
            self._connector_plain = aiohttp.TCPConnector(
                limit=self.total_limit,
                limit_per_host=self.max_per_host,
                ssl=False,
                enable_cleanup_closed=True,
            )
        return self._connector_plain

    async def get_http_session(
        self,
        host: str,
        port: int = 80,
        ssl: bool = False,
    ) -> aiohttp.ClientSession:
        """Return a cached ``aiohttp.ClientSession`` for *host:port*.

        All SSL sessions share one ``TCPConnector`` and all non-SSL
        sessions share another, so ``total_limit`` acts as a true global
        cap on outbound connections.

        Sessions are lazily created on first access and reused for every
        subsequent call with the same (host, port, ssl) key.
        SSL certificate verification is **disabled** — standard practice
        for pentesting internal/self-signed targets.
        """
        key = (host, port, ssl)

        # Fast path: check without lock (session already exists and open)
        session = self._sessions.get(key)
        if session is not None and not session.closed:
            return session

        # Slow path: acquire lock to avoid creating duplicate sessions
        async with self._session_lock:
            # Re-check under lock in case another coroutine created it
            session = self._sessions.get(key)
            if session is not None and not session.closed:
                return session

            connector = self._get_connector(ssl)

            timeout = aiohttp.ClientTimeout(
                total=self.request_timeout,
                connect=self.connect_timeout,
            )

            session = aiohttp.ClientSession(
                connector=connector,
                connector_owner=False,  # pool owns the connector
                timeout=timeout,
            )
            self._sessions[key] = session
            log.debug("Created HTTP session for %s:%d (ssl=%s)", host, port, ssl)
            return session

    # ------------------------------------------------------------------
    # TCP connection management
    # ------------------------------------------------------------------

    async def get_tcp_connection(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a raw TCP connection with uniform timeout handling.

        No pooling is done here — TCP connections are protocol-dependent,
        so callers own the returned reader/writer and must close them.

        Raises
        ------
        ConnectionError
            On connect failure or timeout.
        """
        effective_timeout = timeout if timeout is not None else self.connect_timeout
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=effective_timeout,
            )
            log.debug("TCP connected to %s:%d", host, port)
            return reader, writer
        except TimeoutError as exc:
            raise ConnectionError(
                f"TCP connect to {host}:{port} timed out after {effective_timeout}s"
            ) from exc
        except OSError as exc:
            raise ConnectionError(
                f"TCP connect to {host}:{port} failed: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # HTTP request with retry
    # ------------------------------------------------------------------

    _TRANSIENT_STATUS_CODES = frozenset({429, 503})

    async def http_request(
        self,
        method: str,
        url: str,
        *,
        retries: int = 3,
        backoff: float = 1.0,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Send an HTTP request with automatic retries and exponential backoff.

        The target session is resolved from *url* automatically.  Transient
        errors (``ConnectionError``, ``TimeoutError``, HTTP 429/503) trigger
        a retry with exponential back-off.  On final failure the last
        exception is re-raised.

        Returns
        -------
        aiohttp.ClientResponse
            The **un-read** response object.  Caller is responsible for
            reading / closing it (or using ``async with``).
        """
        parsed = urlparse(url)
        is_ssl = parsed.scheme == "https"
        port = parsed.port or (443 if is_ssl else 80)
        host = parsed.hostname or parsed.netloc

        session = await self.get_http_session(host, port, ssl=is_ssl)
        host_stats = self._stats[host]

        last_exc: BaseException | None = None
        for attempt in range(1, retries + 1):
            host_stats.total += 1
            try:
                resp = await session.request(method, url, **kwargs)
                if resp.status in self._TRANSIENT_STATUS_CODES and attempt < retries:
                    host_stats.retried += 1
                    delay = backoff * (2 ** (attempt - 1))
                    log.debug(
                        "%s %s returned %d — retrying in %.1fs (attempt %d/%d)",
                        method, url, resp.status, delay, attempt, retries,
                    )
                    resp.release()
                    await asyncio.sleep(delay)
                    continue
                host_stats.successful += 1
                return resp
            except (TimeoutError, ConnectionError, aiohttp.ClientError) as exc:
                last_exc = exc
                host_stats.retried += 1
                if attempt < retries:
                    delay = backoff * (2 ** (attempt - 1))
                    log.debug(
                        "%s %s failed (%s) — retrying in %.1fs (attempt %d/%d)",
                        method, url, exc, delay, attempt, retries,
                    )
                    await asyncio.sleep(delay)
                else:
                    host_stats.failed += 1

        # All retries exhausted
        assert last_exc is not None  # noqa: S101
        raise last_exc

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close every cached HTTP session and the shared connectors."""
        for key, session in self._sessions.items():
            if not session.closed:
                await session.close()
                log.debug("Closed HTTP session for %s:%d (ssl=%s)", *key)
        self._sessions.clear()

        # Close the shared connectors (sessions used connector_owner=False)
        for connector in (self._connector_ssl, self._connector_plain):
            if connector is not None and not connector.closed:
                await connector.close()
        self._connector_ssl = None
        self._connector_plain = None

    async def __aenter__(self) -> ConnectionPool:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Return per-host and aggregate request statistics.

        Example return value::

            {
                "hosts": {
                    "10.0.0.1": {"total": 42, "successful": 40, "failed": 1, "retried": 3},
                },
                "totals": {"total": 42, "successful": 40, "failed": 1, "retried": 3},
                "active_sessions": 2,
            }
        """
        hosts: dict[str, dict[str, int]] = {}
        agg_total = agg_ok = agg_fail = agg_retry = 0
        for host, hs in self._stats.items():
            hosts[host] = {
                "total": hs.total,
                "successful": hs.successful,
                "failed": hs.failed,
                "retried": hs.retried,
            }
            agg_total += hs.total
            agg_ok += hs.successful
            agg_fail += hs.failed
            agg_retry += hs.retried

        return {
            "hosts": hosts,
            "totals": {
                "total": agg_total,
                "successful": agg_ok,
                "failed": agg_fail,
                "retried": agg_retry,
            },
            "active_sessions": sum(
                1 for s in self._sessions.values() if not s.closed
            ),
        }


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

class _HostStats:
    """Mutable counters for a single host."""

    __slots__ = ("total", "successful", "failed", "retried")

    def __init__(self) -> None:
        self.total: int = 0
        self.successful: int = 0
        self.failed: int = 0
        self.retried: int = 0
