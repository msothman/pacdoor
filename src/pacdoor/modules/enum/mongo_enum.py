"""MongoDB enumeration — auth check, databases, server info."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import (
    Evidence,
    Finding,
    Phase,
    Severity,
)
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Lazy-imported at first use so the module can still be loaded (and
# gracefully skipped) when pymongo is not installed.
_pymongo_available: bool | None = None
_MongoClient: type | None = None
_ServerSelectionTimeoutError: type | None = None


def _ensure_pymongo() -> bool:
    """Try to import pymongo; cache the result."""
    global _pymongo_available, _MongoClient, _ServerSelectionTimeoutError  # noqa: PLW0603
    if _pymongo_available is not None:
        return _pymongo_available
    try:
        from pymongo import MongoClient as _Client  # type: ignore[import-untyped]
        from pymongo.errors import (
            ServerSelectionTimeoutError as _SSTimeout,  # type: ignore[import-untyped]
        )

        _MongoClient = _Client
        _ServerSelectionTimeoutError = _SSTimeout
        _pymongo_available = True
    except ImportError:
        log.warning("pymongo not installed — mongo_enum module will be skipped")
        _pymongo_available = False
    return _pymongo_available


# ── Helpers (all synchronous — run via asyncio.to_thread) ────────────


def _connect_noauth(
    ip: str, port: int = 27017, timeout_ms: int = 10000
) -> object | None:
    """Attempt to connect to MongoDB without authentication.

    Returns a MongoClient on success or None.
    """
    if _MongoClient is None:
        return None
    try:
        client = _MongoClient(
            ip,
            port,
            serverSelectionTimeoutMS=timeout_ms,
            connectTimeoutMS=timeout_ms,
            socketTimeoutMS=timeout_ms,
            directConnection=True,
        )
        # Force a connection attempt — list_database_names() triggers auth check
        client.admin.command("ping")
        return client
    except Exception:
        return None


def _connect_auth(
    ip: str,
    port: int,
    username: str,
    password: str,
    timeout_ms: int = 10000,
) -> object | None:
    """Attempt to connect to MongoDB with credentials."""
    if _MongoClient is None:
        return None
    try:
        client = _MongoClient(
            ip,
            port,
            username=username,
            password=password,
            serverSelectionTimeoutMS=timeout_ms,
            connectTimeoutMS=timeout_ms,
            socketTimeoutMS=timeout_ms,
            directConnection=True,
        )
        client.admin.command("ping")
        return client
    except Exception:
        return None


def _list_databases(client: object) -> list[dict[str, Any]]:
    """List all databases with size info."""
    databases: list[dict[str, Any]] = []
    try:
        db_list = client.list_databases()  # type: ignore[union-attr]
        for db_info in db_list:
            name = db_info.get("name", "")
            size = db_info.get("sizeOnDisk", 0)
            databases.append({"name": name, "sizeOnDisk": size})
    except Exception:
        pass
    return databases


def _count_collections(client: object, db_name: str) -> list[dict[str, Any]]:
    """List collections in a database with document counts."""
    collections: list[dict[str, Any]] = []
    try:
        db = client[db_name]  # type: ignore[index]
        for coll_name in db.list_collection_names():
            try:
                count = db[coll_name].estimated_document_count()
            except Exception:
                count = -1
            collections.append({"name": coll_name, "documents": count})
    except Exception:
        pass
    return collections


def _get_server_status(client: object) -> dict[str, Any]:
    """Retrieve serverStatus for version and process info."""
    try:
        status = client.admin.command("serverStatus")  # type: ignore[union-attr]
        return {
            "version": status.get("version", "unknown"),
            "process": status.get("process", "unknown"),
            "uptime": status.get("uptime", 0),
            "connections_current": status.get("connections", {}).get("current", 0),
            "connections_available": status.get("connections", {}).get("available", 0),
        }
    except Exception:
        return {}


def _get_replicaset_info(client: object) -> dict[str, Any] | None:
    """Run isMaster to get replica set info."""
    try:
        result = client.admin.command("isMaster")  # type: ignore[union-attr]
        rs_name = result.get("setName")
        if rs_name is None:
            return None
        return {
            "setName": rs_name,
            "ismaster": result.get("ismaster", False),
            "secondary": result.get("secondary", False),
            "hosts": result.get("hosts", []),
            "primary": result.get("primary", ""),
        }
    except Exception:
        return None


def _disconnect(client: object) -> None:
    """Safely close the MongoDB client."""
    with contextlib.suppress(Exception):
        client.close()  # type: ignore[union-attr]


# ── Module ───────────────────────────────────────────────────────────


class MongoEnumModule(BaseModule):
    name = "enum.mongo_enum"
    description = "MongoDB enumeration — auth check, databases, server info"
    phase = Phase.ENUMERATION
    attack_technique_ids = ["T1046"]
    required_facts = ["service.mongodb"]
    produced_facts = ["mongo.noauth", "mongo.databases"]

    async def check(self, ctx: ModuleContext) -> bool:
        if not _ensure_pymongo():
            return False
        return await super().check(ctx)

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        if not _ensure_pymongo():
            return []

        findings: list[Finding] = []

        mongo_services = await ctx.facts.get_all("service.mongodb")
        seen_hosts: set[str] = set()
        targets: list[tuple[str, str, int]] = []

        for fact in mongo_services:
            host_id = fact.host_id
            if host_id is None or host_id in seen_hosts:
                continue
            seen_hosts.add(host_id)
            ip = await self.resolve_ip(ctx, host_id)
            if ip is None:
                continue
            port_num = fact.value.port if hasattr(fact.value, "port") else 27017
            targets.append((host_id, ip, port_num))

        for host_id, ip, port_num in targets:
            await self._enumerate_host(ctx, findings, host_id, ip, port_num)

        return findings

    async def _enumerate_host(
        self,
        ctx: ModuleContext,
        findings: list[Finding],
        host_id: str,
        ip: str,
        port: int,
    ) -> None:
        """Run full MongoDB enumeration on a single host."""

        # ── 1. Try unauthenticated connection ────────────────────
        client = await asyncio.to_thread(_connect_noauth, ip, port)
        noauth = client is not None

        if noauth:
            await ctx.facts.add(
                "mongo.noauth",
                {"host": ip, "port": port},
                self.name,
                host_id=host_id,
            )
            findings.append(Finding(
                title=f"MongoDB requires no authentication on {ip}",
                description=(
                    f"MongoDB on {ip}:{port} is accessible without "
                    "authentication. Any network-reachable client can read, "
                    "modify, or delete all data. This is a common cause of "
                    "large-scale data breaches."
                ),
                severity=Severity.CRITICAL,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mongo_noauth",
                    data=f"Unauthenticated connection succeeded on {ip}:{port}",
                )],
                remediation=(
                    "Enable authentication: set security.authorization to "
                    "'enabled' in mongod.conf and create administrative users. "
                    "Bind to localhost or use firewall rules to restrict access."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                    "https://www.mongodb.com/docs/manual/administration/security-checklist/",
                ],
            ))
        else:
            # Auth required — try with provided creds
            creds = ctx.user_creds
            if creds.username is not None and creds.password is not None:
                client = await asyncio.to_thread(
                    _connect_auth, ip, port, creds.username, creds.password
                )
            if client is None:
                log.debug(
                    "mongo_enum: could not connect to %s:%d (auth required, no valid creds)",
                    ip, port,
                )
                return

        # ── 2. Server status / version ───────────────────────────
        status = await asyncio.to_thread(_get_server_status, client)
        version = status.get("version", "unknown")

        if status:
            findings.append(Finding(
                title=f"MongoDB server info disclosed on {ip}",
                description=(
                    f"MongoDB {version} on {ip}:{port}. "
                    f"Process: {status.get('process', 'unknown')}, "
                    f"uptime: {status.get('uptime', 0)}s, "
                    f"connections: {status.get('connections_current', '?')}"
                    f"/{status.get('connections_available', '?')}."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mongo_version",
                    data=(
                        f"MongoDB serverStatus on {ip}:{port}:\n"
                        + "\n".join(f"  {k}: {v}" for k, v in status.items())
                    ),
                )],
                remediation=(
                    "Keep MongoDB updated to the latest stable release. "
                    "Restrict network access with --bind_ip and firewall rules."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 3. Enumerate databases and collections ───────────────
        databases = await asyncio.to_thread(_list_databases, client)
        if databases:
            await ctx.facts.add(
                "mongo.databases",
                {"host": ip, "port": port, "databases": databases},
                self.name,
                host_id=host_id,
            )

            # Enumerate collections per database (limit to avoid excessive queries)
            db_details: list[str] = []
            for db_info in databases[:20]:  # Cap at 20 databases
                db_name = db_info["name"]
                size_mb = db_info.get("sizeOnDisk", 0) / (1024 * 1024)
                collections = await asyncio.to_thread(
                    _count_collections, client, db_name
                )
                coll_summary = ", ".join(
                    f"{c['name']}({c['documents']})"
                    for c in collections[:10]  # Cap at 10 collections per db
                )
                if len(collections) > 10:
                    coll_summary += f", ... +{len(collections) - 10} more"
                db_details.append(
                    f"  {db_name} ({size_mb:.1f} MB): [{coll_summary}]"
                )

            severity = Severity.HIGH if noauth else Severity.INFO
            findings.append(Finding(
                title=f"MongoDB databases accessible on {ip}",
                description=(
                    f"Enumerated {len(databases)} database(s) on {ip}:{port}. "
                    + (
                        "Access is unauthenticated — all data is exposed."
                        if noauth
                        else f"Authenticated as '{ctx.user_creds.username}'."
                    )
                ),
                severity=severity,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mongo_databases",
                    data=(
                        f"Databases on {ip}:{port}:\n"
                        + "\n".join(db_details)
                    ),
                )],
                remediation=(
                    "Enable authentication and apply least-privilege roles. "
                    "Remove unnecessary databases and restrict collection access."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        # ── 4. Replica set info ──────────────────────────────────
        rs_info = await asyncio.to_thread(_get_replicaset_info, client)
        if rs_info:
            hosts_str = ", ".join(rs_info.get("hosts", []))
            findings.append(Finding(
                title=f"MongoDB replica set discovered on {ip}",
                description=(
                    f"MongoDB on {ip}:{port} is part of replica set "
                    f"'{rs_info['setName']}' with primary "
                    f"'{rs_info.get('primary', 'unknown')}'. "
                    f"Members: {hosts_str}. This reveals additional targets "
                    "for lateral movement."
                ),
                severity=Severity.INFO,
                host_id=host_id,
                module_name=self.name,
                attack_technique_ids=["T1046"],
                evidence=[Evidence(
                    kind="mongo_replicaset",
                    data=(
                        f"Replica set on {ip}:{port}:\n"
                        + "\n".join(f"  {k}: {v}" for k, v in rs_info.items())
                    ),
                )],
                remediation=(
                    "Ensure all replica set members require authentication. "
                    "Use internal authentication (keyFile or x.509) between members."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1046/",
                ],
            ))

        await asyncio.to_thread(_disconnect, client)
