"""Self-updating system -- pulls latest CVEs, templates, creds from public feeds.

Feeds:
  1. NVD CVE API v2.0         -> data/cve_map.json
  2. Nuclei community YAML    -> templates/vulns/community/
  3. MITRE ATT&CK STIX bundle -> data/attack_techniques.json
  4. SecLists default creds    -> data/default_creds.json (merged)

Each feed is independently cached with a last-updated timestamp in
``data/.update_cache.json``.  Feeds only re-fetch when the cache age
exceeds ``UPDATE_INTERVAL_HOURS`` (default 24).
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "vulns"
COMMUNITY_DIR = TEMPLATES_DIR / "community"
CACHE_FILE = DATA_DIR / ".update_cache.json"

# How often each feed is refreshed (hours).
UPDATE_INTERVAL_HOURS = 24

# Limit how many community templates we download per update cycle.
MAX_COMMUNITY_TEMPLATES_PER_UPDATE = 50

# HTTP request timeout (seconds).
HTTP_TIMEOUT = 10

# ── NVD API v2.0 ─────────────────────────────────────────────────────────

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Nuclei community templates (GitHub) ──────────────────────────────────

_NUCLEI_TREE_URL = (
    "https://api.github.com/repos/projectdiscovery/nuclei-templates"
    "/git/trees/main?recursive=1"
)
_NUCLEI_RAW_BASE = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
)

# Only download templates under these directory prefixes.
_NUCLEI_PATH_PREFIXES = (
    "http/cves/",
    "http/misconfiguration/",
    "http/default-logins/",
    # Legacy layout (pre-2024 nuclei-templates)
    "cves/",
    "misconfiguration/",
    "default-logins/",
)

# High-value directories for bulk download (--download-templates).
_NUCLEI_BULK_PREFIXES = (
    "http/cves/",
    "http/misconfiguration/",
    "http/default-logins/",
    "http/vulnerabilities/",
    "network/",
    # Legacy layout
    "cves/",
    "misconfiguration/",
    "default-logins/",
    "vulnerabilities/",
)

# Tracking file for bulk-downloaded templates.
_BULK_MANIFEST_FILE = COMMUNITY_DIR / ".bulk_manifest.json"

# Concurrent download workers for bulk mode.
_BULK_CONCURRENCY = 20

# ── MITRE ATT&CK ─────────────────────────────────────────────────────────

_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master"
    "/enterprise-attack/enterprise-attack.json"
)

# ── SecLists default credentials ─────────────────────────────────────────

_SECLISTS_RAW_BASE = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Passwords/Default-Credentials"
)
_SECLISTS_FILES: dict[str, str] = {
    "ftp": "ftp-betterdefaultpasslist.txt",
    "mssql": "mssql-betterdefaultpasslist.txt",
    "mysql": "mysql-betterdefaultpasslist.txt",
    "postgres": "postgres-betterdefaultpasslist.txt",
    "tomcat": "tomcat-betterdefaultpasslist.txt",
    "vnc": "vnc-betterdefaultpasslist.txt",
}


# ── Helpers ───────────────────────────────────────────────────────────────


def _load_cache() -> dict[str, Any]:
    """Load the update-cache JSON, returning an empty dict on any error."""
    try:
        if CACHE_FILE.exists():
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_cache(cache: dict[str, Any]) -> None:
    """Persist the update-cache JSON atomically."""
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    tmp.replace(CACHE_FILE)


def _feed_stale(cache: dict[str, Any], feed_key: str) -> bool:
    """Return True if *feed_key* has never been fetched or is older than the interval."""
    ts = cache.get(feed_key, {}).get("last_updated")
    if ts is None:
        return True
    age_hours = (time.time() - ts) / 3600
    return age_hours >= UPDATE_INTERVAL_HOURS


def _mark_updated(cache: dict[str, Any], feed_key: str) -> None:
    cache.setdefault(feed_key, {})["last_updated"] = time.time()


def _iso_utc(dt: datetime) -> str:
    """Format *dt* as ISO-8601 string acceptable to the NVD API."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


# ── Main class ────────────────────────────────────────────────────────────


class UpdateManager:
    """Orchestrates all update checks on startup."""

    def __init__(self, *, offline: bool = False) -> None:
        self.data_dir = DATA_DIR
        self.data_dir.mkdir(parents=True, exist_ok=True)
        COMMUNITY_DIR.mkdir(parents=True, exist_ok=True)
        self.offline = offline

    # ── Public entry point ────────────────────────────────────────────────

    async def check_all(self) -> dict[str, bool]:
        """Run every feed updater.  Returns ``{feed_name: success}``."""
        if self.offline:
            log.info("Offline mode — skipping all updates")
            return {}

        log.info("Checking for updates ...")
        cache = _load_cache()

        results: dict[str, bool] = {}
        feeds: list[tuple[str, Any]] = [
            ("cve_feed", self._update_cve_feed),
            ("nuclei_templates", self._update_nuclei_templates),
            ("attack_data", self._update_attack_data),
            ("default_creds", self._update_default_creds),
        ]
        for name, coro_fn in feeds:
            try:
                if _feed_stale(cache, name):
                    await coro_fn(cache)
                    _mark_updated(cache, name)
                    _save_cache(cache)
                    results[name] = True
                    log.info("Feed '%s' updated successfully", name)
                else:
                    log.info("Feed '%s' is fresh — skipped", name)
                    results[name] = True
            except Exception as exc:
                log.info("Feed '%s' update failed: %s", name, exc)
                results[name] = False

        return results

    # ── Bulk Nuclei template download ─────────────────────────────────────

    async def bulk_download_nuclei_templates(
        self,
        *,
        progress_callback: Any | None = None,
    ) -> dict[str, int]:
        """Download ALL Nuclei community templates from high-value directories.

        Targets the following directories from the nuclei-templates repo:
          - http/cves/          (CVE detection templates)
          - http/misconfiguration/  (misconfig templates)
          - http/default-logins/    (default credential templates)
          - http/vulnerabilities/   (vulnerability templates)
          - network/                (network protocol templates)

        Uses a manifest file to track which templates have already been
        downloaded, so subsequent runs only fetch new/changed files.

        Args:
            progress_callback: optional ``callable(downloaded, total, path)``
                invoked after each file download for progress reporting.

        Returns:
            ``{"total_available": N, "already_present": N, "downloaded": N,
              "failed": N}``
        """
        import asyncio

        import aiohttp

        stats = {
            "total_available": 0,
            "already_present": 0,
            "downloaded": 0,
            "failed": 0,
        }

        # Load the manifest of previously downloaded files.
        manifest: dict[str, str] = {}  # path -> sha
        if _BULK_MANIFEST_FILE.exists():
            try:
                manifest = json.loads(
                    _BULK_MANIFEST_FILE.read_text(encoding="utf-8"),
                )
            except Exception:
                manifest = {}

        # 1. Fetch the recursive tree listing from GitHub.
        timeout = aiohttp.ClientTimeout(total=60)
        headers = {"Accept": "application/vnd.github.v3+json"}

        log.info("Fetching Nuclei template tree from GitHub ...")
        print("Fetching template index from GitHub ...", flush=True)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(_NUCLEI_TREE_URL, headers=headers) as resp:
                resp.raise_for_status()
                tree_data = await resp.json(content_type=None)

        # 2. Filter to YAML files under high-value directories.
        candidates: list[dict[str, Any]] = []
        for item in tree_data.get("tree", []):
            path: str = item.get("path", "")
            if not path.endswith(".yaml"):
                continue
            if any(path.startswith(pfx) for pfx in _NUCLEI_BULK_PREFIXES):
                candidates.append(item)

        stats["total_available"] = len(candidates)

        if not candidates:
            log.info("Bulk download: no matching YAML files found in tree")
            print("No matching templates found in repository.", flush=True)
            return stats

        # 3. Determine which files need downloading.
        to_download: list[dict[str, Any]] = []
        for c in candidates:
            rel_path = c["path"]
            sha = c.get("sha", "")
            if rel_path in manifest and manifest[rel_path] == sha:
                stats["already_present"] += 1
                continue
            to_download.append(c)

        if not to_download:
            msg = (
                f"All {stats['total_available']} templates already present "
                f"-- nothing to download."
            )
            log.info("Bulk download: %s", msg)
            print(msg, flush=True)
            return stats

        total = len(to_download)
        print(
            f"Found {stats['total_available']} templates, "
            f"{stats['already_present']} already present, "
            f"{total} to download ...",
            flush=True,
        )

        # 4. Download concurrently with a semaphore.
        sem = asyncio.Semaphore(_BULK_CONCURRENCY)
        dl_timeout = aiohttp.ClientTimeout(total=15)
        downloaded_count = 0
        lock = asyncio.Lock()

        async def _download_one(
            dl_session: aiohttp.ClientSession,
            item: dict[str, Any],
        ) -> None:
            nonlocal downloaded_count
            rel_path = item["path"]
            sha = item.get("sha", "")
            raw_url = f"{_NUCLEI_RAW_BASE}/{rel_path}"

            async with sem:
                try:
                    async with dl_session.get(raw_url) as dl_resp:
                        dl_resp.raise_for_status()
                        content = await dl_resp.text()

                    # Preserve subdirectory structure under community/.
                    from pathlib import PurePosixPath

                    sub_path = PurePosixPath(rel_path)
                    dest_dir = COMMUNITY_DIR / str(sub_path.parent)
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest = dest_dir / sub_path.name
                    dest.write_text(content, encoding="utf-8")

                    async with lock:
                        manifest[rel_path] = sha
                        downloaded_count += 1
                        stats["downloaded"] += 1
                        current = downloaded_count

                    if progress_callback is not None:
                        progress_callback(current, total, rel_path)
                    elif current % 50 == 0 or current == total:
                        print(
                            f"Downloaded {current}/{total} templates ...",
                            flush=True,
                        )

                except Exception as exc:
                    log.debug(
                        "Bulk download failed for %s: %s", rel_path, exc,
                    )
                    async with lock:
                        stats["failed"] += 1

        async with aiohttp.ClientSession(timeout=dl_timeout) as dl_session:
            tasks = [_download_one(dl_session, item) for item in to_download]
            await asyncio.gather(*tasks)

        # 5. Persist the updated manifest.
        _BULK_MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _BULK_MANIFEST_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        tmp.replace(_BULK_MANIFEST_FILE)

        summary = (
            f"Bulk download complete: {stats['downloaded']}/{total} new "
            f"templates downloaded, {stats['failed']} failed, "
            f"{stats['already_present']} already present "
            f"(total available: {stats['total_available']})"
        )
        log.info(summary)
        print(summary, flush=True)

        return stats

    # ── Feed: NVD CVE v2.0 ────────────────────────────────────────────────

    async def _update_cve_feed(self, cache: dict[str, Any]) -> None:
        """Pull recent CVEs from NVD API v2.0 and append to cve_map.json."""
        import aiohttp

        cve_path = self.data_dir / "cve_map.json"

        # Load existing map
        existing: dict[str, Any] = {}
        if cve_path.exists():
            try:
                existing = json.loads(cve_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}

        # Determine the window — last 8 days (overlap is fine, we deduplicate)
        now = datetime.now(UTC)
        from datetime import timedelta

        start = now - timedelta(days=8)

        # Pagination constants
        _RESULTS_PER_PAGE = 100
        _MAX_TOTAL_CVES = 2000  # safety cap to avoid hammering the API
        # NVD rate limit: 5 requests per 30 seconds without an API key
        _NVD_PAGE_DELAY = 6.5  # seconds between paginated requests

        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
        all_vulns: list[dict[str, Any]] = []

        async with aiohttp.ClientSession(timeout=timeout) as session:
            start_index = 0
            page_num = 0
            while start_index < _MAX_TOTAL_CVES:
                params = {
                    "pubStartDate": _iso_utc(start),
                    "pubEndDate": _iso_utc(now),
                    "resultsPerPage": str(_RESULTS_PER_PAGE),
                    "startIndex": str(start_index),
                }
                # Respect NVD rate limit between pages (skip delay on first)
                if page_num > 0:
                    import asyncio as _aio

                    await _aio.sleep(_NVD_PAGE_DELAY)

                async with session.get(_NVD_BASE, params=params) as resp:
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)

                vulns_page = data.get("vulnerabilities", [])
                all_vulns.extend(vulns_page)

                total_results = data.get("totalResults", 0)
                start_index += _RESULTS_PER_PAGE
                page_num += 1

                log.info(
                    "CVE feed: fetched page %d (%d items, %d/%d total)",
                    page_num, len(vulns_page), min(start_index, total_results),
                    total_results,
                )

                # Stop when we've retrieved all available results
                if start_index >= total_results:
                    break

        new_count = 0
        for vuln in all_vulns:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "")
            if not cve_id or cve_id in existing:
                continue

            # Extract best-available description (English preferred)
            descriptions = cve_item.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc and descriptions:
                desc = descriptions[0].get("value", "")

            # Extract CVSS score (prefer v3.1, fall back to v3.0, then v2.0)
            metrics = cve_item.get("metrics", {})
            cvss_score: float | None = None
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    if cvss_score is not None:
                        break

            # Extract affected CPE strings
            cpe_list: list[str] = []
            configs = cve_item.get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if criteria:
                            cpe_list.append(criteria)

            existing[cve_id] = {
                "description": desc,
                "cvss_score": cvss_score,
                "cpe": cpe_list,
                "published": cve_item.get("published", ""),
            }
            new_count += 1

        # Write atomically
        tmp = cve_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        tmp.replace(cve_path)
        log.info("CVE feed: %d new CVEs added (total %d)", new_count, len(existing))

    # ── Feed: Nuclei community templates ──────────────────────────────────

    async def _update_nuclei_templates(self, cache: dict[str, Any]) -> None:
        """Download newest Nuclei YAML templates from GitHub."""
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=30)
        headers = {"Accept": "application/vnd.github.v3+json"}

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # 1. Fetch the recursive tree listing
            async with session.get(_NUCLEI_TREE_URL, headers=headers) as resp:
                resp.raise_for_status()
                tree_data = await resp.json(content_type=None)

            # 2. Filter to interesting YAML files
            candidates: list[dict[str, Any]] = []
            for item in tree_data.get("tree", []):
                path: str = item.get("path", "")
                if not path.endswith(".yaml"):
                    continue
                if any(path.startswith(pfx) for pfx in _NUCLEI_PATH_PREFIXES):
                    candidates.append(item)

            if not candidates:
                log.info("Nuclei templates: no matching YAML files found in tree")
                return

            # Sort by path descending to approximate "newest" (year dirs sort high)
            candidates.sort(key=lambda c: c["path"], reverse=True)

            # Determine which we already have locally
            existing_files = {
                p.name for p in COMMUNITY_DIR.rglob("*.yaml")
            }

            to_download: list[str] = []
            for c in candidates:
                fname = Path(c["path"]).name
                if fname not in existing_files:
                    to_download.append(c["path"])
                if len(to_download) >= MAX_COMMUNITY_TEMPLATES_PER_UPDATE:
                    break

            if not to_download:
                log.info("Nuclei templates: all candidate templates already present")
                return

            # 3. Download each template
            downloaded = 0
            dl_timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
            async with aiohttp.ClientSession(timeout=dl_timeout) as dl_session:
                for rel_path in to_download:
                    raw_url = f"{_NUCLEI_RAW_BASE}/{rel_path}"
                    try:
                        async with dl_session.get(raw_url) as dl_resp:
                            dl_resp.raise_for_status()
                            content = await dl_resp.text()

                        dest = COMMUNITY_DIR / Path(rel_path).name
                        dest.write_text(content, encoding="utf-8")
                        downloaded += 1
                    except Exception as exc:
                        log.debug(
                            "Failed to download nuclei template %s: %s",
                            rel_path, exc,
                        )

            log.info(
                "Nuclei templates: downloaded %d / %d new templates",
                downloaded, len(to_download),
            )

    # ── Feed: MITRE ATT&CK STIX ──────────────────────────────────────────

    async def _update_attack_data(self, cache: dict[str, Any]) -> None:
        """Pull the MITRE ATT&CK Enterprise STIX bundle and extract techniques."""
        import aiohttp

        attack_path = self.data_dir / "attack_techniques.json"

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(_ATTACK_STIX_URL) as resp:
                resp.raise_for_status()
                stix_bundle = await resp.json(content_type=None)

        techniques: dict[str, dict[str, Any]] = {}
        for obj in stix_bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            # External ID (e.g. "T1059")
            ext_refs = obj.get("external_references", [])
            ext_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    break
            if not ext_id:
                continue

            # Tactics from kill_chain_phases
            tactics: list[str] = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase["phase_name"])

            # First paragraph of description only (keep data compact)
            description = obj.get("description", "")
            first_para = description.split("\n")[0].strip() if description else ""

            techniques[ext_id] = {
                "name": obj.get("name", ""),
                "tactic": tactics[0] if tactics else "",
                "tactics": tactics,
                "description": first_para,
            }

        if not techniques:
            log.info("ATT&CK: no techniques parsed — keeping existing file")
            return

        tmp = attack_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(techniques, indent=2), encoding="utf-8")
        tmp.replace(attack_path)
        log.info("ATT&CK: wrote %d techniques", len(techniques))

    # ── Feed: SecLists default credentials ────────────────────────────────

    async def _update_default_creds(self, cache: dict[str, Any]) -> None:
        """Fetch SecLists credential files and merge into default_creds.json."""
        import aiohttp

        creds_path = self.data_dir / "default_creds.json"

        # Load existing seed data (preserves hand-curated entries)
        existing: dict[str, Any] = {}
        if creds_path.exists():
            try:
                existing = json.loads(creds_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}

        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for service, filename in _SECLISTS_FILES.items():
                url = f"{_SECLISTS_RAW_BASE}/{filename}"
                try:
                    async with session.get(url) as resp:
                        resp.raise_for_status()
                        text = await resp.text()
                except Exception as exc:
                    log.debug("SecLists fetch failed for %s: %s", filename, exc)
                    continue

                new_creds = _parse_seclists_creds(text)
                if not new_creds:
                    continue

                _merge_creds(existing, service, new_creds)

        # Write atomically
        tmp = creds_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        tmp.replace(creds_path)
        log.info("Default creds: merged SecLists data for %d services", len(existing))


# ── Credential parsing helpers ────────────────────────────────────────────


def _parse_seclists_creds(text: str) -> list[dict[str, str]]:
    """Parse a SecLists ``betterdefaultpasslist.txt`` file.

    Lines are formatted as ``username:password`` (one pair per line).
    """
    creds: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Split on first colon only (passwords may contain colons)
        parts = line.split(":", 1)
        if len(parts) == 2:
            creds.append({"username": parts[0], "password": parts[1]})
    return creds


def _merge_creds(
    existing: dict[str, Any],
    service: str,
    new_creds: list[dict[str, str]],
) -> None:
    """Merge *new_creds* into the *service* section of *existing* without duplicates.

    Handles both the legacy list-of-lists format and the current dict format.
    """
    # Ensure the service entry exists with correct structure
    if service not in existing:
        existing[service] = {"credentials": []}
    entry = existing[service]

    # Handle both nested (dict with "credentials" key) and flat (list) formats
    if isinstance(entry, dict):
        current_list = entry.setdefault("credentials", [])
    elif isinstance(entry, list):
        # Legacy format: convert in-place
        current_list = entry
        existing[service] = {"credentials": current_list}
    else:
        current_list = []
        existing[service] = {"credentials": current_list}

    # Build a set of existing (user, pass) for dedup
    seen: set[tuple[str, str]] = set()
    for c in current_list:
        if isinstance(c, dict):
            seen.add((c.get("username", ""), c.get("password", "")))
        elif isinstance(c, list) and len(c) >= 2:
            seen.add((c[0], c[1]))

    for nc in new_creds:
        key = (nc["username"], nc["password"])
        if key not in seen:
            current_list.append(nc)
            seen.add(key)
