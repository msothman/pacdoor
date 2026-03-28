"""Web service screenshot capture for visual evidence in reports.

Takes headless browser screenshots of HTTP services discovered during
reconnaissance.  Screenshots serve as visual evidence and are embedded
in HTML reports as base64 data URIs for self-contained distribution.

Uses playwright (preferred) or selenium+chromedriver as a fallback.
If neither is available, the module silently skips.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from pacdoor.core.models import Evidence, Finding, Phase, Port, Severity
from pacdoor.modules.base import BaseModule

if TYPE_CHECKING:
    from pacdoor.modules.base import ModuleContext

log = logging.getLogger(__name__)

# Maximum screenshots per host to avoid excessive capture.
_MAX_SCREENSHOTS_PER_HOST = 5

# Page load timeout in milliseconds.
_PAGE_TIMEOUT_MS = 10_000

# Interesting paths that warrant dedicated screenshots (admin panels, logins).
_INTERESTING_PATHS: list[str] = [
    "/admin", "/administrator", "/login", "/auth",
    "/dashboard", "/panel", "/console", "/manage",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/grafana", "/kibana", "/jenkins",
]

# ── Optional-import helpers ───────────────────────────────────────────────

_playwright_available: bool | None = None
_selenium_available: bool | None = None


def _check_playwright() -> bool:
    global _playwright_available  # noqa: PLW0603
    if _playwright_available is not None:
        return _playwright_available
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        _playwright_available = True
    except ImportError:
        log.debug("playwright not installed -- screenshot module will try selenium")
        _playwright_available = False
    return _playwright_available


def _check_selenium() -> bool:
    global _selenium_available  # noqa: PLW0603
    if _selenium_available is not None:
        return _selenium_available
    try:
        from selenium import webdriver  # noqa: F401
        from selenium.webdriver.chrome.options import Options  # noqa: F401
        _selenium_available = True
    except ImportError:
        log.debug("selenium not installed -- screenshot module unavailable")
        _selenium_available = False
    return _selenium_available


# ── Playwright backend ────────────────────────────────────────────────────


async def _capture_playwright(
    urls: list[tuple[str, Path]],
    timeout_ms: int = _PAGE_TIMEOUT_MS,
) -> list[tuple[str, Path, bool]]:
    """Capture screenshots using playwright.  Reuses a single browser instance.

    Args:
        urls: list of (url, output_path) tuples.
        timeout_ms: max wait time per page in ms.

    Returns:
        list of (url, output_path, success) tuples.
    """
    from playwright.async_api import async_playwright

    results: list[tuple[str, Path, bool]] = []

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True)
        except Exception as exc:
            log.debug("Failed to launch Chromium: %s", exc)
            return [(url, path, False) for url, path in urls]

        try:
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )

            for url, output_path in urls:
                success = False
                try:
                    page = await context.new_page()
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                    except Exception:
                        # Some pages never reach network idle; take screenshot anyway
                        try:
                            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                        except Exception as nav_err:
                            log.debug("Navigation failed for %s: %s", url, nav_err)
                            await page.close()
                            results.append((url, output_path, False))
                            continue

                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    await page.screenshot(path=str(output_path), full_page=True)
                    success = True
                    await page.close()
                except Exception as exc:
                    log.debug("Screenshot failed for %s: %s", url, exc)

                results.append((url, output_path, success))
        finally:
            await browser.close()

    return results


# ── Selenium fallback backend ─────────────────────────────────────────────


def _capture_selenium_sync(
    urls: list[tuple[str, Path]],
    timeout_secs: int = _PAGE_TIMEOUT_MS // 1000,
) -> list[tuple[str, Path, bool]]:
    """Capture screenshots using selenium + chromedriver (synchronous).

    Called via ``asyncio.to_thread``.
    """
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    results: list[tuple[str, Path, bool]] = []

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,720")
    options.add_argument("--ignore-certificate-errors")

    try:
        driver = webdriver.Chrome(options=options)
    except Exception as exc:
        log.debug("Failed to launch Chrome via selenium: %s", exc)
        return [(url, path, False) for url, path in urls]

    driver.set_page_load_timeout(timeout_secs)

    try:
        for url, output_path in urls:
            success = False
            try:
                driver.get(url)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                driver.save_screenshot(str(output_path))
                success = True
            except Exception as exc:
                log.debug("Selenium screenshot failed for %s: %s", url, exc)
            results.append((url, output_path, success))
    finally:
        driver.quit()

    return results


async def _capture_selenium(
    urls: list[tuple[str, Path]],
) -> list[tuple[str, Path, bool]]:
    """Async wrapper around the synchronous selenium backend."""
    return await asyncio.to_thread(_capture_selenium_sync, urls)


# ── Module ────────────────────────────────────────────────────────────────


class ScreenshotModule(BaseModule):
    """Headless browser screenshots of web services for visual evidence."""

    name = "recon.screenshot"
    description = "Capture screenshots of HTTP services for visual evidence"
    phase = Phase.RECON
    attack_technique_ids = ["T1592"]
    required_facts = ["service.http"]
    produced_facts = ["http.screenshot"]

    async def check(self, ctx: ModuleContext) -> bool:
        """Pre-check: need service.http facts and at least one browser backend."""
        if not await ctx.facts.has("service.http"):
            return False
        return _check_playwright() or _check_selenium()

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        # Resolve output directory from context config or default.
        output_dir = Path(ctx.config.get("output_dir", "./pacdoor-results"))
        screenshots_dir = output_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        # Gather HTTP services from the fact store.
        http_services: list[Port] = await ctx.facts.get_values("service.http")
        if not http_services:
            return findings

        # Build host_id -> IP lookup.
        hosts = await ctx.facts.get_values("host")
        host_ip_map: dict[str, str] = {h.id: h.ip for h in hosts}

        # Collect interesting paths discovered by http_enum (if available).
        http_paths: dict[str, list[str]] = {}
        try:
            http_enum_facts = await ctx.facts.get_all("http.path")
            for fact in http_enum_facts:
                host_id = fact.host_id or ""
                path_val = str(fact.value) if fact.value else ""
                if path_val:
                    http_paths.setdefault(host_id, []).append(path_val)
        except Exception:
            pass  # http.path facts may not exist

        # Build URL list with per-host caps.
        host_screenshot_counts: dict[str, int] = {}
        url_tasks: list[tuple[str, Path]] = []

        for port_obj in http_services:
            ip = host_ip_map.get(port_obj.host_id)
            if not ip:
                continue

            host_key = f"{ip}:{port_obj.port}"
            count = host_screenshot_counts.get(host_key, 0)
            if count >= _MAX_SCREENSHOTS_PER_HOST:
                continue

            # Determine scheme.
            scheme = "https" if port_obj.port in (443, 8443) else "http"
            base_url = f"{scheme}://{ip}:{port_obj.port}"

            # Root page screenshot.
            safe_name = f"{ip}_{port_obj.port}"
            root_path = screenshots_dir / f"{safe_name}.png"
            url_tasks.append((base_url + "/", root_path))
            host_screenshot_counts[host_key] = count + 1

            # Interesting paths from http_enum.
            discovered_paths = http_paths.get(port_obj.host_id, [])
            interesting = [
                p for p in discovered_paths
                if any(p.rstrip("/").lower().endswith(ip_path.lstrip("/").lower())
                       for ip_path in _INTERESTING_PATHS)
            ]

            for extra_path in interesting:
                if host_screenshot_counts.get(host_key, 0) >= _MAX_SCREENSHOTS_PER_HOST:
                    break
                clean_path = extra_path.lstrip("/").replace("/", "_")
                file_name = f"{safe_name}_{clean_path}.png"
                url_tasks.append((f"{base_url}/{extra_path.lstrip('/')}", screenshots_dir / file_name))
                host_screenshot_counts[host_key] = host_screenshot_counts.get(host_key, 0) + 1

        if not url_tasks:
            return findings

        # Capture screenshots.
        if _check_playwright():
            results = await _capture_playwright(url_tasks)
        elif _check_selenium():
            results = await _capture_selenium(url_tasks)
        else:
            return findings

        # Process results and create findings.
        captured_count = 0
        for url, screenshot_path, success in results:
            if not success or not screenshot_path.exists():
                continue

            captured_count += 1

            # Add fact for this screenshot.
            await ctx.facts.add(
                "http.screenshot",
                {"url": url, "path": str(screenshot_path)},
                self.name,
            )

            findings.append(Finding(
                title=f"Screenshot captured: {url}",
                description=(
                    f"Headless browser screenshot of {url} saved to "
                    f"{screenshot_path.name}. This provides visual evidence "
                    f"of the web service's interface and content."
                ),
                severity=Severity.INFO,
                module_name=self.name,
                attack_technique_ids=["T1592"],
                evidence=[
                    Evidence(
                        kind="screenshot",
                        data=str(screenshot_path),
                    ),
                ],
            ))

        if captured_count > 0:
            log.debug("Captured %d screenshots out of %d URLs", captured_count, len(url_tasks))

        return findings


def screenshots_to_base64(screenshot_dir: Path) -> list[dict[str, str]]:
    """Read all PNG screenshots from a directory and return base64-encoded data.

    Used by the report generator to embed screenshots as data URIs.

    Returns:
        list of dicts with keys: filename, data_uri, url_hint
    """
    result: list[dict[str, str]] = []
    if not screenshot_dir.exists():
        return result

    for png_file in sorted(screenshot_dir.glob("*.png")):
        try:
            raw = png_file.read_bytes()
            b64 = base64.b64encode(raw).decode("ascii")
            data_uri = f"data:image/png;base64,{b64}"

            # Extract URL hint from filename: ip_port[_path].png
            stem = png_file.stem
            parts = stem.split("_", 2)
            if len(parts) >= 2:
                url_hint = f"{parts[0]}:{parts[1]}"
                if len(parts) == 3:
                    url_hint += f"/{parts[2].replace('_', '/')}"
            else:
                url_hint = stem

            result.append({
                "filename": png_file.name,
                "data_uri": data_uri,
                "url_hint": url_hint,
            })
        except Exception as exc:
            log.debug("Failed to read screenshot %s: %s", png_file, exc)

    return result
