"""PACDOOR TUI Dashboard -- Textual-based terminal interface.

Tabbed layout with real-time scan progress:
  [Activity]    Live log + severity bars + stats
  [Hosts]       Discovered hosts with profiles + drill-down
  [Findings]    All findings with severity, CVE, module + drill-down
  [Creds]       Harvested credentials
  [Attack Map]  Attack path tree visualization
  [Modules]     Module registry status
"""

from __future__ import annotations

import asyncio
import logging
from argparse import Namespace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import (
        DataTable,
        Input,
        RichLog,
        Static,
        TabbedContent,
        TabPane,
    )
except ImportError as _exc:
    raise ImportError(
        "TUI requires 'textual' package.  Install: pip install 'pacdoor[tui]'"
    ) from _exc

import contextlib

from rich.markup import escape as _esc

from pacdoor.core.events import Event
from pacdoor.tui.widgets import (
    AttackGraphTree,
    FindingDetailPanel,
    HelpOverlay,
    HostDetailPanel,
    ScanHeader,
    SeverityBars,
    StatsPanel,
    export_datatable_csv,
)

log = logging.getLogger(__name__)

# Severity colors for Rich markup in the activity log
_SEV_STYLE: dict[str, str] = {
    "critical": "bold #ff0040",
    "high": "bold #ff8c00",
    "medium": "bold #ffcc00",
    "low": "#00cc66",
    "info": "dim",
}

_SEV_BADGE: dict[str, str] = {
    "critical": "[bold #ff0040 on #1a0008] CRIT [/]",
    "high": "[bold #ff8c00 on #1a0f00] HIGH [/]",
    "medium": "[bold #ffcc00 on #1a1500] MED  [/]",
    "low": "[#00cc66 on #001a0d] LOW  [/]",
    "info": "[dim on #111111] INFO [/]",
}


class PacdoorApp(App):
    """Main Textual application for the PACDOOR dashboard."""

    TITLE = "PACDOOR"
    CSS_PATH = "theme.tcss"

    BINDINGS = [
        Binding("q", "quit_app", "Quit"),
        Binding("p", "pause_scan", "Pause/Resume"),
        Binding("r", "generate_report", "Report"),
        Binding("1", "show_tab('tab-activity')", "Activity", show=False),
        Binding("2", "show_tab('tab-hosts')", "Hosts", show=False),
        Binding("3", "show_tab('tab-findings')", "Findings", show=False),
        Binding("4", "show_tab('tab-creds')", "Creds", show=False),
        Binding("5", "show_tab('tab-attack')", "Attack Map", show=False),
        Binding("6", "show_tab('tab-modules')", "Modules", show=False),
        Binding("slash", "focus_filter", "Search", show=False),
        Binding("escape", "clear_filter", "Clear", show=False),
        Binding("e", "export_csv", "Export", show=False),
        Binding("question_mark", "toggle_help", "Help", show=False),
        Binding("f", "toggle_follow", "Follow", show=False),
    ]

    def __init__(self, args: Namespace, output_dir: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._args = args
        self._output_dir = output_dir
        self._engine: Any = None
        self._scan_started_at: datetime | None = None
        self._scan_complete = False
        self._paused = False
        self._modules_started = 0
        self._modules_completed = 0
        self._total_modules = 0
        self._host_count = 0
        self._finding_count = 0
        self._cred_count = 0
        self._current_phase = "INIT"
        self._target_display = ", ".join(args.target) if args.target else "N/A"
        # Row keys for hosts table updates
        self._host_rows: set[str] = set()
        # Shadow data for filtering and drill-down
        self._all_hosts: list[dict[str, Any]] = []
        self._all_findings: list[dict[str, Any]] = []
        self._all_creds: list[dict[str, Any]] = []
        self._all_modules: list[dict[str, Any]] = []
        # Host-id-to-IP mapping for DB lookups
        self._host_id_map: dict[str, str] = {}  # ip -> host_id
        self._host_data_map: dict[str, dict] = {}  # ip -> full data dict
        # Per-host phase tracking
        self._host_phases: dict[str, str] = {}
        # Detail panel state
        self._host_detail_visible = False
        self._finding_detail_visible = False
        self._help_visible = False
        self._auto_follow = True
        # Attack graph state
        self._attack_hops: list[dict[str, Any]] = []

    # -- Layout ────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield ScanHeader(id="scan-header")

        with TabbedContent(id="tabs"):
            # Tab 1: Activity
            with TabPane("1 Activity", id="tab-activity"):
                with Horizontal(id="activity-layout"):
                    yield RichLog(
                        id="activity-log", markup=True, wrap=True,
                        max_lines=2000,
                    )
                    with Vertical(id="stats-sidebar"):
                        yield SeverityBars(id="severity-bars")
                        yield StatsPanel(id="stats-panel")

            # Tab 2: Hosts
            with TabPane("2 Hosts", id="tab-hosts"), Vertical(id="hosts-container"):
                yield Input(
                    placeholder="Filter hosts (IP, hostname, OS, profile)...",
                    id="hosts-filter",
                )
                yield DataTable(id="hosts-table")
                yield HostDetailPanel(id="host-detail-panel")

            # Tab 3: Findings
            with TabPane("3 Findings", id="tab-findings"):
                with Vertical(id="findings-container"):
                    yield Input(
                        placeholder="Filter findings (severity, title, CVE, module)...",
                        id="findings-filter",
                    )
                    yield DataTable(id="findings-table")
                    yield FindingDetailPanel(id="finding-detail-panel")

            # Tab 4: Credentials
            with TabPane("4 Creds", id="tab-creds"):
                yield DataTable(id="creds-table")

            # Tab 5: Attack Map
            with TabPane("5 Attack", id="tab-attack"):
                yield AttackGraphTree(id="attack-tree")

            # Tab 6: Modules
            with TabPane("6 Modules", id="tab-modules"):
                yield DataTable(id="modules-table")

        # Help overlay (hidden by default)
        yield HelpOverlay(id="help-overlay")

        yield Static(
            " [bold #8b949e]q[/] Quit  "
            "[bold #8b949e]p[/] Pause  "
            "[bold #8b949e]r[/] Report  "
            "[bold #8b949e]e[/] Export  "
            "[bold #8b949e]/[/] Filter  "
            "[bold #8b949e]?[/] Help  "
            "[dim]|[/dim]  "
            "[bold #8b949e]1[/]-[bold #8b949e]6[/] Tabs",
            id="footer-bar",
        )

    # -- Lifecycle ─────────────────────────────────────────────────────

    def on_mount(self) -> None:
        self._scan_started_at = datetime.now(UTC)

        # Initialize header
        header: ScanHeader = self.query_one("#scan-header", ScanHeader)
        header.target = self._target_display
        header.status = "LIVE"

        # Hosts table (now with Phase column)
        ht: DataTable = self.query_one("#hosts-table", DataTable)
        self._hcol_ip, self._hcol_host, self._hcol_os, self._hcol_profile, self._hcol_phase = (
            ht.add_columns("IP Address", "Hostname", "OS", "Profile", "Phase")
        )
        ht.cursor_type = "row"
        ht.zebra_stripes = True

        # Findings table
        ft: DataTable = self.query_one("#findings-table", DataTable)
        ft.add_columns("Sev", "Title", "Module", "CVE")
        ft.cursor_type = "row"
        ft.zebra_stripes = True

        # Credentials table
        ct: DataTable = self.query_one("#creds-table", DataTable)
        ct.add_columns("Username", "Type", "Host", "Domain", "Admin", "Source")
        ct.cursor_type = "row"
        ct.zebra_stripes = True

        # Modules table
        mt: DataTable = self.query_one("#modules-table", DataTable)
        mt.add_columns("Module", "Phase", "Status", "Host", "Findings", "Waiting For")
        mt.cursor_type = "row"
        mt.zebra_stripes = True

        # Hide detail panels and help initially
        self.query_one("#host-detail-panel").display = False
        self.query_one("#finding-detail-panel").display = False
        self.query_one("#help-overlay").display = False

        # Timer for elapsed display
        self.set_interval(1.0, self._tick)

        # Launch engine
        self.run_worker(self._run_engine(), exclusive=True)

    # -- Engine integration ────────────────────────────────────────────

    async def _run_engine(self) -> None:
        from pacdoor.core.engine import Engine

        engine = Engine(
            targets=self._args.target,
            db_path=self._output_dir / "pacdoor.db",
            max_concurrency=self._args.concurrency,
            rate_limit=self._args.rate_limit,
            max_safety=self._args.max_safety,
            no_exploit=self._args.no_exploit,
            recon_only=self._args.recon_only,
            offline=self._args.offline,
            timeout=self._args.timeout,
            exclude=self._args.exclude,
            ports=self._args.ports,
            username=self._args.username,
            password=self._args.password,
            ntlm_hash=getattr(self._args, "hash", None),
            domain=self._args.domain,
            resume=getattr(self._args, "resume", False),
            excluded_modules=getattr(self._args, "excluded_modules", []),
            module_timeout=getattr(self._args, "module_timeout", 300),
            scope_file=getattr(self._args, "scope_file", None),
            module_dir=getattr(self._args, "module_dir", None),
        )
        self._engine = engine

        engine.events.on(Event.MODULE_STARTED, self._on_module_started)
        engine.events.on(Event.MODULE_COMPLETED, self._on_module_completed)
        engine.events.on(Event.HOST_DISCOVERED, self._on_host_discovered)
        engine.events.on(Event.FINDING_DISCOVERED, self._on_finding_discovered)
        engine.events.on(Event.CREDENTIAL_FOUND, self._on_credential_found)
        engine.events.on(Event.PHASE_CHANGED, self._on_phase_changed)
        engine.events.on(Event.HOST_PHASE_CHANGED, self._on_host_phase_changed)
        engine.events.on(Event.PROFILE_DETECTED, self._on_profile_detected)
        engine.events.on(Event.LATERAL_HOP, self._on_lateral_hop)
        engine.events.on(Event.SCAN_COMPLETE, self._on_scan_complete)

        self._log(
            "[bold #00ff41]Engine initialized. Scanning...[/bold #00ff41]"
        )

        try:
            summary = await engine.run()
            h = summary.get("hosts", 0)
            f = summary.get("findings", 0)
            c = summary.get("credentials", 0)
            t = summary.get("elapsed_seconds", 0)
            self._log(
                f"[bold #00ff41]Scan complete -- "
                f"{h} hosts, {f} findings, {c} creds "
                f"in {t:.0f}s[/bold #00ff41]"
            )
        except asyncio.CancelledError:
            self._log("[bold yellow]Scan cancelled.[/bold yellow]")
        except Exception as exc:
            self._log(f"[bold #ff0040]Engine error: {_esc(str(exc))}[/bold #ff0040]")
            log.exception("Engine crashed")

    # -- Event handlers ────────────────────────────────────────────────

    def _on_module_started(self, data: dict[str, Any]) -> None:
        mod = data.get("module", "?")
        host = data.get("host", "")
        phase = data.get("phase", "")
        self._modules_started += 1

        # Track in shadow list
        mod_entry = {
            "module": mod, "phase": phase, "status": "running",
            "host": host, "findings": 0,
            "required_facts": data.get("required_facts", []),
        }
        self._all_modules.append(mod_entry)
        self._refresh_modules_table()

        self._log(f"[cyan]{mod}[/cyan]: [dim]running...[/dim]")
        self._sync_header()
        self._sync_stats()

    def _on_module_completed(self, data: dict[str, Any]) -> None:
        mod = data.get("module", "?")
        findings = data.get("findings", 0)
        error = data.get("error")
        self._modules_completed += 1

        # Update shadow list
        status = "failed" if error else "completed"
        for entry in self._all_modules:
            if entry["module"] == mod and entry["status"] == "running":
                entry["status"] = status
                entry["findings"] = findings
                break
        self._refresh_modules_table()

        if error:
            self._log(f"[cyan]{mod}[/cyan]: [bold #ff0040]FAILED[/bold #ff0040] -- {_esc(str(error))}")
        elif findings > 0:
            self._log(
                f"[cyan]{mod}[/cyan]: "
                f"[bold #00ff41]{findings} finding(s)[/bold #00ff41]"
            )
        else:
            self._log(f"[cyan]{mod}[/cyan]: [dim]done (0 findings)[/dim]")
        self._sync_header()
        self._sync_stats()

    def _on_host_discovered(self, data: dict[str, Any]) -> None:
        ip = data.get("ip", "?")
        hostname = data.get("hostname", "")
        host_id = data.get("id", "")
        os_info = data.get("os", "")
        self._host_count += 1

        # Store mapping
        if host_id:
            self._host_id_map[ip] = host_id
        self._host_data_map[ip] = data

        # Shadow list for filtering
        host_entry = {
            "ip": ip, "hostname": hostname or "", "os": os_info or "",
            "profile": "unknown", "phase": "",
        }
        self._all_hosts.append(host_entry)

        if ip not in self._host_rows:
            self._host_rows.add(ip)
            try:
                ht: DataTable = self.query_one("#hosts-table", DataTable)
                ht.add_row(ip, hostname or "", os_info or "", "unknown", "", key=ip)
            except Exception:
                pass

        # Add to attack tree as discovered
        try:
            tree: AttackGraphTree = self.query_one("#attack-tree", AttackGraphTree)
            tree.add_discovered_host(ip)
        except Exception:
            pass

        self._log(f"[bold white]{ip}[/bold white] [dim]{_esc(hostname or '')}[/dim] discovered")
        self._sync_header()
        self._sync_stats()

    def _on_finding_discovered(self, data: dict[str, Any]) -> None:
        title = data.get("title", "untitled")
        sev = data.get("severity", "info")
        module = data.get("module_name", "") or data.get("module", "") or ""
        cve = data.get("cve_id", "") or ""
        self._finding_count += 1

        badge = _SEV_BADGE.get(sev, _SEV_BADGE["info"])

        # Store full finding data in shadow list
        self._all_findings.append(data)

        # Update severity bars
        try:
            bars: SeverityBars = self.query_one("#severity-bars", SeverityBars)
            bars.increment(sev)
        except Exception:
            pass

        # Add to findings table with module and CVE (FIX for P2.2 bug)
        try:
            ft: DataTable = self.query_one("#findings-table", DataTable)
            sev_display = {
                "critical": "[bold #ff0040]CRIT[/]",
                "high": "[bold #ff8c00]HIGH[/]",
                "medium": "[bold #ffcc00]MED[/]",
                "low": "[#00cc66]LOW[/]",
                "info": "[#777777]INFO[/]",
            }.get(sev, sev.upper())
            ft.add_row(sev_display, title[:80], module[:30], cve[:20])
        except Exception:
            pass

        self._log(f"{badge} {_esc(title)}")
        self._sync_header()

    def _on_credential_found(self, data: dict[str, Any]) -> None:
        username = data.get("username", "?")
        cred_type = data.get("cred_type", "?")
        host = data.get("host", "?")
        domain = data.get("domain", "")
        admin = data.get("admin", False)
        source = data.get("source_module", "")
        self._cred_count += 1

        # Shadow list
        self._all_creds.append(data)

        try:
            ct: DataTable = self.query_one("#creds-table", DataTable)
            ct.add_row(
                username, cred_type, host, domain,
                "Y" if admin else "", source,
            )
        except Exception:
            pass

        admin_tag = " [bold #ff0040](ADMIN)[/bold #ff0040]" if admin else ""
        self._log(
            f"[bold #ffcc00]CRED[/bold #ffcc00] "
            f"[bold white]{username}[/bold white]:{cred_type} "
            f"@ {host}{admin_tag}"
        )
        self._sync_header()
        self._sync_stats()

    def _on_phase_changed(self, data: dict[str, Any]) -> None:
        phase = data.get("phase", "unknown")
        # Check for host-specific suffix (e.g., "enumeration:10.0.0.1")
        parts = phase.split(":")
        base_phase = parts[0]

        if len(parts) > 1:
            # Per-host phase update
            host_ip = parts[1]
            self._update_host_phase(host_ip, base_phase)

        self._current_phase = base_phase

        from pacdoor.tui.widgets import _PHASE_MAP
        label = _PHASE_MAP.get(base_phase, base_phase.upper())
        self._log(
            f"[bold #00ff41]>> Phase: {label}[/bold #00ff41]"
        )
        self._sync_header()
        self._sync_stats()

    def _on_host_phase_changed(self, data: dict[str, Any]) -> None:
        """Handle dedicated per-host phase events from the planner."""
        ip = data.get("ip", "")
        phase = data.get("phase", "")
        if ip and phase:
            self._update_host_phase(ip, phase)

    def _update_host_phase(self, ip: str, phase: str) -> None:
        """Update the Phase column for a specific host."""
        from pacdoor.tui.widgets import _PHASE_MAP
        label = _PHASE_MAP.get(phase, phase.upper())
        self._host_phases[ip] = label

        # Update shadow data
        for h in self._all_hosts:
            if h["ip"] == ip:
                h["phase"] = label
                break

        try:
            ht: DataTable = self.query_one("#hosts-table", DataTable)
            ht.update_cell(ip, self._hcol_phase, label)
        except Exception:
            pass

    def _on_profile_detected(self, data: dict[str, Any]) -> None:
        ip = data.get("ip", "?")
        profile = data.get("profile", "unknown")

        # Update shadow data
        for h in self._all_hosts:
            if h["ip"] == ip:
                h["profile"] = profile
                break
        if ip in self._host_data_map:
            self._host_data_map[ip]["profile"] = profile

        try:
            ht: DataTable = self.query_one("#hosts-table", DataTable)
            ht.update_cell(ip, self._hcol_profile, profile)
        except Exception:
            pass
        self._log(
            f"[white]{ip}[/white] profiled as [cyan]{profile}[/cyan]"
        )

    def _on_lateral_hop(self, data: dict[str, Any]) -> None:
        from_ip = data.get("from", "?")
        to_ip = data.get("to", "?")
        technique = data.get("technique", "")

        self._attack_hops.append(data)

        self._log(
            f"[bold #ff8c00]LATERAL[/bold #ff8c00] "
            f"[white]{from_ip}[/white] [bold #ff8c00]>>>[/bold #ff8c00] "
            f"[bold white]{to_ip}[/bold white] "
            f"[dim]({technique})[/dim]"
        )

        # Update attack tree
        try:
            tree: AttackGraphTree = self.query_one("#attack-tree", AttackGraphTree)
            tree.add_initial_host(from_ip)
            tree.add_lateral_hop(from_ip, to_ip, technique)
        except Exception:
            pass

    def _on_scan_complete(self, _data: dict[str, Any]) -> None:
        self._scan_complete = True
        self._log(
            "[bold #00ff41]"
            "============================================\n"
            "  SCAN COMPLETE -- press r for reports\n"
            "============================================"
            "[/bold #00ff41]"
        )
        try:
            header: ScanHeader = self.query_one("#scan-header", ScanHeader)
            header.status = "DONE"
        except Exception:
            pass

    # -- DataTable row selection handlers ──────────────────────────────

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle Enter on a DataTable row -- drill down into host or finding."""
        table_id = event.data_table.id

        if table_id == "hosts-table":
            self._drill_into_host(event)
        elif table_id == "findings-table":
            self._drill_into_finding(event)

    def _drill_into_host(self, event: DataTable.RowSelected) -> None:
        """Show the HostDetailPanel for the selected host."""
        row_data = event.data_table.get_row(event.row_key)
        if not row_data:
            return
        ip = str(row_data[0])

        panel: HostDetailPanel = self.query_one("#host-detail-panel", HostDetailPanel)
        host_data = self._host_data_map.get(ip, {"ip": ip})

        # Gather data from shadow lists
        host_id = self._host_id_map.get(ip, "")

        ports: list[dict] = []
        findings: list[dict] = []
        creds: list[dict] = []
        paths: list[dict] = []

        # Findings for this host
        for f in self._all_findings:
            fhost = f.get("host_id", "") or f.get("host", "") or f.get("ip", "")
            if fhost == host_id or fhost == ip:
                findings.append(f)

        # Creds for this host
        for c in self._all_creds:
            if c.get("host", "") == ip or c.get("host_id", "") == host_id:
                creds.append(c)

        # Attack paths involving this host
        for hop in self._attack_hops:
            if hop.get("from", "") == ip:
                paths.append({
                    "direction": "-->",
                    "remote_host": hop.get("to", ""),
                    "technique_id": hop.get("technique", ""),
                    "description": hop.get("description", ""),
                })
            elif hop.get("to", "") == ip:
                paths.append({
                    "direction": "<--",
                    "remote_host": hop.get("from", ""),
                    "technique_id": hop.get("technique", ""),
                    "description": hop.get("description", ""),
                })

        panel.load_host(ip, host_data, ports, findings, creds, paths)
        panel.display = True
        self._host_detail_visible = True

        # Also try async DB fetch for ports -- show loading indicator
        if host_id:
            try:
                pt = panel.query_one("#host-ports-table", DataTable)
                pt.clear()
                pt.add_row("...", "", "", "Loading...", "", "")
            except Exception:
                pass
            self.run_worker(
                self._load_host_ports(ip, host_id),
                exclusive=False,
            )

    async def _load_host_ports(self, ip: str, host_id: str) -> None:
        """Fetch ports from DB and update the host detail panel."""
        try:
            from pacdoor.db.database import Database
            db = Database(self._output_dir / "pacdoor.db")
            await db.initialize()
            all_ports = await db.get_all_ports()
            await db.close()

            ports = [p for p in all_ports if p.get("host_id") == host_id]
            panel: HostDetailPanel = self.query_one("#host-detail-panel", HostDetailPanel)
            pt = panel.query_one("#host-ports-table", DataTable)
            pt.clear()
            for p in ports:
                pt.add_row(
                    str(p.get("port", "")),
                    p.get("protocol", "tcp"),
                    p.get("state", ""),
                    p.get("service_name", "") or "",
                    p.get("service_version", "") or "",
                    (p.get("banner", "") or "")[:40],
                )
        except Exception:
            pass

    def _drill_into_finding(self, event: DataTable.RowSelected) -> None:
        """Show the FindingDetailPanel for the selected finding."""
        # Map the selected table row back to the correct finding in
        # _all_findings.  The table may be filtered, so cursor_row does NOT
        # correspond 1-to-1 with _all_findings indices.  Instead, retrieve
        # the row data from the table and match by title.
        row_data = event.data_table.get_row(event.row_key)
        if not row_data:
            return
        selected_title = str(row_data[1]).strip()
        finding = None
        for f in self._all_findings:
            if f.get("title", "")[:80] == selected_title:
                finding = f
                break
        if finding is None:
            return
        panel: FindingDetailPanel = self.query_one("#finding-detail-panel", FindingDetailPanel)

        # Get affected hosts
        host_id = finding.get("host_id", "") or ""
        affected_hosts: list[dict] = []
        if host_id:
            for h in self._all_hosts:
                hid = self._host_id_map.get(h["ip"], "")
                if hid == host_id:
                    affected_hosts.append(h)

        # If no match by id, try matching by IP in finding
        if not affected_hosts:
            fhost = finding.get("host", "") or finding.get("ip", "")
            if fhost:
                for h in self._all_hosts:
                    if h["ip"] == fhost:
                        affected_hosts.append(h)

        panel.load_finding(finding, affected_hosts)
        panel.display = True
        self._finding_detail_visible = True

    # -- Filter / Search (P2.3) ────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        """Re-filter the relevant table when filter text changes."""
        input_id = event.input.id
        query = event.value.strip().lower()

        if input_id == "hosts-filter":
            self._apply_hosts_filter(query)
        elif input_id == "findings-filter":
            self._apply_findings_filter(query)

    def _apply_hosts_filter(self, query: str) -> None:
        """Filter hosts table by IP, hostname, OS, or profile."""
        try:
            ht: DataTable = self.query_one("#hosts-table", DataTable)
            ht.clear()
            shown = 0
            total = len(self._all_hosts)
            for h in self._all_hosts:
                if query and not any(
                    query in (h.get(k, "") or "").lower()
                    for k in ("ip", "hostname", "os", "profile")
                ):
                    continue
                ip = h["ip"]
                ht.add_row(
                    ip,
                    h.get("hostname", ""),
                    h.get("os", ""),
                    h.get("profile", "unknown"),
                    h.get("phase", ""),
                    key=ip,
                )
                shown += 1
            # Update filter placeholder with result counts
            hf = self.query_one("#hosts-filter", Input)
            if query:
                hf.placeholder = f"Filter hosts... ({shown} of {total})"
            else:
                hf.placeholder = "Filter hosts (IP, hostname, OS, profile)..."
        except Exception:
            pass

    def _apply_findings_filter(self, query: str) -> None:
        """Filter findings table by severity, title, CVE, or module."""
        try:
            ft: DataTable = self.query_one("#findings-table", DataTable)
            ft.clear()
            shown = 0
            total = len(self._all_findings)
            for f in self._all_findings:
                sev = f.get("severity", "info")
                title = f.get("title", "")
                module = f.get("module_name", "") or f.get("module", "") or ""
                cve = f.get("cve_id", "") or ""
                searchable = f"{sev} {title} {module} {cve}".lower()
                if query and query not in searchable:
                    continue
                sev_display = {
                    "critical": "[bold #ff0040]CRIT[/]",
                    "high": "[bold #ff8c00]HIGH[/]",
                    "medium": "[bold #ffcc00]MED[/]",
                    "low": "[#00cc66]LOW[/]",
                    "info": "[#777777]INFO[/]",
                }.get(sev, sev.upper())
                ft.add_row(
                    sev_display,
                    title[:80],
                    module[:30],
                    cve[:20],
                )
                shown += 1
            # Update filter placeholder with result counts
            ff = self.query_one("#findings-filter", Input)
            if query:
                ff.placeholder = f"Filter findings... ({shown} of {total})"
            else:
                ff.placeholder = "Filter findings (severity, title, CVE, module)..."
        except Exception:
            pass

    # -- Modules table refresh (P2.7) ──────────────────────────────────

    def _refresh_modules_table(self) -> None:
        """Rebuild the modules table from the shadow list."""
        try:
            mt: DataTable = self.query_one("#modules-table", DataTable)
            mt.clear()
            for m in self._all_modules:
                status = m.get("status", "pending")
                status_display = {
                    "pending": "[dim]PENDING[/dim]",
                    "running": "[bold cyan]RUNNING[/bold cyan]",
                    "completed": "[bold #00ff41]DONE[/bold #00ff41]",
                    "failed": "[bold #ff0040]FAILED[/bold #ff0040]",
                    "skipped": "[yellow]SKIP[/yellow]",
                }.get(status, status.upper())
                phase = m.get("phase", "")
                if isinstance(phase, str):
                    from pacdoor.tui.widgets import _PHASE_MAP
                    phase = _PHASE_MAP.get(phase, phase.upper() if phase else "")
                required = m.get("required_facts", [])
                waiting = ", ".join(required[:3]) if required else ""
                mt.add_row(
                    m.get("module", ""),
                    phase,
                    status_display,
                    m.get("host", ""),
                    str(m.get("findings", 0)),
                    waiting,
                )
        except Exception:
            pass

    # -- Helpers ────────────────────────────────────────────────────────

    def _log(self, message: str) -> None:
        """Write a timestamped line to the activity log."""
        now = datetime.now(UTC)
        elapsed = 0
        if self._scan_started_at:
            elapsed = int((now - self._scan_started_at).total_seconds())
        m, s = divmod(elapsed, 60)
        h, m = divmod(m, 60)
        if h:
            ts = f"[dim]{h}:{m:02d}:{s:02d}[/dim]"
        else:
            ts = f"[dim]{m:02d}:{s:02d}[/dim]"
        try:
            al: RichLog = self.query_one("#activity-log", RichLog)
            al.write(f" {ts}  {message}")
            if self._auto_follow:
                al.scroll_end(animate=False)
        except Exception:
            pass

    def _sync_header(self) -> None:
        try:
            hdr: ScanHeader = self.query_one("#scan-header", ScanHeader)
            hdr.hosts = self._host_count
            hdr.findings = self._finding_count
            hdr.creds = self._cred_count
            hdr.mods_done = self._modules_completed
            hdr.mods_total = self._modules_started
            hdr.phase = self._current_phase
        except Exception:
            pass

    def _sync_stats(self) -> None:
        try:
            sp: StatsPanel = self.query_one("#stats-panel", StatsPanel)
            sp.hosts = self._host_count
            sp.credentials = self._cred_count
            sp.modules_done = self._modules_completed
            sp.modules_total = self._modules_started
            from pacdoor.tui.widgets import _PHASE_MAP
            sp.phase = _PHASE_MAP.get(self._current_phase, self._current_phase.upper())
        except Exception:
            pass

    def _tick(self) -> None:
        if not self._scan_started_at:
            return
        secs = int((datetime.now(UTC) - self._scan_started_at).total_seconds())
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        elapsed = f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
        try:
            hdr: ScanHeader = self.query_one("#scan-header", ScanHeader)
            hdr.elapsed = elapsed
        except Exception:
            pass

    # -- Actions ───────────────────────────────────────────────────────

    def action_quit_app(self) -> None:
        if self._engine and not self._scan_complete:
            self._engine.shutdown()
            self._log("[bold yellow]Shutting down...[/bold yellow]")
        self.exit()

    def action_pause_scan(self) -> None:
        if self._scan_complete or not self._engine:
            return
        if self._paused:
            self._engine._shutdown.clear()
            self._paused = False
            self._log("[bold #00ff41]Resumed.[/bold #00ff41]")
            try:
                hdr: ScanHeader = self.query_one("#scan-header", ScanHeader)
                hdr.status = "LIVE"
            except Exception:
                pass
        else:
            self._engine._shutdown.set()
            self._paused = True
            self._log("[bold yellow]Paused.[/bold yellow]")
            try:
                hdr: ScanHeader = self.query_one("#scan-header", ScanHeader)
                hdr.status = "PAUSED"
            except Exception:
                pass

    def action_generate_report(self) -> None:
        if not self._scan_complete:
            self._log("[yellow]Scan still running -- report may be partial.[/yellow]")
        self.run_worker(self._do_generate_report(), exclusive=False)

    async def _do_generate_report(self) -> None:
        self._log("[bold cyan]Generating reports...[/bold cyan]")
        try:
            from pacdoor.db.database import Database
            from pacdoor.report.generator import ReportGenerator

            db = Database(self._output_dir / "pacdoor.db")
            await db.initialize()
            gen = ReportGenerator(db, self._output_dir)
            for fmt in self._args.report_format:
                path = await gen.generate(fmt)
                self._log(f"[#00ff41]Saved:[/#00ff41] [bold white]{path}[/bold white]")
            await db.close()
            self._log("[bold #00ff41]All reports generated.[/bold #00ff41]")
        except Exception as exc:
            self._log(f"[bold #ff0040]Report failed: {_esc(str(exc))}[/bold #ff0040]")
            log.exception("Report generation error")

    def action_show_tab(self, tab_id: str) -> None:
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            tabs.active = tab_id
        except Exception:
            pass

    def action_focus_filter(self) -> None:
        """Focus the filter input on the current tab."""
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            active = tabs.active
            if active == "tab-hosts":
                self.query_one("#hosts-filter", Input).focus()
            elif active == "tab-findings":
                self.query_one("#findings-filter", Input).focus()
        except Exception:
            pass

    def action_clear_filter(self) -> None:
        """Clear filters, close detail panels, close help."""
        if self._help_visible:
            self.query_one("#help-overlay").display = False
            self._help_visible = False
            return

        if self._host_detail_visible:
            self.query_one("#host-detail-panel").display = False
            self._host_detail_visible = False
            return

        if self._finding_detail_visible:
            self.query_one("#finding-detail-panel").display = False
            self._finding_detail_visible = False
            return

        # Clear filter inputs
        try:
            hf = self.query_one("#hosts-filter", Input)
            if hf.value:
                hf.value = ""
                self._apply_hosts_filter("")
                return
        except Exception:
            pass
        try:
            ff = self.query_one("#findings-filter", Input)
            if ff.value:
                ff.value = ""
                self._apply_findings_filter("")
                return
        except Exception:
            pass

    def action_export_csv(self) -> None:
        """Export the currently visible DataTable to CSV."""
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            active = tabs.active
            table: DataTable | None = None
            name = "export"

            if active == "tab-hosts":
                table = self.query_one("#hosts-table", DataTable)
                name = "hosts"
            elif active == "tab-findings":
                table = self.query_one("#findings-table", DataTable)
                name = "findings"
            elif active == "tab-creds":
                table = self.query_one("#creds-table", DataTable)
                name = "credentials"
            elif active == "tab-modules":
                table = self.query_one("#modules-table", DataTable)
                name = "modules"

            if table is not None:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = str(self._output_dir / f"{name}_{ts}.csv")
                count = export_datatable_csv(table, path)
                self._log(
                    f"[#00ff41]Exported {count} rows to:[/#00ff41] "
                    f"[bold white]{path}[/bold white]"
                )
            else:
                self._log("[yellow]No table to export on this tab.[/yellow]")
        except Exception as exc:
            self._log(f"[bold #ff0040]Export failed: {_esc(str(exc))}[/bold #ff0040]")

    def action_toggle_help(self) -> None:
        """Show or hide the help overlay."""
        self._help_visible = not self._help_visible
        with contextlib.suppress(Exception):
            self.query_one("#help-overlay").display = self._help_visible

    def action_toggle_follow(self) -> None:
        """Toggle auto-follow on the activity log."""
        self._auto_follow = not self._auto_follow
        state = "ON" if self._auto_follow else "OFF"
        self._log(f"[dim]Auto-follow: {state}[/dim]")
