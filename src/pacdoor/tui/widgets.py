"""Custom TUI widgets for the PACDOOR dashboard."""

from __future__ import annotations

import csv
import io
from typing import Any

from textual.containers import Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Static, Tree

try:
    from rich.markup import escape
except ImportError:  # pragma: no cover
    def escape(s: str) -> str:  # type: ignore[misc]
        """Fallback: escape Rich markup brackets."""
        return s.replace("[", "\\[")

# ── Severity bar chart ────────────────────────────────────────────────

_BAR_WIDTH = 16
_SEV_COLORS = {
    "critical": "#ff0040",
    "high": "#ff8c00",
    "medium": "#ffcc00",
    "low": "#00cc66",
    "info": "#777777",
}


class SeverityBars(Static):
    """Visual bar chart showing findings by severity."""

    critical: reactive[int] = reactive(0)
    high: reactive[int] = reactive(0)
    medium: reactive[int] = reactive(0)
    low: reactive[int] = reactive(0)
    info: reactive[int] = reactive(0)

    def render(self) -> str:
        total = self.critical + self.high + self.medium + self.low + self.info
        peak = max(self.critical, self.high, self.medium, self.low, self.info, 1)

        def bar(label: str, count: int, color: str) -> str:
            filled = int((count / peak) * _BAR_WIDTH) if peak else 0
            empty = _BAR_WIDTH - filled
            return (
                f"  [{color}]{label}[/{color}] "
                f"[{color}]{'#' * filled}[/{color}]"
                f"[#333333]{'.' * empty}[/#333333] "
                f"[bold white]{count}[/bold white]"
            )

        lines = [
            "[bold #00ff41]FINDINGS[/bold #00ff41]",
            "",
            bar("CRIT", self.critical, _SEV_COLORS["critical"]),
            bar("HIGH", self.high, _SEV_COLORS["high"]),
            bar(" MED", self.medium, _SEV_COLORS["medium"]),
            bar(" LOW", self.low, _SEV_COLORS["low"]),
            bar("INFO", self.info, _SEV_COLORS["info"]),
            "",
            f"  [dim]Total:[/dim] [bold white]{total}[/bold white]",
        ]
        return "\n".join(lines)

    def increment(self, severity: str) -> None:
        sev = severity.lower()
        if sev == "critical":
            self.critical += 1
        elif sev == "high":
            self.high += 1
        elif sev == "medium":
            self.medium += 1
        elif sev == "low":
            self.low += 1
        elif sev == "info":
            self.info += 1

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


# ── Live stats panel ─────────────────────────────────────────────────


class StatsPanel(Static):
    """Live-updating scan statistics."""

    hosts: reactive[int] = reactive(0)
    ports: reactive[int] = reactive(0)
    credentials: reactive[int] = reactive(0)
    modules_done: reactive[int] = reactive(0)
    modules_total: reactive[int] = reactive(0)
    phase: reactive[str] = reactive("INIT")

    def render(self) -> str:
        lines = [
            "[bold #00ff41]STATS[/bold #00ff41]",
            "",
            f"  [#a0a8b0]Hosts[/#a0a8b0]       [bold white]{self.hosts}[/bold white]",
            f"  [#a0a8b0]Ports[/#a0a8b0]       [bold white]{self.ports}[/bold white]",
            f"  [#a0a8b0]Creds[/#a0a8b0]       [bold white]{self.credentials}[/bold white]",
            "",
            f"  [#a0a8b0]Modules[/#a0a8b0]     [bold white]{self.modules_done}[/bold white][dim]/{self.modules_total}[/dim]",
            f"  [#a0a8b0]Phase[/#a0a8b0]       [bold cyan]{self.phase}[/bold cyan]",
        ]
        return "\n".join(lines)


# ── Scan header ──────────────────────────────────────────────────────

_PHASE_PIPELINE = ["RECON", "ENUM", "VULN", "EXPLOIT", "POST", "LATERAL"]

_PHASE_MAP = {
    "reconnaissance": "RECON",
    "enumeration": "ENUM",
    "vulnerability_scan": "VULN",
    "exploitation": "EXPLOIT",
    "post_exploitation": "POST",
    "lateral_movement": "LATERAL",
}


class ScanHeader(Static):
    """Two-line header showing scan status and live counters."""

    status: reactive[str] = reactive("INIT")
    phase: reactive[str] = reactive("INIT")
    hosts: reactive[int] = reactive(0)
    findings: reactive[int] = reactive(0)
    creds: reactive[int] = reactive(0)
    mods_done: reactive[int] = reactive(0)
    mods_total: reactive[int] = reactive(0)
    elapsed: reactive[str] = reactive("00:00")
    target: reactive[str] = reactive("")
    hosts_filtered: reactive[int] = reactive(-1)
    findings_filtered: reactive[int] = reactive(-1)

    def _progress_bar(self, done: int, total: int, width: int = 10) -> str:
        r"""Return an ASCII progress bar like \[=====>    ] 47%."""
        if total <= 0:
            dots = "." * width
            return f"\\[{dots}]  0%"
        pct = min(done / total, 1.0)
        filled = int(pct * width)
        arrow = ">" if filled < width else ""
        empty = width - filled - (1 if arrow else 0)
        pct_str = f"{int(pct * 100)}%"
        bar_filled = "=" * filled + arrow
        bar_empty = "." * empty
        return (
            f"\\[[#00ff41]{bar_filled}[/#00ff41]"
            f"[#333333]{bar_empty}[/#333333]] {pct_str}"
        )

    def render(self) -> str:
        # Status dot
        if self.status == "LIVE":
            dot = "[bold #00ff41]*[/bold #00ff41] [#00ff41]LIVE[/#00ff41]"
        elif self.status == "PAUSED":
            dot = "[bold yellow]*[/bold yellow] [yellow]PAUSED[/yellow]"
        elif self.status == "DONE":
            dot = "[bold #58a6ff]*[/bold #58a6ff] [#58a6ff]DONE[/#58a6ff]"
        else:
            dot = "[dim]*[/dim] [dim]INIT[/dim]"

        # Phase pipeline
        phase_parts = []
        active = _PHASE_MAP.get(self.phase, self.phase.upper() if self.phase else "INIT")
        for p in _PHASE_PIPELINE:
            if p == active:
                phase_parts.append(f"[bold #00ff41]{p}[/bold #00ff41]")
            else:
                phase_parts.append(f"[#555555]{p}[/#555555]")
        pipeline = " [dim]>[/dim] ".join(phase_parts)

        # Target (truncated)
        tgt = self.target
        if len(tgt) > 28:
            tgt = tgt[:25] + "..."

        line1 = (
            f" [bold #00ff41]PACDOOR[/bold #00ff41] [dim]v0.1[/dim]  "
            f"{dot}  [dim]|[/dim]  {pipeline}"
        )

        # Filter counts (show "X of Y" when filter is active)
        h_str = (
            f"[bold white]{self.hosts_filtered}[/bold white][dim]/{self.hosts}[/dim]"
            if self.hosts_filtered >= 0
            else f"[bold white]{self.hosts}[/bold white]"
        )
        f_str = (
            f"[bold white]{self.findings_filtered}[/bold white][dim]/{self.findings}[/dim]"
            if self.findings_filtered >= 0
            else f"[bold white]{self.findings}[/bold white]"
        )

        # Progress bar for modules
        prog = self._progress_bar(self.mods_done, self.mods_total)

        line2 = (
            f" [dim]Target:[/dim] [white]{tgt}[/white]  [dim]|[/dim]  "
            f"[#a0a8b0]H:[/#a0a8b0]{h_str}  "
            f"[#a0a8b0]F:[/#a0a8b0]{f_str}  "
            f"[#a0a8b0]C:[/#a0a8b0][bold white]{self.creds}[/bold white]  "
            f"[dim]|[/dim]  "
            f"[#a0a8b0]Mod:[/#a0a8b0] [bold white]{self.mods_done}[/bold white]"
            f"[dim]/{self.mods_total}[/dim] {prog}  "
            f"[dim]|[/dim]  [bold white]{self.elapsed}[/bold white]"
        )
        return f"{line1}\n{line2}"

    def set_phase(self, phase_name: str) -> None:
        self.phase = phase_name
        label = _PHASE_MAP.get(phase_name, phase_name.upper())
        return label


# ── Host Detail Panel (P2.1) ─────────────────────────────────────────


class HostDetailPanel(Vertical):
    """Drill-down panel shown when a host row is selected.

    Shows ports, findings, credentials, and attack paths for a single host.
    """

    def compose(self):
        from textual.widgets import Static as S
        yield S("[bold #00ff41]HOST DETAIL[/bold #00ff41]  [dim]\\[Esc] Close[/dim]", id="host-detail-title")
        yield S("", id="host-detail-info")
        yield S("[bold #58a6ff]Open Ports[/bold #58a6ff]", id="host-ports-label")
        yield DataTable(id="host-ports-table")
        yield S("[bold #58a6ff]Findings[/bold #58a6ff]", id="host-findings-label")
        yield DataTable(id="host-findings-table")
        yield S("[bold #58a6ff]Credentials[/bold #58a6ff]", id="host-creds-label")
        yield DataTable(id="host-creds-table")
        yield S("[bold #58a6ff]Attack Paths[/bold #58a6ff]", id="host-paths-label")
        yield DataTable(id="host-paths-table")

    def on_mount(self) -> None:
        # Ports table
        pt = self.query_one("#host-ports-table", DataTable)
        pt.add_columns("Port", "Proto", "State", "Service", "Version", "Banner")
        pt.cursor_type = "row"
        pt.zebra_stripes = True

        # Findings table
        ft = self.query_one("#host-findings-table", DataTable)
        ft.add_columns("Sev", "Title", "Module", "CVE")
        ft.cursor_type = "row"
        ft.zebra_stripes = True

        # Creds table
        ct = self.query_one("#host-creds-table", DataTable)
        ct.add_columns("Username", "Type", "Domain", "Admin", "Source")
        ct.cursor_type = "row"
        ct.zebra_stripes = True

        # Paths table
        at = self.query_one("#host-paths-table", DataTable)
        at.add_columns("Direction", "Remote Host", "Technique", "Description")
        at.cursor_type = "row"
        at.zebra_stripes = True

    def load_host(self, ip: str, host_data: dict[str, Any],
                  ports: list[dict], findings: list[dict],
                  creds: list[dict], paths: list[dict]) -> None:
        """Populate all sub-tables with data for one host."""
        info = self.query_one("#host-detail-info", Static)
        hostname = escape(host_data.get("hostname", "") or "")
        os_str = escape(host_data.get("os", "") or "")
        profile = escape(host_data.get("profile", "") or "")
        info.update(
            f"  [bold white]{ip}[/bold white]  "
            f"[dim]{hostname}[/dim]  "
            f"[cyan]{os_str}[/cyan]  "
            f"[#ff8c00]{profile}[/#ff8c00]"
        )

        # Ports
        pt = self.query_one("#host-ports-table", DataTable)
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

        # Findings
        ft = self.query_one("#host-findings-table", DataTable)
        ft.clear()
        for f in findings:
            ft.add_row(
                (f.get("severity", "info")).upper(),
                (f.get("title", ""))[:60],
                f.get("module_name", "") or "",
                f.get("cve_id", "") or "",
            )

        # Creds
        ct = self.query_one("#host-creds-table", DataTable)
        ct.clear()
        for c in creds:
            ct.add_row(
                c.get("username", ""),
                c.get("cred_type", ""),
                c.get("domain", "") or "",
                "Y" if c.get("admin") else "",
                c.get("source_module", "") or "",
            )

        # Attack paths
        at = self.query_one("#host-paths-table", DataTable)
        at.clear()
        for ap in paths:
            at.add_row(
                ap.get("direction", ""),
                ap.get("remote_host", ""),
                ap.get("technique_id", ""),
                (ap.get("description", "") or "")[:50],
            )


# ── Finding Detail Panel (P2.2) ──────────────────────────────────────


class FindingDetailPanel(Vertical):
    """Drill-down panel shown when a finding row is selected.

    Shows full description, evidence, remediation, CVSS, ATT&CK, refs.
    """

    def compose(self):
        from textual.widgets import Static as S
        yield S("[bold #00ff41]FINDING DETAIL[/bold #00ff41]  [dim]\\[Esc] Close[/dim]", id="finding-detail-title")
        yield S("", id="finding-detail-body")
        yield S("[bold #58a6ff]Affected Hosts[/bold #58a6ff]", id="finding-hosts-label")
        yield DataTable(id="finding-hosts-table")

    def on_mount(self) -> None:
        ht = self.query_one("#finding-hosts-table", DataTable)
        ht.add_columns("IP", "Hostname", "Profile")
        ht.cursor_type = "row"
        ht.zebra_stripes = True

    def load_finding(self, finding: dict[str, Any],
                     hosts: list[dict[str, Any]]) -> None:
        """Populate the panel with a finding's full data."""
        title = escape(finding.get("title", "Untitled"))
        sev = (finding.get("severity", "info")).upper()
        desc = escape(finding.get("description", "No description."))
        remed = escape(finding.get("remediation", "") or "N/A")
        cvss = finding.get("cvss_score")
        cvss_str = f"{cvss}" if cvss is not None else "N/A"
        cvss_vec = finding.get("cvss_vector", "") or ""
        cve = finding.get("cve_id", "") or "N/A"
        module = finding.get("module_name", "") or "N/A"
        techniques = finding.get("attack_technique_ids", [])
        if isinstance(techniques, str):
            import json
            try:
                techniques = json.loads(techniques)
            except Exception:
                techniques = [techniques] if techniques else []
        tech_str = ", ".join(techniques) if techniques else "N/A"

        refs = finding.get("references", [])
        if isinstance(refs, str):
            import json
            try:
                refs = json.loads(refs)
            except Exception:
                refs = [refs] if refs else []
        refs_str = "\n    ".join(escape(r) for r in refs) if refs else "N/A"

        evidence = finding.get("evidence", [])
        if isinstance(evidence, str):
            import json
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = []
        ev_lines = []
        for ev in evidence[:5]:
            if isinstance(ev, dict):
                kind = escape(ev.get('kind', '?'))
                data = escape(ev.get('data', '')[:80])
                ev_lines.append(f"    \\[{kind}] {data}")
            else:
                ev_lines.append(f"    {escape(str(ev)[:80])}")
        ev_str = "\n".join(ev_lines) if ev_lines else "    N/A"

        sev_color = {
            "CRITICAL": "#ff0040", "HIGH": "#ff8c00",
            "MEDIUM": "#ffcc00", "LOW": "#00cc66", "INFO": "#555555",
        }.get(sev, "#777777")

        body_text = (
            f"\n  [bold white]{title}[/bold white]\n"
            f"  [{sev_color}]{sev}[/{sev_color}]  "
            f"CVSS: [bold white]{cvss_str}[/bold white] {cvss_vec}\n"
            f"  CVE: [bold white]{cve}[/bold white]  "
            f"Module: [cyan]{module}[/cyan]\n"
            f"  ATT&CK: [bold white]{tech_str}[/bold white]\n\n"
            f"  [bold #58a6ff]Description[/bold #58a6ff]\n"
            f"  {desc}\n\n"
            f"  [bold #58a6ff]Evidence[/bold #58a6ff]\n{ev_str}\n\n"
            f"  [bold #58a6ff]Remediation[/bold #58a6ff]\n  {remed}\n\n"
            f"  [bold #58a6ff]References[/bold #58a6ff]\n    {refs_str}\n"
        )

        body = self.query_one("#finding-detail-body", Static)
        body.update(body_text)

        # Affected hosts
        ht = self.query_one("#finding-hosts-table", DataTable)
        ht.clear()
        for h in hosts:
            ht.add_row(
                h.get("ip", ""),
                h.get("hostname", "") or "",
                h.get("profile", "") or "",
            )


# ── Attack Graph Tree (P2.5) ─────────────────────────────────────────


class AttackGraphTree(Tree):
    """Tree widget showing attack paths as a hierarchy.

    Root nodes = initial access hosts.  Children = lateral hops.
    Edges labeled with technique.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__("Attack Graph", **kwargs)
        self._host_nodes: dict[str, Any] = {}  # ip -> tree node
        self._compromised: set[str] = set()
        self._partial: set[str] = set()

    def add_initial_host(self, ip: str) -> None:
        """Add a root-level initial access host."""
        if ip not in self._host_nodes:
            label = f"[bold #00ff41]{ip}[/bold #00ff41]"
            node = self.root.add(label, expand=True)
            self._host_nodes[ip] = node
            self._compromised.add(ip)

    def add_lateral_hop(self, from_ip: str, to_ip: str, technique: str) -> None:
        """Add a child node representing lateral movement."""
        parent = self._host_nodes.get(from_ip)
        if parent is None:
            self.add_initial_host(from_ip)
            parent = self._host_nodes[from_ip]

        if to_ip in self._host_nodes:
            # Already in tree, mark as compromised
            self._compromised.add(to_ip)
            return

        label = (
            f"[bold white]{to_ip}[/bold white] "
            f"[dim]via[/dim] [#ff8c00]{technique}[/#ff8c00]"
        )
        node = parent.add(label, expand=True)
        self._host_nodes[to_ip] = node
        self._compromised.add(to_ip)

    def add_discovered_host(self, ip: str) -> None:
        """Mark a host as discovered but not yet compromised."""
        if ip not in self._host_nodes:
            label = f"[white]{ip}[/white] [dim](discovered)[/dim]"
            node = self.root.add(label)
            self._host_nodes[ip] = node

    def mark_partial(self, ip: str) -> None:
        """Mark a host as partially compromised."""
        self._partial.add(ip)


# ── Help Overlay (P2.G) ──────────────────────────────────────────────


class HelpOverlay(Static):
    """Full-screen keybinding reference overlay."""

    def render(self) -> str:
        lines = [
            "",
            "  [bold #00ff41]PACDOOR Keybindings[/bold #00ff41]",
            "",
            "  [bold white]q[/bold white]       Quit",
            "  [bold white]p[/bold white]       Pause / Resume scan",
            "  [bold white]r[/bold white]       Generate reports",
            "  [bold white]1-6[/bold white]     Switch tabs",
            "  [bold white]/[/bold white]       Focus search filter",
            "  [bold white]Escape[/bold white]  Clear filter / close panel",
            "  [bold white]Enter[/bold white]   Drill into selected row",
            "  [bold white]e[/bold white]       Export current table to CSV",
            "  [bold white]f[/bold white]       Toggle auto-follow in activity log",
            "  [bold white]?[/bold white]       Show / hide this help",
            "",
            "  [dim]Press ? or Escape to close[/dim]",
            "",
        ]
        return "\n".join(lines)


# ── CSV Export helper ────────────────────────────────────────────────


def export_datatable_csv(table: DataTable, path: str) -> int:
    """Export a DataTable's visible content to a CSV file.

    Returns the number of rows written.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    # Header row
    headers = []
    for col in table.columns.values():
        headers.append(str(col.label))
    writer.writerow(headers)

    # Data rows
    row_count = 0
    for row_key in table.rows:
        row_data = table.get_row(row_key)
        writer.writerow([str(cell) for cell in row_data])
        row_count += 1

    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(buf.getvalue())

    return row_count
