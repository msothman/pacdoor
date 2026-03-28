"""CLI argument parsing."""

from __future__ import annotations

import argparse

from pacdoor.core.profiles import PROFILES


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pacdoor",
        description="PACDOOR — Automated Red Team Penetration Testing Tool",
    )

    p.add_argument(
        "target", nargs="*",
        help="Target IP, CIDR range, or hostname (e.g. 10.0.0.0/24, 192.168.1.5)",
    )

    # ── Profile ──
    _profile_help = "Scan profile: " + ", ".join(
        f"{name} ({cfg['description']})" for name, cfg in PROFILES.items()
    )
    p.add_argument(
        "--profile", choices=list(PROFILES.keys()), default=None,
        help=_profile_help,
    )

    # ── Scope control ──
    scope = p.add_argument_group("Scope")
    scope.add_argument(
        "--exclude", nargs="*", default=[],
        help="IPs or CIDRs to exclude from scanning",
    )
    scope.add_argument(
        "--ports", default="top1000",
        help="Port spec: 'top1000', 'all', or '22,80,443' (default: top1000)",
    )
    scope.add_argument(
        "--scope-file", default=None,
        help="File with in-scope IPs/CIDRs/hostnames (one per line)",
    )

    # ── Execution control ──
    ex = p.add_argument_group("Execution")
    ex.add_argument("--concurrency", type=int, default=20,
                    help="Max concurrent module executions (default: 20)")
    ex.add_argument("--rate-limit", type=int, default=100,
                    help="Max requests per second (default: 100)")
    ex.add_argument("--timeout", type=int, default=0,
                    help="Global scan timeout in seconds (0=unlimited, default: 0)")
    ex.add_argument("--conn-timeout", type=int, default=5,
                    help="Per-connection timeout in seconds (default: 5)")

    # ── Mode ──
    mode = p.add_argument_group("Mode")
    mode.add_argument("--recon-only", action="store_true",
                      help="Only run reconnaissance")
    mode.add_argument("--no-exploit", action="store_true",
                      help="Scan + enum + vuln but do NOT exploit")
    mode.add_argument("--max-safety", choices=["safe", "moderate", "dangerous"],
                      default="moderate",
                      help="Max exploit safety level (default: moderate)")

    # ── Resume ──
    resume = p.add_argument_group("Resume")
    resume.add_argument("--resume", action="store_true",
                        help="Resume interrupted scan from checkpoint in output-dir")

    # ── Updates ──
    updates = p.add_argument_group("Updates")
    updates.add_argument("--offline", action="store_true",
                         help="Skip auto-updates, use local data only")
    updates.add_argument("--update-only", action="store_true",
                         help="Update databases and exit (no scanning)")
    updates.add_argument("--download-templates", action="store_true",
                         help="Bulk-download all Nuclei community templates and exit")

    # ── Diff ──
    diff_group = p.add_argument_group("Diff")
    diff_group.add_argument(
        "--diff", nargs=2, metavar=("OLD_DB", "NEW_DB"),
        help="Compare two scan databases and generate a diff report (no scan)",
    )

    # ── Output ──
    out = p.add_argument_group("Output")
    out.add_argument("--output-dir", default="./pacdoor-results",
                     help="Directory for reports and database")
    out.add_argument("--report-format", nargs="+", default=["html", "json"],
                     choices=["html", "json", "markdown", "pdf", "bloodhound"],
                     help="Report formats (default: html json)")
    out.add_argument("--no-tui", action="store_true",
                     help="Disable TUI, log to stderr")
    out.add_argument("--brand-name", default=None,
                     help="Company/assessor name for report branding")
    out.add_argument("--classification", default=None,
                     help="Classification marking (e.g. CONFIDENTIAL)")
    out.add_argument("--logo", default=None, dest="logo_path",
                     help="Path to logo image for report branding")

    # ── Credentials ──
    creds = p.add_argument_group("Credentials")
    creds.add_argument("-u", "--username", help="Username for authenticated scanning")
    creds.add_argument("-p", "--password", help="Password for authenticated scanning")
    creds.add_argument("--hash", help="NTLM hash for pass-the-hash")
    creds.add_argument("-d", "--domain", help="Domain for AD auth")
    creds.add_argument("--cred-file", default=None,
                       help="Read credentials from file (one per line: user:pass or user:hash)")

    # ── Modules ──
    modules = p.add_argument_group("Modules")
    modules.add_argument("--module-dir", default=None,
                         help="Path to external module directory for custom modules")

    # ── Agent mode ──
    agent = p.add_argument_group("Agent")
    agent.add_argument(
        "--agent", metavar="CONFIG",
        help="Run as autonomous agent daemon with YAML config file",
    )

    return p


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --resume and --diff can work without targets
    if (
        not args.update_only
        and not args.download_templates
        and not args.resume
        and not args.diff
        and not getattr(args, "agent", None)
        and not args.target
    ):
        parser.error("target is required (unless --agent, --update-only, --download-templates, --resume, or --diff)")

    # Apply profile defaults (CLI flags override profile values)
    if args.profile:
        from pacdoor.core.profiles import apply_profile
        apply_profile(args, args.profile)

    # Ensure these attributes exist even without a profile
    if not hasattr(args, "excluded_modules"):
        args.excluded_modules = []
    if not hasattr(args, "module_timeout"):
        args.module_timeout = 300

    return args
