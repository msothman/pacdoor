"""Entry point: python -m pacdoor"""

import asyncio
import logging
import sys
from pathlib import Path

from pacdoor.cli import parse_args


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Configure logging
    level = logging.DEBUG if args.no_tui else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.download_templates:
        asyncio.run(_download_templates())
        return

    if args.update_only:
        asyncio.run(_update_only(args))
        return

    if args.diff:
        asyncio.run(_run_diff(args, output_dir))
        return

    if getattr(args, "agent", None):
        _run_agent(args)
        return

    if args.no_tui:
        asyncio.run(_run_headless(args, output_dir))
    else:
        _run_with_tui(args, output_dir)


async def _download_templates() -> None:
    from pacdoor.updater.manager import UpdateManager
    updater = UpdateManager(offline=False)
    stats = await updater.bulk_download_nuclei_templates()
    print(
        f"\nTemplate download summary:\n"
        f"  Total available:  {stats['total_available']}\n"
        f"  Already present:  {stats['already_present']}\n"
        f"  Downloaded:       {stats['downloaded']}\n"
        f"  Failed:           {stats['failed']}",
        file=sys.stderr,
    )


async def _update_only(args) -> None:
    from pacdoor.updater.manager import UpdateManager
    updater = UpdateManager(offline=False)
    results = await updater.check_all()
    for feed, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"  {feed}: {status}", file=sys.stderr)
    print("Update complete.", file=sys.stderr)


async def _run_diff(args, output_dir: Path) -> None:
    from pacdoor.core.scan_diff import ScanDiff
    from pacdoor.report.generator import ReportGenerator

    old_db_path = Path(args.diff[0])
    new_db_path = Path(args.diff[1])

    if not old_db_path.exists():
        print(f"Error: old database not found: {old_db_path}", file=sys.stderr)
        sys.exit(1)
    if not new_db_path.exists():
        print(f"Error: new database not found: {new_db_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Comparing scans:\n  Old: {old_db_path}\n  New: {new_db_path}", file=sys.stderr)

    diff = ScanDiff(old_db_path, new_db_path)
    result = await diff.compare()

    # Print summary to stderr.
    stats = result.stats
    print("\n" + "=" * 60, file=sys.stderr)
    print("SCAN DIFF SUMMARY", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Hosts added:        {stats.get('hosts_added', 0)}", file=sys.stderr)
    print(f"  Hosts removed:      {stats.get('hosts_removed', 0)}", file=sys.stderr)
    print(f"  Findings fixed:     {stats.get('findings_fixed', 0)}", file=sys.stderr)
    print(f"  Findings new:       {stats.get('findings_new', 0)}", file=sys.stderr)
    print(f"  Findings persistent:{stats.get('findings_persistent', 0)}", file=sys.stderr)
    print(f"  New credentials:    {stats.get('credentials_new', 0)}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Generate diff report.
    gen = ReportGenerator(output_dir=output_dir)
    path = await gen.generate_diff(result)
    print(f"  Diff report: {path}", file=sys.stderr)


async def _run_headless(args, output_dir: Path) -> None:
    from pacdoor.core.engine import Engine

    engine = Engine(
        targets=args.target,
        db_path=output_dir / "pacdoor.db",
        max_concurrency=args.concurrency,
        rate_limit=args.rate_limit,
        max_safety=args.max_safety,
        no_exploit=args.no_exploit,
        recon_only=args.recon_only,
        offline=args.offline,
        timeout=args.timeout,
        exclude=args.exclude,
        ports=args.ports,
        username=args.username,
        password=args.password,
        ntlm_hash=getattr(args, "hash", None),
        domain=args.domain,
        resume=args.resume,
        excluded_modules=getattr(args, "excluded_modules", []),
        module_timeout=getattr(args, "module_timeout", 300),
        scope_file=args.scope_file,
        module_dir=getattr(args, "module_dir", None),
    )

    summary = await engine.run()

    # Print summary to stderr
    print("\n" + "=" * 60, file=sys.stderr)
    print("PACDOOR SCAN COMPLETE", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    for k, v in summary.items():
        if k != "fact_summary":
            print(f"  {k}: {v}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Generate reports (db is closed in engine.run()'s finally block,
    # so we need a fresh connection for reporting)
    from pacdoor.db.database import Database
    from pacdoor.report.generator import ReportGenerator
    report_db = Database(output_dir / "pacdoor.db")
    await report_db.initialize()
    gen = ReportGenerator(report_db, output_dir)
    for fmt in args.report_format:
        path = await gen.generate(fmt)
        print(f"  Report: {path}", file=sys.stderr)
    await report_db.close()


def _run_agent(args) -> None:
    from pacdoor.agent.daemon import start_agent
    config_path = Path(args.agent)
    if not config_path.exists():
        print(f"Error: agent config not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    start_agent(config_path)


def _run_with_tui(args, output_dir: Path) -> None:
    try:
        from pacdoor.tui.app import PacdoorApp
        app = PacdoorApp(args=args, output_dir=output_dir)
        app.run()
    except ImportError:
        print("TUI requires 'textual' package. Install or use --no-tui.", file=sys.stderr)
        asyncio.run(_run_headless(args, output_dir))


if __name__ == "__main__":
    main()
