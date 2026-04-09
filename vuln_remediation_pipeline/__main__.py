"""
CLI entry point for the Vulnerability Remediation Pipeline.

Usage::

    # Dry run (parse & prioritize only, no Devin sessions)
    python -m vuln_remediation_pipeline \
        --sarif report.sarif.json \
        --repo owner/repo \
        --dry-run

    # Full run
    python -m vuln_remediation_pipeline \
        --sarif report.sarif.json \
        --repo owner/repo

    # With options
    python -m vuln_remediation_pipeline \
        --sarif report.sarif.json \
        --repo owner/repo \
        --strategy severity_desc \
        --min-severity 7.0 \
        --exclude py/log-injection \
        --timeout 3600 \
        --output-dir ./reports
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .devin_client import DevinClient, DevinClientConfig
from .pipeline import PipelineConfig, RemediationPipeline
from .prioritizer import Strategy, format_priority_table, prioritize
from .sarif_parser import parse_sarif


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vuln_remediation_pipeline",
        description=(
            "Parse a CodeQL SARIF report, prioritize vulnerabilities, and "
            "resolve them one-by-one using the Devin API."
        ),
    )

    p.add_argument(
        "--sarif",
        required=True,
        help="Path to the SARIF JSON report file.",
    )
    p.add_argument(
        "--repo",
        required=True,
        help="Target repository in owner/repo format.",
    )

    # Prioritization
    p.add_argument(
        "--strategy",
        choices=[s.value for s in Strategy],
        default=Strategy.SEVERITY_DESC.value,
        help="Prioritization strategy (default: severity_desc).",
    )
    p.add_argument(
        "--min-severity",
        type=float,
        default=0.0,
        help="Minimum security-severity score to include (default: 0.0).",
    )
    p.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        metavar="RULE_ID",
        help="Rule IDs to skip (e.g. py/log-injection).",
    )
    p.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable deduplication by rule (process each finding separately).",
    )

    # Session control
    p.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Per-session timeout in seconds (default: 1800).",
    )
    p.add_argument(
        "--max-acu",
        type=int,
        default=None,
        help="Maximum ACU limit per Devin session.",
    )

    # Output
    p.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output reports (default: current directory).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and prioritize only; do not create Devin sessions.",
    )
    p.add_argument(
        "--json-config",
        help="Path to a JSON config file (overrides CLI flags).",
    )

    # Verbosity
    p.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v info, -vv debug).",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Logging
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose >= 1:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Build config
    if args.json_config:
        with open(args.json_config) as f:
            config = PipelineConfig.from_dict(json.load(f))
    else:
        config = PipelineConfig(
            sarif_path=args.sarif,
            repo=args.repo,
            strategy=Strategy(args.strategy),
            deduplicate_by_rule=not args.no_dedup,
            exclude_rules=args.exclude or None,
            min_severity=args.min_severity,
            session_timeout=args.timeout,
            dry_run=args.dry_run,
            output_dir=args.output_dir,
            max_acu_limit=args.max_acu,
        )

    # Show plan
    sarif = parse_sarif(config.sarif_path)
    items = prioritize(
        sarif,
        strategy=config.strategy,
        deduplicate_by_rule=config.deduplicate_by_rule,
        exclude_rules=config.exclude_rules,
        min_severity=config.min_severity,
    )

    print(f"\nSARIF Report: {config.sarif_path}")
    print(f"Repository:   {config.repo}")
    print(f"Strategy:     {config.strategy.value}")
    print(f"Total findings: {sarif.total_count} ({sarif.error_count} errors, {sarif.warning_count} warnings)")
    print(f"Unique rules to remediate: {len(items)}")
    print(f"Mode: {'DRY RUN' if config.dry_run else 'LIVE'}")
    print()
    print(format_priority_table(items))
    print()

    if config.dry_run:
        print("Dry run complete. No Devin sessions created.")
        return 0

    # Run pipeline
    client_config = DevinClientConfig.from_env()
    if not client_config.api_key:
        print("ERROR: DEVIN_API_KEY environment variable is not set.", file=sys.stderr)
        return 1
    if not client_config.org_id:
        print("ERROR: DEVIN_ORG_ID environment variable is not set.", file=sys.stderr)
        return 1

    client = DevinClient(client_config)
    pipeline = RemediationPipeline(config, client=client)
    report = pipeline.run()

    # Summary
    print()
    print(report.to_markdown())
    print()
    print(f"Reports written to: {config.output_dir}/")

    return 0 if report.total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
