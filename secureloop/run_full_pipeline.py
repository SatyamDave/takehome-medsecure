"""
Full Pipeline Runner

This script runs the complete SecureLoop remediation pipeline, processing all
security issues through Devin AI for automated remediation.

Usage:
    python run_full_pipeline.py [--limit N] [--dry-run] [--issue-ids ID1 ID2...]

Author: SecureLoop Team
Version: 1.0.0
"""

import sys
import os
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from orchestrator import Orchestrator, PipelineState


def print_banner():
    print("=" * 70)
    print(
        "  ██████╗ ███████╗████████╗██████╗  ██████╗ ██████╗  ██████╗  █████╗ ██████╗ ██████╗ "
    )
    print(
        "  ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔══██╗"
    )
    print(
        "  ██████╔╝█████╗     ██║   ██████╔╝██║   ██║██████╔╝██║   ██║███████║██████╔╝██║  ██║"
    )
    print(
        "  ██╔══██╗██╔══╝     ██║   ██╔══██╗██║   ██║██╔══██╗██║   ██║██╔══██║██╔══██╗██║  ██║"
    )
    print(
        "  ██║  ██║███████╗   ██║   ██║  ██║╚██████╔╝██║  ██║╚██████╔╝██║  ██║██║  ██║██████╔╝"
    )
    print(
        "  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    )
    print("=" * 70)
    print("  Automated Security Remediation Pipeline")
    print("=" * 70)


def print_state(state: PipelineState):
    """Print current pipeline state."""
    m = state.metrics
    print("\n" + "=" * 50)
    print("  PIPELINE METRICS")
    print("=" * 50)
    print(f"  Total Issues:    {m['total_issues']}")
    print(f"  Fixed:           {m['fixed']}")
    print(f"  Pending:         {m['pending']}")
    print(f"  In Progress:     {m['in_progress']}")
    print(f"  MTTR:            {m['mean_time_to_remediation_hours']:.1f} hours")
    print()
    print("  Severity Breakdown:")
    for sev, count in m["severity_breakdown"].items():
        print(f"    {sev.upper()}: {count}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Run full SecureLoop remediation pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_full_pipeline.py                    # Process all issues
  python run_full_pipeline.py --limit 3          # Process first 3 issues
  python run_full_pipeline.py --dry-run          # Test without API calls
  python run_full_pipeline.py --issue-ids MS-SEC-2025-001 MS-SEC-2025-002
        """,
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="Maximum number of issues to process"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run pipeline without calling Devin API (for testing)",
    )
    parser.add_argument(
        "--issue-ids",
        nargs="+",
        help="Specific issue IDs to process (default: all unprocessed)",
    )
    print_banner()
    print(f"\nStarted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if args.dry_run:
        orchestrator.dry_run = True
        print("\n*** DRY RUN MODE - No API calls will be made ***\n")

    print("Loading current state...")
    current_state = orchestrator.load_state()
    print_state(current_state)

    print("\nStarting pipeline...")
    start_time = datetime.now()

    final_state = orchestrator.run_pipeline(issue_ids=args.issue_ids, limit=args.limit)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("\n" + "=" * 70)
    print("  PIPELINE COMPLETE")
    print("=" * 70)
    print(f"  Duration: {duration:.1f} seconds")
    print(f"  Issues processed: {len(final_state.sessions)}")
    print_state(final_state)
    print("=" * 70)

    print("\nSession Details:")
    for session in final_state.sessions:
        status_icon = {
            "completed": "✓",
            "pending": "⏳",
            "failed": "✗",
            "needs_review": "⚠",
        }.get(session.status, "?")

        pr_info = f" PR: {session.pr_url}" if session.pr_url else ""
        print(f"  {status_icon} {session.issue_id}: {session.status}{pr_info}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
