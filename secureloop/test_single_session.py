"""
Test Script: Single Session

This script sends ONE issue to Devin for debugging/testing purposes.
Use this to test the pipeline with a single issue before running the full flow.

Usage:
    python test_single_session.py [--issue-id ISSUE_ID] [--dry-run]

Author: SecureLoop Team
Version: 1.0.0
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from orchestrator import Orchestrator


def main():
    parser = argparse.ArgumentParser(description="Test single Devin session")
    parser.add_argument("--issue-id", type=str, help="Specific issue ID to test")
    parser.add_argument(
        "--dry-run", action="store_true", help="Run without calling Devin API"
    )
    parser.add_argument(
        "--limit", type=int, default=1, help="Number of issues to process"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("SecureLoop - Single Session Test")
    print("=" * 60)

    if args.dry_run:
        print("\n*** DRY RUN MODE ***\n")

    orchestrator = Orchestrator()

    issue_ids = [args.issue_id] if args.issue_id else None

    print(f"Loading issues...")
    issues = orchestrator.load_issues()

    if not issues:
        print("ERROR: No issues found")
        return 1

    if issue_ids:
        issues_to_process = [i for i in issues if i["id"] in issue_ids]
    else:
        issues_to_process = issues[: args.limit]

    print(f"Found {len(issues_to_process)} issue(s) to process\n")

    for issue in issues_to_process:
        print(f"Issue: {issue['id']}")
        print(f"  Title: {issue['title']}")
        print(f"  Severity: {issue['severity']}")
        print(f"  CWE: {issue['cwe']}")
        print(f"  File: {issue['file_path']}")
        print(f"  Lines: {issue['line_range']}")

        complexity = orchestrator.classify_issue(issue)
        print(f"  Complexity: {complexity.value}")

        print(f"\nGenerating prompt...")
        prompt = orchestrator.prompt_generator.generate_fix_prompt(issue)
        print(f"  Prompt length: {len(prompt)} characters")

        if args.dry_run:
            print(f"\n[DRY RUN] Would send to Devin API")
            print(f"  Session would be created")
            print(f"  Would poll for completion")
            result = orchestrator.send_to_devin(issue)
        else:
            print(f"\nSending to Devin...")
            result = orchestrator.send_to_devin(issue)

            if not result:
                print(f"  ERROR: Failed to create session")
                continue

            print(f"  Session ID: {result.session_id}")
            print(f"  Status: {result.status}")

            print(f"\nPolling for completion...")
            status = orchestrator.poll_session(result.session_id)

            print(f"  Final status: {status.get('status')}")
            print(f"  PR URL: {status.get('pr_url', 'N/A')}")

        print("\n" + "-" * 60)

    print("\nTest complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
