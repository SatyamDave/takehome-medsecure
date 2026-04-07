"""
Slack Notification Module

Provides Slack webhook integration for SecureLoop pipeline notifications.
Sends alerts for:
- New security issue processed
- PR opened
- Needs human review
- Pipeline completion

Author: SecureLoop Team
Version: 1.0.0
"""

import os
import logging
from typing import Optional
from datetime import datetime
import requests

logger = logging.getLogger(__name__)


class SlackNotifier:
    """
    Slack notification handler for SecureLoop pipeline events.
    """

    DEFAULT_COLOR = "#36a64f"
    COLORS = {
        "info": "#36a64f",
        "warning": "#ff9800",
        "error": "#dc3545",
        "critical": "#dc3545",
        "success": "#36a64f",
    }

    def __init__(self, webhook_url: Optional[str] = None):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL (from SLACK_WEBHOOK_URL env var if not provided)
        """
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.enabled = bool(self.webhook_url)

        if not self.enabled:
            logger.info("Slack notifications disabled (no webhook URL)")

    def send(
        self, message: str, severity: str = "info", fields: Optional[dict] = None
    ) -> bool:
        """
        Send a Slack notification.

        Args:
            message: Main message text
            severity: Severity level (info, warning, error, critical)
            fields: Additional fields for the message

        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            logger.info(f"[Slack Mock] {message}")
            return False

        emoji = {
            "info": ":information_source:",
            "warning": ":warning:",
            "error": ":x:",
            "critical": ":rotating_light:",
            "success": ":white_check_mark:",
        }.get(severity, ":information_source:")

        payload = {
            "text": f"{emoji} SecureLoop: {message}",
            "attachments": [
                {
                    "color": self.COLORS.get(severity, self.DEFAULT_COLOR),
                    "timestamp": int(datetime.utcnow().timestamp()),
                    "fields": [
                        {"title": k, "value": str(v), "short": True}
                        for k, v in (fields or {}).items()
                    ],
                }
            ],
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)

            if response.status_code == 200:
                logger.info(f"Slack notification sent: {message}")
                return True
            else:
                logger.error(f"Slack API error: {response.status_code}")
                return False

        except requests.RequestException as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    def notify_issue_received(self, issue_id: str, title: str, severity: str) -> bool:
        """Notify when a new issue is received for processing."""
        return self.send(
            f"[{severity.upper()}] New finding: {issue_id}",
            severity=severity,
            fields={
                "Finding": issue_id,
                "Description": title[:48] + "..." if len(title) > 48 else title,
                "Classification": severity.upper(),
            },
        )

    def notify_remediation_started(self, issue_id: str, session_id: str) -> bool:
        """Notify when remediation has started."""
        return self.send(
            f"Auto-remediation initiated for {issue_id}",
            severity="info",
            fields={"Finding": issue_id, "Devin Session": session_id[:20] + "..."},
        )

    def notify_pr_created(self, issue_id: str, pr_url: str, severity: str) -> bool:
        """Notify when a PR is created."""
        return self.send(
            f"[{severity.upper()}] PR ready for review: {issue_id}",
            severity="success",
            fields={"Finding": issue_id, "PR": f"<{pr_url}|View Pull Request>"},
        )

    def notify_needs_human(self, issue_id: str, reason: str) -> bool:
        """Notify when an issue needs human review."""
        return self.send(
            f"[ESCALATION] Manual review required: {issue_id}",
            severity="warning",
            fields={"Finding": issue_id, "Reason": reason},
        )

    def notify_pipeline_complete(self, total: int, fixed: int, failed: int) -> bool:
        """Notify when pipeline run completes."""
        status = "success" if failed == 0 else "warning"
        return self.send(
            f"Remediation cycle complete: {fixed}/{total} resolved",
            severity=status,
            fields={
                "Findings Processed": total,
                "Auto-Remediated": fixed,
                "Requires Review": failed,
                "Resolution Rate": f"{(fixed / total * 100):.0f}%"
                if total > 0
                else "N/A",
            },
        )

    def notify_error(self, context: str, error: str) -> bool:
        """Notify on pipeline errors."""
        return self.send(
            f"[ALERT] Remediation pipeline error",
            severity="error",
            fields={"Component": context, "Error": error[:100]},
        )


def main():
    """Test Slack notifications."""
    import argparse

    parser = argparse.ArgumentParser(description="Test Slack notifications")
    parser.add_argument("--message", type=str, required=True, help="Test message")
    parser.add_argument(
        "--severity",
        type=str,
        default="info",
        choices=["info", "warning", "error", "critical"],
    )

    args = parser.parse_args()

    notifier = SlackNotifier()
    result = notifier.send(args.message, severity=args.severity)

    print(f"Sent: {result}")


if __name__ == "__main__":
    main()
