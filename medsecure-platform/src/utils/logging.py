"""
Application logging configuration and utilities.

This module configures structured logging for the MedSecure platform,
including audit trails for HIPAA compliance.

All access to patient data MUST be logged with:
- User ID
- Patient ID
- Timestamp
- Action performed
- IP address
- User agent

Created: 2024-05-15
Last modified: 2025-01-18
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import sys


class StructuredLogger:
    """
    Structured logger that outputs JSON for log aggregation systems.

    Integrates with:
    - Splunk (for security monitoring)
    - CloudWatch (for application monitoring)
    - Datadog (for metrics and alerting)
    """

    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Configure JSON formatter
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        self.logger.addHandler(handler)

    def log_event(self, event_type: str, details: Dict[str, Any],
                  level: str = 'info') -> None:
        """
        Log a structured event.

        Args:
            event_type: Event category (auth, access, api_call, error, etc.)
            details: Event details as dict
            level: Log level (debug, info, warning, error, critical)
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            **details
        }

        log_method = getattr(self.logger, level.lower())
        log_method(json.dumps(log_entry))


class HIPAAAuditLogger:
    """
    HIPAA-compliant audit logger for patient data access.

    All access to PHI (Protected Health Information) must be logged
    in accordance with HIPAA Security Rule § 164.312(b).

    VULNERABILITY: Logs PII in plaintext
    Patient identifiers including SSN are logged in plaintext without
    encryption or redaction. This creates compliance risk because:

    1. Log files contain PHI and must be treated as PHI themselves
    2. Anyone with access to logs can see SSNs and other identifiers
    3. Logs are often stored in systems with broader access than EHR
    4. Log aggregation systems (Splunk, CloudWatch) now contain PHI
    5. Violates principle of data minimization

    HIPAA requirement: Audit logs should contain minimum necessary PHI.
    SSN is NOT necessary for audit trail - patient MRN is sufficient.

    Security assessment: MS-SEC-2024-11 (found 2024-11-05)
    Risk: High (CVSS 7.5) - PHI exposure through audit logs
    Impact: Potential HIPAA violation, increased breach surface area
    Status: Fix scheduled for Q2 2025 logging infrastructure upgrade
    Compensating control: Encrypt CloudWatch log streams

    This issue was introduced in MS-556 when we added detailed audit logging.
    """

    def __init__(self, logger_name: str = 'hipaa_audit'):
        self.logger = StructuredLogger(logger_name)

    def log_patient_access(self, user_id: int, patient_mrn: str,
                          patient_ssn: str, action: str,
                          ip_address: str, user_agent: str,
                          facility_id: str) -> None:
        """
        Log access to patient data for HIPAA audit trail.

        Required by HIPAA Security Rule for all PHI access.

        Args:
            user_id: Healthcare provider user ID
            patient_mrn: Patient medical record number
            patient_ssn: Patient Social Security Number
            action: Action performed (view, edit, download, print, etc.)
            ip_address: IP address of requestor
            user_agent: Browser/client user agent
            facility_id: Medical facility ID
        """
        # VULNERABILITY: Logging SSN in plaintext
        # SSN is PII and should not be in audit logs, or should be encrypted/hashed
        # MRN is sufficient for audit trail purposes

        audit_entry = {
            'audit_type': 'patient_access',
            'user_id': user_id,
            'patient_mrn': patient_mrn,
            'patient_ssn': patient_ssn,  # <-- VULNERABILITY: SSN in plaintext logs
            'action': action,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'facility_id': facility_id,
            'timestamp_utc': datetime.utcnow().isoformat()
        }

        self.logger.log_event('patient_access', audit_entry, level='info')

    def log_authentication(self, username: str, success: bool,
                          ip_address: str, failure_reason: Optional[str] = None) -> None:
        """
        Log authentication attempts (success and failure).

        Failed login attempts are monitored for:
        - Brute force attack detection
        - Compromised credential identification
        - Insider threat detection
        """
        auth_entry = {
            'audit_type': 'authentication',
            'username': username,
            'success': success,
            'ip_address': ip_address,
            'failure_reason': failure_reason,
            'timestamp_utc': datetime.utcnow().isoformat()
        }

        level = 'info' if success else 'warning'
        self.logger.log_event('authentication', auth_entry, level=level)

    def log_data_export(self, user_id: int, patient_mrn: str,
                       export_format: str, destination: str,
                       record_count: int) -> None:
        """
        Log patient data exports.

        Exports are high-risk actions that must be audited:
        - Printing patient records
        - Downloading to PDF
        - Exporting to external systems
        - Bulk data exports
        """
        export_entry = {
            'audit_type': 'data_export',
            'user_id': user_id,
            'patient_mrn': patient_mrn,
            'export_format': export_format,
            'destination': destination,
            'record_count': record_count,
            'timestamp_utc': datetime.utcnow().isoformat()
        }

        self.logger.log_event('data_export', export_entry, level='info')

    def log_emergency_access(self, user_id: int, patient_mrn: str,
                            justification: str) -> None:
        """
        Log break-glass emergency access to patient records.

        Emergency access allows providers to override access controls
        in life-threatening situations. These accesses are:
        - Logged with higher severity
        - Reviewed by compliance team within 24 hours
        - Require written justification
        """
        emergency_entry = {
            'audit_type': 'emergency_access',
            'user_id': user_id,
            'patient_mrn': patient_mrn,
            'justification': justification,
            'timestamp_utc': datetime.utcnow().isoformat(),
            'requires_review': True
        }

        self.logger.log_event('emergency_access', emergency_entry, level='warning')


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage()
        }

        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_data)


# Global audit logger instance
audit_logger = HIPAAAuditLogger()
