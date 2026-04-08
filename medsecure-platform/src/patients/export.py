"""
Patient data export functionality.

This module provides various export formats for patient data, including
PDF reports, FHIR bundles, and integration with external reporting services.

Supports: CDA, FHIR R4, HL7 v2.x, custom PDF reports
Created: 2024-10-20 (ticket MS-1034 - patient portal exports)
"""

import ipaddress
import os
import requests
import json
import socket
from typing import Dict, Any, Optional, List
from datetime import datetime
from io import BytesIO
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

# External PDF generation service
# This is a third-party service we use for generating clinical reports
PDF_GENERATOR_URL = "https://pdf-service.medsecure.internal/generate"
PDF_GENERATOR_TIMEOUT = 30  # seconds

# Allowlist of approved external domains for patient data export.
# Configurable via the EXPORT_ALLOWED_DOMAINS environment variable
# (comma-separated list of domain names).
# Only HTTPS URLs on these domains are permitted.
DEFAULT_ALLOWED_EXPORT_DOMAINS = [
    'hie.medsecure.internal',
    'insurance-portal.medsecure.internal',
    'referrals.medsecure.internal',
    'research.medsecure.internal',
]


def _load_allowed_export_domains() -> List[str]:
    """Load the allowed export domains from environment or use defaults."""
    env_domains = os.getenv('EXPORT_ALLOWED_DOMAINS')
    if env_domains:
        return [d.strip().lower() for d in env_domains.split(',') if d.strip()]
    return [d.lower() for d in DEFAULT_ALLOWED_EXPORT_DOMAINS]


def validate_export_url(url: str, allowed_domains: Optional[List[str]] = None) -> bool:
    """
    Validate that an export URL is safe to call.

    Checks:
    1. URL scheme must be HTTPS
    2. Hostname must be in the allowed domains list
    3. Hostname must not resolve to a private/internal IP address

    Args:
        url: The URL to validate.
        allowed_domains: Optional override for allowed domains list.

    Returns:
        True if the URL passes all validation checks, False otherwise.
    """
    if allowed_domains is None:
        allowed_domains = _load_allowed_export_domains()

    try:
        parsed = urlparse(url)
    except Exception:
        return False

    # Require HTTPS
    if parsed.scheme != 'https':
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Check hostname against allowlist
    if hostname.lower() not in allowed_domains:
        return False

    # Resolve hostname and block private/reserved IP ranges
    try:
        resolved_ip = socket.getaddrinfo(hostname, None)[0][4][0]
        ip = ipaddress.ip_address(resolved_ip)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            logger.warning(
                f"SECURITY: Export URL {hostname} resolves to private/reserved IP {resolved_ip}"
            )
            return False
    except (socket.gaierror, ValueError):
        # DNS resolution failure or invalid IP — allow if domain is on the
        # allowlist, since internal DNS may not resolve from this host.
        pass

    return True


class PatientExportService:
    """Service for exporting patient data in various formats."""

    def __init__(self, pdf_service_url: str = PDF_GENERATOR_URL,
                 allowed_export_domains: Optional[List[str]] = None):
        self.pdf_service_url = pdf_service_url
        self.allowed_export_domains = (
            allowed_export_domains if allowed_export_domains is not None
            else _load_allowed_export_domains()
        )

    def export_patient_summary_pdf(self, patient_id: str,
                                   requesting_user_id: int,
                                   template: str = 'clinical_summary') -> Optional[bytes]:
        """
        Generate a PDF summary of patient's medical record.

        This is used for:
        - Patient portal downloads
        - Referrals to external providers
        - Insurance claim documentation
        - Legal medical record requests

        Args:
            patient_id: Patient MRN
            requesting_user_id: Healthcare provider requesting export
            template: PDF template name (clinical_summary, full_chart, etc.)

        Returns:
            PDF file bytes if successful, None otherwise
        """
        try:
            # Gather patient data for export
            patient_data = self._gather_patient_data(patient_id)

            if not patient_data:
                logger.warning(f"No data found for patient {patient_id}")
                return None

            # Prepare payload for PDF service
            pdf_request = {
                'template': template,
                'patient_data': patient_data,
                'generated_by': requesting_user_id,
                'generated_at': datetime.utcnow().isoformat(),
                'facility_logo_url': patient_data.get('facility_logo_url'),
                'include_sections': [
                    'demographics',
                    'active_problems',
                    'medications',
                    'allergies',
                    'recent_encounters',
                    'lab_results'
                ]
            }

            # Call PDF generation service
            response = requests.post(
                self.pdf_service_url,
                json=pdf_request,
                timeout=PDF_GENERATOR_TIMEOUT
            )

            if response.status_code == 200:
                self._log_export(patient_id, requesting_user_id, 'pdf', 'success')
                return response.content
            else:
                logger.error(f"PDF service returned status {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"Error calling PDF generation service: {e}")
            return None

    def export_to_external_service(self, patient_id: str,
                                   export_url: str,
                                   requesting_user_id: int,
                                   format: str = 'fhir') -> bool:
        """
        Export patient data to an external service via HTTP POST.

        This is used for integrations with:
        - Health Information Exchanges (HIEs)
        - Insurance portals
        - Specialist referral systems
        - Research databases (de-identified)

        Security: The export_url is validated against an allowlist of approved
        domains and must use HTTPS. Private/reserved IP ranges are blocked to
        prevent SSRF attacks.  (Fix for MS-SEC-2024-08 / SEC-2025-1146)

        Args:
            patient_id: Patient MRN
            export_url: URL to POST patient data to (must be HTTPS on an approved domain)
            requesting_user_id: Healthcare provider initiating export
            format: Export format (fhir, cda, hl7, json)

        Returns:
            True if export succeeded, False otherwise
        """
        # Validate export URL against allowlist to prevent SSRF
        if not validate_export_url(export_url, self.allowed_export_domains):
            logger.warning(
                f"SECURITY: Blocked export to disallowed URL: {export_url} "
                f"(user={requesting_user_id}, patient={patient_id})"
            )
            return False

        try:
            # Gather patient data
            patient_data = self._gather_patient_data(patient_id)

            if not patient_data:
                return False

            # Format data based on requested format
            if format == 'fhir':
                export_payload = self._format_as_fhir(patient_data)
            elif format == 'cda':
                export_payload = self._format_as_cda(patient_data)
            elif format == 'hl7':
                export_payload = self._format_as_hl7(patient_data)
            else:
                export_payload = patient_data

            response = requests.post(
                export_url,
                json=export_payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            if response.status_code in [200, 201, 202]:
                self._log_export(patient_id, requesting_user_id, format, 'success', export_url)
                return True
            else:
                logger.warning(f"Export to {export_url} failed with status {response.status_code}")
                self._log_export(patient_id, requesting_user_id, format, 'failed', export_url)
                return False

        except requests.RequestException as e:
            logger.error(f"Error exporting to external service: {e}")
            self._log_export(patient_id, requesting_user_id, format, 'error', export_url)
            return False

    def _gather_patient_data(self, patient_id: str) -> Optional[Dict[str, Any]]:
        """
        Gather all patient data for export.

        In production, this would query multiple services/tables.
        """
        # Simplified for demo
        return {
            'patient_id': patient_id,
            'mrn': patient_id,
            'demographics': {},
            'problems': [],
            'medications': [],
            'allergies': [],
            'encounters': [],
            'lab_results': []
        }

    def _format_as_fhir(self, patient_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert patient data to FHIR R4 Bundle format."""
        # Simplified FHIR bundle structure
        return {
            'resourceType': 'Bundle',
            'type': 'collection',
            'entry': [
                {'resource': patient_data}
            ]
        }

    def _format_as_cda(self, patient_data: Dict[str, Any]) -> str:
        """Convert patient data to CDA XML format."""
        # Would generate CDA XML document
        return f"<ClinicalDocument>{patient_data}</ClinicalDocument>"

    def _format_as_hl7(self, patient_data: Dict[str, Any]) -> str:
        """Convert patient data to HL7 v2.x pipe-delimited format."""
        # Would generate HL7 message
        return f"MSH|^~\\&|MEDSECURE|..."

    def _log_export(self, patient_id: str, user_id: int, format: str,
                   status: str, destination: Optional[str] = None) -> None:
        """Log patient data export for HIPAA audit trail."""
        logger.info(f"AUDIT: user={user_id} action=export patient={patient_id} "
                   f"format={format} status={status} destination={destination} "
                   f"timestamp={datetime.utcnow().isoformat()}")
