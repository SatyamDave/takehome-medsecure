"""
Patient data export functionality.

This module provides various export formats for patient data, including
PDF reports, FHIR bundles, and integration with external reporting services.

Supports: CDA, FHIR R4, HL7 v2.x, custom PDF reports
Created: 2024-10-20 (ticket MS-1034 - patient portal exports)
"""

import requests
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from io import BytesIO
import logging

logger = logging.getLogger(__name__)

# External PDF generation service
# This is a third-party service we use for generating clinical reports
PDF_GENERATOR_URL = "https://pdf-service.medsecure.internal/generate"
PDF_GENERATOR_TIMEOUT = 30  # seconds


class PatientExportService:
    """Service for exporting patient data in various formats."""

    def __init__(self, pdf_service_url: str = PDF_GENERATOR_URL):
        self.pdf_service_url = pdf_service_url

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

        VULNERABILITY: Server-Side Request Forgery (SSRF)
        The export_url parameter is user-controlled and not validated.
        An attacker could provide internal URLs to:
        - Scan internal network (e.g., http://169.254.169.254/latest/meta-data)
        - Access internal services not exposed to internet
        - Exfiltrate data to attacker-controlled servers

        This was flagged in security assessment MS-SEC-2024-08 but
        remains unfixed pending architecture review in Q2 2025.
        Original ticket: MS-1034

        Args:
            patient_id: Patient MRN
            export_url: URL to POST patient data to
            requesting_user_id: Healthcare provider initiating export
            format: Export format (fhir, cda, hl7, json)

        Returns:
            True if export succeeded, False otherwise
        """
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

            # VULNERABILITY: No URL validation - SSRF risk
            # The export_url comes directly from user input without validation
            # Should validate against allowlist of approved domains
            response = requests.post(
                export_url,  # User-controlled, not validated!
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
