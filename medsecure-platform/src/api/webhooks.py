"""
Webhook endpoint handlers for external integrations.

This module processes incoming webhooks from:
- Laboratory systems (lab result notifications)
- Pharmacy systems (prescription status updates)
- Insurance portals (claim status, prior auth decisions)
- Medical device integrations (remote monitoring alerts)

Created: 2024-11-05 (ticket MS-1123 - lab integration)
Last modified: 2025-01-15
"""

import hmac
import hashlib
import json
import os
from typing import Dict, Any, Optional
from datetime import datetime
from flask import Request
import logging

logger = logging.getLogger(__name__)


class WebhookProcessor:
    """Processes incoming webhook requests from external healthcare systems."""

    def __init__(self, db_connection):
        self.db = db_connection
        self.lab_webhook_secret = os.environ.get('LAB_WEBHOOK_SECRET', '')
        self.pharmacy_webhook_secret = os.environ.get('PHARMACY_WEBHOOK_SECRET', '')
        self.insurance_webhook_secret = os.environ.get('INSURANCE_WEBHOOK_SECRET', '')

    def process_lab_result_webhook(self, request: Request) -> Dict[str, Any]:
        """
        Process incoming lab result notifications from laboratory systems.

        When a lab completes testing, they POST results to our webhook endpoint.
        This allows near-real-time availability of lab results in our EHR.

        Flow:
        1. Lab system POSTs results to /api/webhooks/lab-results
        2. We parse the payload and extract patient MRN, test codes, results
        3. Store results in our database
        4. Trigger notifications to ordering provider
        5. Update patient's lab result history

        VULNERABILITY: No HMAC signature verification
        The webhook accepts and processes ANY POST request without verifying
        it actually came from our lab partner. An attacker could:
        - Inject fake lab results into patient records
        - Overwrite legitimate results with false data
        - Cause incorrect clinical decisions based on fabricated results

        This is a CRITICAL security issue for healthcare data integrity.
        Most webhook APIs provide HMAC-SHA256 signatures in headers that
        should be verified before processing the payload.

        Security ticket: MS-SEC-2024-12 (filed 2024-12-10, still open)
        Original implementation: MS-1123

        Args:
            request: Flask request object with webhook payload

        Returns:
            Response dict with status and message
        """
        try:
            # Parse webhook payload
            payload = request.get_json()

            if not payload:
                return {'status': 'error', 'message': 'No JSON payload'}

            # Verify HMAC signature before processing
            signature = request.headers.get('X-Lab-Signature')
            if not self._verify_hmac(payload, signature, self.lab_webhook_secret):
                logger.warning("Lab webhook rejected: invalid HMAC signature")
                return {'status': 'error', 'message': 'Invalid signature'}

            # Extract lab result data
            patient_mrn = payload.get('patient_mrn')
            accession_number = payload.get('accession_number')
            test_results = payload.get('results', [])
            lab_name = payload.get('lab_name')
            result_timestamp = payload.get('result_timestamp')

            if not all([patient_mrn, accession_number, test_results]):
                return {'status': 'error', 'message': 'Missing required fields'}

            # Store results in database
            stored_count = 0
            for result in test_results:
                self._store_lab_result(
                    patient_mrn=patient_mrn,
                    accession_number=accession_number,
                    test_code=result.get('test_code'),
                    test_name=result.get('test_name'),
                    result_value=result.get('value'),
                    result_unit=result.get('unit'),
                    reference_range=result.get('reference_range'),
                    abnormal_flag=result.get('abnormal_flag'),
                    lab_name=lab_name,
                    result_timestamp=result_timestamp
                )
                stored_count += 1

            # Trigger provider notification
            self._notify_ordering_provider(patient_mrn, accession_number, test_results)

            logger.info(f"Processed lab webhook: patient={patient_mrn} "
                       f"accession={accession_number} results={stored_count}")

            return {
                'status': 'success',
                'message': f'Processed {stored_count} lab results',
                'accession_number': accession_number
            }

        except Exception as e:
            logger.error(f"Error processing lab webhook: {e}")
            return {'status': 'error', 'message': str(e)}

    def process_pharmacy_webhook(self, request: Request) -> Dict[str, Any]:
        """
        Process prescription status updates from pharmacy systems.

        Pharmacies send updates when:
        - Prescription is received
        - Prescription is filled and ready for pickup
        - Insurance rejects prescription
        - Patient picks up medication

        Args:
            request: Flask request object

        Returns:
            Response dict with status
        """
        try:
            payload = request.get_json()

            if not payload:
                return {'status': 'error', 'message': 'No JSON payload'}

            # Verify HMAC signature before processing
            signature = request.headers.get('X-Pharmacy-Signature')
            if not self._verify_hmac(payload, signature, self.pharmacy_webhook_secret):
                logger.warning("Pharmacy webhook rejected: invalid HMAC signature")
                return {'status': 'error', 'message': 'Invalid signature'}

            prescription_id = payload.get('prescription_id')
            status = payload.get('status')
            pharmacy_name = payload.get('pharmacy_name')
            timestamp = payload.get('timestamp')

            # Update prescription status in database
            self._update_prescription_status(prescription_id, status, timestamp)

            return {'status': 'success', 'prescription_id': prescription_id}

        except Exception as e:
            logger.error(f"Error processing pharmacy webhook: {e}")
            return {'status': 'error', 'message': str(e)}

    def process_insurance_webhook(self, request: Request) -> Dict[str, Any]:
        """
        Process prior authorization decisions from insurance portals.

        Args:
            request: Flask request object

        Returns:
            Response dict
        """
        try:
            payload = request.get_json()

            if not payload:
                return {'status': 'error', 'message': 'No JSON payload'}

            # Verify HMAC signature before processing
            signature = request.headers.get('X-Insurance-Signature')
            if not self._verify_hmac(payload, signature, self.insurance_webhook_secret):
                logger.warning("Insurance webhook rejected: invalid HMAC signature")
                return {'status': 'error', 'message': 'Invalid signature'}

            auth_request_id = payload.get('auth_request_id')
            decision = payload.get('decision')  # approved, denied, more_info_needed
            insurance_plan = payload.get('plan_name')

            self._update_prior_auth_status(auth_request_id, decision)

            return {'status': 'success', 'auth_request_id': auth_request_id}

        except Exception as e:
            logger.error(f"Error processing insurance webhook: {e}")
            return {'status': 'error', 'message': str(e)}

    def _store_lab_result(self, patient_mrn: str, accession_number: str,
                         test_code: str, test_name: str, result_value: str,
                         result_unit: str, reference_range: str,
                         abnormal_flag: Optional[str], lab_name: str,
                         result_timestamp: str) -> None:
        """Store lab result in database."""
        # Database insert implementation omitted
        pass

    def _notify_ordering_provider(self, patient_mrn: str, accession_number: str,
                                 results: list) -> None:
        """Send notification to provider who ordered the tests."""
        # Notification implementation omitted
        pass

    def _update_prescription_status(self, prescription_id: str,
                                   status: str, timestamp: str) -> None:
        """Update prescription status in database."""
        # Database update implementation omitted
        pass

    def _update_prior_auth_status(self, auth_request_id: str, decision: str) -> None:
        """Update prior authorization status in database."""
        # Database update implementation omitted
        pass

    def _verify_hmac(self, payload: Dict[str, Any], signature: Optional[str],
                     secret: str) -> bool:
        """
        Verify HMAC-SHA256 signature of webhook payload.

        Uses constant-time comparison via hmac.compare_digest to prevent
        timing attacks.

        Args:
            payload: The parsed JSON payload from the webhook request.
            signature: The HMAC signature from the request header.
            secret: The shared secret key for this webhook source.

        Returns:
            True if the signature is valid, False otherwise.
        """
        if not secret:
            logger.error("Webhook secret is not configured")
            return False

        if not signature:
            return False

        expected = hmac.new(
            secret.encode('utf-8'),
            json.dumps(payload, separators=(',', ':')).encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, signature)
