"""Tests for webhook HMAC signature verification (SEC-2025-1147)."""

import hmac
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from src.api.webhooks import WebhookProcessor


# Test secret keys
LAB_SECRET = 'test-lab-webhook-secret-key'
PHARMACY_SECRET = 'test-pharmacy-webhook-secret-key'
INSURANCE_SECRET = 'test-insurance-webhook-secret-key'


def _compute_hmac(payload: dict, secret: str) -> str:
    """Helper to compute HMAC-SHA256 signature for a payload."""
    return hmac.new(
        secret.encode('utf-8'),
        json.dumps(payload, separators=(',', ':')).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def _make_request(payload: dict, headers: dict = None) -> MagicMock:
    """Create a mock Flask request with the given payload and headers."""
    request = MagicMock()
    request.get_json.return_value = payload
    header_dict = headers or {}
    request.headers = MagicMock()
    request.headers.get = lambda key, default=None: header_dict.get(key, default)
    return request


class TestVerifyHmac:
    """Test the _verify_hmac method directly."""

    def setup_method(self):
        self.processor = WebhookProcessor(db_connection=MagicMock())
        self.processor.lab_webhook_secret = LAB_SECRET

    def test_valid_signature(self):
        """Valid HMAC signature returns True."""
        payload = {'patient_mrn': 'MRN-001'}
        sig = _compute_hmac(payload, LAB_SECRET)
        assert self.processor._verify_hmac(payload, sig, LAB_SECRET) is True

    def test_invalid_signature(self):
        """Tampered signature returns False."""
        payload = {'patient_mrn': 'MRN-001'}
        assert self.processor._verify_hmac(payload, 'bad-signature', LAB_SECRET) is False

    def test_missing_signature(self):
        """None signature returns False."""
        payload = {'patient_mrn': 'MRN-001'}
        assert self.processor._verify_hmac(payload, None, LAB_SECRET) is False

    def test_empty_signature(self):
        """Empty string signature returns False."""
        payload = {'patient_mrn': 'MRN-001'}
        assert self.processor._verify_hmac(payload, '', LAB_SECRET) is False

    def test_missing_secret(self):
        """Empty secret returns False (secret not configured)."""
        payload = {'patient_mrn': 'MRN-001'}
        assert self.processor._verify_hmac(payload, 'any-sig', '') is False

    def test_tampered_payload(self):
        """Signature computed for original payload fails on tampered payload."""
        original = {'patient_mrn': 'MRN-001', 'value': 'normal'}
        sig = _compute_hmac(original, LAB_SECRET)
        tampered = {'patient_mrn': 'MRN-001', 'value': 'critical'}
        assert self.processor._verify_hmac(tampered, sig, LAB_SECRET) is False

    def test_wrong_secret(self):
        """Signature computed with a different secret returns False."""
        payload = {'patient_mrn': 'MRN-001'}
        sig = _compute_hmac(payload, 'wrong-secret')
        assert self.processor._verify_hmac(payload, sig, LAB_SECRET) is False


class TestLabResultWebhook:
    """Test HMAC verification on the lab result webhook endpoint."""

    def setup_method(self):
        self.processor = WebhookProcessor(db_connection=MagicMock())
        self.processor.lab_webhook_secret = LAB_SECRET

    def _lab_payload(self):
        return {
            'patient_mrn': 'MRN-12345',
            'accession_number': 'ACC-001',
            'results': [
                {
                    'test_code': 'CBC',
                    'test_name': 'Complete Blood Count',
                    'value': '14.2',
                    'unit': 'g/dL',
                    'reference_range': '12.0-17.5',
                    'abnormal_flag': None
                }
            ],
            'lab_name': 'TestLab',
            'result_timestamp': '2025-01-15T10:00:00Z'
        }

    def test_valid_signature_processes_results(self):
        """Lab webhook accepts valid HMAC signature and processes results."""
        payload = self._lab_payload()
        sig = _compute_hmac(payload, LAB_SECRET)
        request = _make_request(payload, {'X-Lab-Signature': sig})
        result = self.processor.process_lab_result_webhook(request)
        assert result['status'] == 'success'
        assert 'Processed 1 lab results' in result['message']

    def test_missing_signature_rejected(self):
        """Lab webhook rejects requests without a signature header."""
        payload = self._lab_payload()
        request = _make_request(payload)
        result = self.processor.process_lab_result_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'

    def test_invalid_signature_rejected(self):
        """Lab webhook rejects requests with an incorrect signature."""
        payload = self._lab_payload()
        request = _make_request(payload, {'X-Lab-Signature': 'forged-signature'})
        result = self.processor.process_lab_result_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'

    def test_no_payload_rejected(self):
        """Lab webhook rejects requests with no JSON body."""
        request = _make_request(None)
        result = self.processor.process_lab_result_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'No JSON payload'

    def test_forged_results_rejected(self):
        """Attacker cannot inject fake results with wrong signature."""
        payload = self._lab_payload()
        # Attacker signs with their own key
        attacker_sig = _compute_hmac(payload, 'attacker-key')
        request = _make_request(payload, {'X-Lab-Signature': attacker_sig})
        result = self.processor.process_lab_result_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'


class TestPharmacyWebhook:
    """Test HMAC verification on the pharmacy webhook endpoint."""

    def setup_method(self):
        self.processor = WebhookProcessor(db_connection=MagicMock())
        self.processor.pharmacy_webhook_secret = PHARMACY_SECRET

    def _pharmacy_payload(self):
        return {
            'prescription_id': 'RX-001',
            'status': 'filled',
            'pharmacy_name': 'TestPharmacy',
            'timestamp': '2025-01-15T10:00:00Z'
        }

    def test_valid_signature_processes_update(self):
        """Pharmacy webhook accepts valid HMAC signature."""
        payload = self._pharmacy_payload()
        sig = _compute_hmac(payload, PHARMACY_SECRET)
        request = _make_request(payload, {'X-Pharmacy-Signature': sig})
        result = self.processor.process_pharmacy_webhook(request)
        assert result['status'] == 'success'
        assert result['prescription_id'] == 'RX-001'

    def test_missing_signature_rejected(self):
        """Pharmacy webhook rejects requests without a signature."""
        payload = self._pharmacy_payload()
        request = _make_request(payload)
        result = self.processor.process_pharmacy_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'

    def test_invalid_signature_rejected(self):
        """Pharmacy webhook rejects requests with incorrect signature."""
        payload = self._pharmacy_payload()
        request = _make_request(payload, {'X-Pharmacy-Signature': 'bad-sig'})
        result = self.processor.process_pharmacy_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'


class TestInsuranceWebhook:
    """Test HMAC verification on the insurance webhook endpoint."""

    def setup_method(self):
        self.processor = WebhookProcessor(db_connection=MagicMock())
        self.processor.insurance_webhook_secret = INSURANCE_SECRET

    def _insurance_payload(self):
        return {
            'auth_request_id': 'AUTH-001',
            'decision': 'approved',
            'plan_name': 'TestPlan'
        }

    def test_valid_signature_processes_decision(self):
        """Insurance webhook accepts valid HMAC signature."""
        payload = self._insurance_payload()
        sig = _compute_hmac(payload, INSURANCE_SECRET)
        request = _make_request(payload, {'X-Insurance-Signature': sig})
        result = self.processor.process_insurance_webhook(request)
        assert result['status'] == 'success'
        assert result['auth_request_id'] == 'AUTH-001'

    def test_missing_signature_rejected(self):
        """Insurance webhook rejects requests without a signature."""
        payload = self._insurance_payload()
        request = _make_request(payload)
        result = self.processor.process_insurance_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'

    def test_invalid_signature_rejected(self):
        """Insurance webhook rejects requests with incorrect signature."""
        payload = self._insurance_payload()
        request = _make_request(payload, {'X-Insurance-Signature': 'bad-sig'})
        result = self.processor.process_insurance_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'


class TestWebhookSecretConfiguration:
    """Test that webhooks fail safely when secrets are not configured."""

    def test_lab_webhook_rejects_when_secret_not_configured(self):
        """Lab webhook rejects all requests when secret env var is missing."""
        processor = WebhookProcessor(db_connection=MagicMock())
        processor.lab_webhook_secret = ''
        payload = {'patient_mrn': 'MRN-001', 'accession_number': 'ACC-001',
                   'results': [{'test_code': 'CBC'}]}
        request = _make_request(payload, {'X-Lab-Signature': 'any-signature'})
        result = processor.process_lab_result_webhook(request)
        assert result['status'] == 'error'
        assert result['message'] == 'Invalid signature'

    def test_pharmacy_webhook_rejects_when_secret_not_configured(self):
        """Pharmacy webhook rejects all requests when secret is missing."""
        processor = WebhookProcessor(db_connection=MagicMock())
        processor.pharmacy_webhook_secret = ''
        payload = {'prescription_id': 'RX-001', 'status': 'filled'}
        request = _make_request(payload, {'X-Pharmacy-Signature': 'any'})
        result = processor.process_pharmacy_webhook(request)
        assert result['status'] == 'error'

    def test_insurance_webhook_rejects_when_secret_not_configured(self):
        """Insurance webhook rejects all requests when secret is missing."""
        processor = WebhookProcessor(db_connection=MagicMock())
        processor.insurance_webhook_secret = ''
        payload = {'auth_request_id': 'AUTH-001', 'decision': 'approved'}
        request = _make_request(payload, {'X-Insurance-Signature': 'any'})
        result = processor.process_insurance_webhook(request)
        assert result['status'] == 'error'
