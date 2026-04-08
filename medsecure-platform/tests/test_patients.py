"""Tests for patient data modules."""

import pytest
from unittest.mock import MagicMock, patch
from src.patients.search import PatientSearchService


class TestPatientSearch:
    """Test patient search functionality."""

    def test_format_patient_result(self):
        """Test patient result formatting."""
        service = PatientSearchService('mongodb://localhost:27017')

        sample_doc = {
            '_id': '507f1f77bcf86cd799439011',
            'medical_record_number': 'MRN-123456',
            'first_name': 'John',
            'last_name': 'Doe',
            'date_of_birth': '1980-05-15',
            'gender': 'M',
            'phone_number': '555-0123',
            'email': 'john.doe@example.com',
            'facility_id': 'FAC-001'
        }

        result = service._format_patient_result(sample_doc)
        assert result['mrn'] == 'MRN-123456'
        assert result['first_name'] == 'John'


class TestSanitizeQueryValue:
    """Test _sanitize_query_value prevents NoSQL injection."""

    def setup_method(self):
        self.service = PatientSearchService('mongodb://localhost:27017')

    def test_valid_string_passes(self):
        """Normal string values should pass sanitization."""
        assert self.service._sanitize_query_value('E11.9') == 'E11.9'
        assert self.service._sanitize_query_value('metformin') == 'metformin'

    def test_empty_string_passes(self):
        """Empty string is a valid string value."""
        assert self.service._sanitize_query_value('') == ''

    def test_rejects_dict_with_ne_operator(self):
        """Dict with $ne operator (common NoSQL injection) must be rejected."""
        with pytest.raises(ValueError, match="Expected string"):
            self.service._sanitize_query_value({'$ne': ''})

    def test_rejects_dict_with_where_operator(self):
        """Dict with $where operator must be rejected."""
        with pytest.raises(ValueError, match="Expected string"):
            self.service._sanitize_query_value({'$where': '1==1'})

    def test_rejects_dict_with_regex_operator(self):
        """Dict with $regex operator must be rejected."""
        with pytest.raises(ValueError, match="Expected string"):
            self.service._sanitize_query_value({'$regex': '.*'})

    def test_rejects_dict_with_gt_operator(self):
        """Dict with $gt operator must be rejected."""
        with pytest.raises(ValueError, match="Expected string"):
            self.service._sanitize_query_value({'$gt': ''})

    def test_rejects_nested_operator_dict(self):
        """Nested dict payloads must be rejected."""
        with pytest.raises(ValueError, match="Expected string"):
            self.service._sanitize_query_value({'$elemMatch': {'$ne': ''}})

    def test_rejects_list_input(self):
        """List input must be rejected."""
        with pytest.raises(ValueError, match="Expected string"):
            self.service._sanitize_query_value(['$ne', ''])

    def test_rejects_int_input(self):
        """Integer input must be rejected."""
        with pytest.raises(ValueError, match="Expected string"):
            self.service._sanitize_query_value(123)

    def test_rejects_string_with_dollar_sign(self):
        """String containing $ character must be rejected."""
        with pytest.raises(ValueError, match="invalid characters"):
            self.service._sanitize_query_value('$ne')

    def test_rejects_string_with_embedded_dollar(self):
        """String with embedded $ must be rejected."""
        with pytest.raises(ValueError, match="invalid characters"):
            self.service._sanitize_query_value('valid$ne')


class TestBuildAdvancedQuery:
    """Test _build_advanced_query with sanitization."""

    def setup_method(self):
        self.service = PatientSearchService('mongodb://localhost:27017')

    def test_valid_diagnosis_query(self):
        """Valid diagnosis string produces correct query."""
        result = self.service._build_advanced_query({'diagnosis': 'E11.9'})
        assert result == {'conditions': {'$elemMatch': {'icd10_code': 'E11.9'}}}

    def test_valid_medication_query(self):
        """Valid medication string produces correct query."""
        result = self.service._build_advanced_query({'medication': 'metformin'})
        assert result == {'medications': {'$elemMatch': {'name': 'metformin'}}}

    def test_diagnosis_injection_dict_rejected(self):
        """Diagnosis with operator dict raises ValueError."""
        with pytest.raises(ValueError):
            self.service._build_advanced_query({'diagnosis': {'$ne': ''}})

    def test_medication_injection_dict_rejected(self):
        """Medication with operator dict raises ValueError."""
        with pytest.raises(ValueError):
            self.service._build_advanced_query({'medication': {'$regex': '.*'}})

    def test_diagnosis_injection_string_rejected(self):
        """Diagnosis string containing $ raises ValueError."""
        with pytest.raises(ValueError):
            self.service._build_advanced_query({'diagnosis': '$where'})


class TestSearchPatientsIntegration:
    """Test that search_patients handles injection attempts gracefully."""

    def setup_method(self):
        self.service = PatientSearchService('mongodb://localhost:27017')

    @patch.object(PatientSearchService, '_log_search')
    def test_injection_returns_empty_results(self, mock_log):
        """Injected operator in diagnosis returns empty list, not an error."""
        result = self.service.search_patients(
            query_params={'diagnosis': {'$ne': ''}},
            facility_id='FAC-001',
            requesting_user_id=42,
        )
        assert result == []

    @patch.object(PatientSearchService, '_log_search')
    def test_injection_in_medication_returns_empty(self, mock_log):
        """Injected operator in medication returns empty list."""
        result = self.service.search_patients(
            query_params={'medication': {'$where': '1==1'}},
            facility_id='FAC-001',
            requesting_user_id=42,
        )
        assert result == []
