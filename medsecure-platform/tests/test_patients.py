"""Tests for patient data modules."""

import pytest
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
