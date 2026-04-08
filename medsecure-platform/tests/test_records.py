"""Tests for patient record service path traversal fix (SEC-2025-1144)."""

import os
import tempfile
import pytest
from src.patients.records import PatientRecordService


class TestPatientRecordPathValidation:
    """Test path traversal prevention in patient document retrieval."""

    def setup_method(self):
        """Set up a temporary directory structure mimicking patient records."""
        self.temp_dir = tempfile.mkdtemp()

        # Create patient directory with a test document
        patient_dir = os.path.join(self.temp_dir, 'MRN-123456', 'labs')
        os.makedirs(patient_dir, exist_ok=True)

        self.test_file = os.path.join(patient_dir, 'cbc-2024-01-15.pdf')
        with open(self.test_file, 'w') as f:
            f.write('test lab results content')

        # Create a sensitive file outside the patient directory
        self.secret_file = os.path.join(self.temp_dir, 'secret.txt')
        with open(self.secret_file, 'w') as f:
            f.write('sensitive data')

        # Create another patient's directory with a document
        other_patient_dir = os.path.join(self.temp_dir, 'MRN-999999', 'labs')
        os.makedirs(other_patient_dir, exist_ok=True)
        with open(os.path.join(other_patient_dir, 'private.pdf'), 'w') as f:
            f.write('other patient data')

        self.service = PatientRecordService(base_path=self.temp_dir)

    def teardown_method(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --- Legitimate access tests ---

    def test_download_valid_document(self):
        """Test that legitimate document paths still work correctly."""
        result = self.service.download_patient_document(
            'MRN-123456', 'labs/cbc-2024-01-15.pdf', requesting_user_id=42
        )
        assert result is not None
        content = result.read()
        result.close()
        assert content == b'test lab results content'

    def test_get_metadata_valid_document(self):
        """Test that metadata retrieval works for legitimate paths."""
        result = self.service.get_document_metadata(
            'MRN-123456', 'labs/cbc-2024-01-15.pdf'
        )
        assert result is not None
        assert result['file_name'] == 'cbc-2024-01-15.pdf'
        assert result['file_size_bytes'] > 0

    # --- Path traversal attack tests ---

    def test_download_blocks_parent_directory_traversal(self):
        """Test that '../' sequences are blocked in download."""
        result = self.service.download_patient_document(
            'MRN-123456', '../secret.txt', requesting_user_id=42
        )
        assert result is None

    def test_download_blocks_deep_traversal(self):
        """Test that deeply nested '../' traversal is blocked."""
        result = self.service.download_patient_document(
            'MRN-123456', '../../../../../../etc/passwd', requesting_user_id=42
        )
        assert result is None

    def test_download_blocks_access_to_other_patient(self):
        """Test that accessing another patient's records via traversal is blocked."""
        result = self.service.download_patient_document(
            'MRN-123456', '../MRN-999999/labs/private.pdf', requesting_user_id=42
        )
        assert result is None

    def test_metadata_blocks_parent_directory_traversal(self):
        """Test that '../' sequences are blocked in metadata retrieval."""
        result = self.service.get_document_metadata(
            'MRN-123456', '../secret.txt'
        )
        assert result is None

    def test_metadata_blocks_deep_traversal(self):
        """Test that deeply nested '../' traversal is blocked in metadata."""
        result = self.service.get_document_metadata(
            'MRN-123456', '../../../../../../etc/passwd'
        )
        assert result is None

    def test_metadata_blocks_access_to_other_patient(self):
        """Test that accessing another patient's metadata via traversal is blocked."""
        result = self.service.get_document_metadata(
            'MRN-123456', '../MRN-999999/labs/private.pdf'
        )
        assert result is None

    def test_download_blocks_encoded_traversal(self):
        """Test that path traversal with mixed separators is blocked."""
        result = self.service.download_patient_document(
            'MRN-123456', 'labs/../../secret.txt', requesting_user_id=42
        )
        assert result is None

    def test_download_nonexistent_file_returns_none(self):
        """Test that requesting a nonexistent (but safe) path returns None."""
        result = self.service.download_patient_document(
            'MRN-123456', 'labs/nonexistent.pdf', requesting_user_id=42
        )
        assert result is None

    # --- Path validation helper tests ---

    def test_resolve_and_validate_path_allows_valid(self):
        """Test that _resolve_and_validate_path allows safe paths."""
        result = self.service._resolve_and_validate_path(
            'MRN-123456', 'labs/cbc-2024-01-15.pdf'
        )
        assert result is not None
        assert str(result).endswith('labs/cbc-2024-01-15.pdf')

    def test_resolve_and_validate_path_blocks_traversal(self):
        """Test that _resolve_and_validate_path rejects '../' paths."""
        result = self.service._resolve_and_validate_path(
            'MRN-123456', '../secret.txt'
        )
        assert result is None

    def test_resolve_and_validate_path_blocks_absolute_path(self):
        """Test that absolute paths in document_path are handled safely."""
        result = self.service._resolve_and_validate_path(
            'MRN-123456', '/etc/passwd'
        )
        assert result is None

    # --- Patient ID traversal attack tests (SEC-2025-1144) ---

    def test_download_blocks_traversal_in_patient_id(self):
        """Test that '../' sequences in patient_id are blocked."""
        result = self.service.download_patient_document(
            '../../../etc', 'passwd', requesting_user_id=42
        )
        assert result is None

    def test_download_blocks_patient_id_with_path_separator(self):
        """Test that patient_id containing '/' is blocked."""
        result = self.service.download_patient_document(
            'MRN-123456/../MRN-999999', 'labs/private.pdf', requesting_user_id=42
        )
        assert result is None

    def test_metadata_blocks_traversal_in_patient_id(self):
        """Test that '../' sequences in patient_id are blocked for metadata."""
        result = self.service.get_document_metadata(
            '../../../etc', 'passwd'
        )
        assert result is None

    def test_validate_path_blocks_traversal_in_patient_id(self):
        """Test that _resolve_and_validate_path rejects traversal in patient_id."""
        result = self.service._resolve_and_validate_path(
            '../../../etc', 'passwd'
        )
        assert result is None

    def test_validate_path_blocks_dotdot_patient_id(self):
        """Test that patient_id of '..' is rejected."""
        result = self.service._resolve_and_validate_path(
            '..', 'secret.txt'
        )
        assert result is None

    def test_validate_path_blocks_empty_patient_id(self):
        """Test that empty patient_id is rejected."""
        result = self.service._resolve_and_validate_path(
            '', 'labs/cbc.pdf'
        )
        assert result is None

    def test_validate_path_blocks_null_byte_in_patient_id(self):
        """Test that null bytes in patient_id are rejected."""
        result = self.service._resolve_and_validate_path(
            'MRN-123456\x00', 'labs/cbc.pdf'
        )
        assert result is None

    def test_validate_path_blocks_null_byte_in_document_path(self):
        """Test that null bytes in document_path are rejected."""
        result = self.service._resolve_and_validate_path(
            'MRN-123456', 'labs/cbc.pdf\x00.html'
        )
        assert result is None

    def test_validate_patient_id_allows_valid_mrn(self):
        """Test that valid MRN formats are accepted."""
        assert PatientRecordService._validate_patient_id('MRN-123456') is True
        assert PatientRecordService._validate_patient_id('PAT_001') is True
        assert PatientRecordService._validate_patient_id('abc123') is True

    def test_validate_patient_id_rejects_traversal(self):
        """Test that traversal sequences in patient_id are rejected."""
        assert PatientRecordService._validate_patient_id('../etc') is False
        assert PatientRecordService._validate_patient_id('..') is False
        assert PatientRecordService._validate_patient_id('.') is False
        assert PatientRecordService._validate_patient_id('foo/bar') is False
        assert PatientRecordService._validate_patient_id('') is False
