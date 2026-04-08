"""Tests for patient data export SSRF protection."""

import pytest
from unittest.mock import patch, MagicMock

from src.patients.export import (
    PatientExportService,
    validate_export_url,
    _load_allowed_export_domains,
    DEFAULT_ALLOWED_EXPORT_DOMAINS,
)

ALLOWED_DOMAINS = ['hie.medsecure.internal', 'insurance-portal.medsecure.internal']


class TestValidateExportUrl:
    """Test URL validation logic that prevents SSRF."""

    def test_allows_https_url_on_allowlisted_domain(self):
        url = 'https://hie.medsecure.internal/api/import'
        assert validate_export_url(url, ALLOWED_DOMAINS) is True

    def test_rejects_http_url(self):
        """HTTP is not allowed — only HTTPS."""
        url = 'http://hie.medsecure.internal/api/import'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_non_allowlisted_domain(self):
        url = 'https://evil-server.example.com/steal'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_cloud_metadata_endpoint(self):
        """Block AWS metadata endpoint (classic SSRF target)."""
        url = 'https://169.254.169.254/latest/meta-data'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_localhost(self):
        url = 'https://localhost/internal'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_loopback_ip(self):
        url = 'https://127.0.0.1/internal'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_private_ip(self):
        url = 'https://10.0.0.1/internal'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_empty_url(self):
        assert validate_export_url('', ALLOWED_DOMAINS) is False

    def test_rejects_url_without_scheme(self):
        url = 'hie.medsecure.internal/api/import'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_ftp_scheme(self):
        url = 'ftp://hie.medsecure.internal/data'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_rejects_file_scheme(self):
        url = 'file:///etc/passwd'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    def test_allows_url_with_path_and_query(self):
        url = 'https://hie.medsecure.internal/api/v2/import?format=fhir'
        assert validate_export_url(url, ALLOWED_DOMAINS) is True

    def test_case_insensitive_domain_check(self):
        url = 'https://HIE.MEDSECURE.INTERNAL/api/import'
        assert validate_export_url(url, ALLOWED_DOMAINS) is True

    @patch('src.patients.export.socket.getaddrinfo')
    def test_rejects_allowlisted_domain_resolving_to_private_ip(self, mock_getaddrinfo):
        """Even if on the allowlist, block if DNS resolves to a private IP."""
        mock_getaddrinfo.return_value = [(None, None, None, None, ('127.0.0.1', 0))]
        url = 'https://hie.medsecure.internal/api/import'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False

    @patch('src.patients.export.socket.getaddrinfo')
    def test_rejects_link_local_ip(self, mock_getaddrinfo):
        """Block link-local addresses (169.254.x.x) even on allowlisted domains."""
        mock_getaddrinfo.return_value = [(None, None, None, None, ('169.254.169.254', 0))]
        url = 'https://hie.medsecure.internal/api/import'
        assert validate_export_url(url, ALLOWED_DOMAINS) is False


class TestLoadAllowedExportDomains:
    """Test domain allowlist loading from environment."""

    def test_returns_defaults_when_env_not_set(self):
        with patch.dict('os.environ', {}, clear=True):
            domains = _load_allowed_export_domains()
            assert domains == [d.lower() for d in DEFAULT_ALLOWED_EXPORT_DOMAINS]

    def test_loads_from_environment_variable(self):
        with patch.dict('os.environ', {'EXPORT_ALLOWED_DOMAINS': 'a.example.com,b.example.com'}):
            domains = _load_allowed_export_domains()
            assert domains == ['a.example.com', 'b.example.com']

    def test_strips_whitespace_from_env(self):
        with patch.dict('os.environ', {'EXPORT_ALLOWED_DOMAINS': ' a.example.com , b.example.com '}):
            domains = _load_allowed_export_domains()
            assert domains == ['a.example.com', 'b.example.com']

    def test_lowercases_env_domains(self):
        with patch.dict('os.environ', {'EXPORT_ALLOWED_DOMAINS': 'A.EXAMPLE.COM'}):
            domains = _load_allowed_export_domains()
            assert domains == ['a.example.com']


class TestExportToExternalService:
    """Test that export_to_external_service enforces URL validation."""

    def setup_method(self):
        self.service = PatientExportService(
            allowed_export_domains=['hie.medsecure.internal']
        )

    @patch('src.patients.export.requests.post')
    def test_blocks_non_allowlisted_url(self, mock_post):
        """Export to a non-allowlisted URL must be rejected without making a request."""
        result = self.service.export_to_external_service(
            patient_id='MRN-001',
            export_url='https://evil.example.com/steal',
            requesting_user_id=42,
        )
        assert result is False
        mock_post.assert_not_called()

    @patch('src.patients.export.requests.post')
    def test_blocks_http_url(self, mock_post):
        """HTTP URLs must be rejected."""
        result = self.service.export_to_external_service(
            patient_id='MRN-001',
            export_url='http://hie.medsecure.internal/api/import',
            requesting_user_id=42,
        )
        assert result is False
        mock_post.assert_not_called()

    @patch('src.patients.export.requests.post')
    def test_blocks_cloud_metadata_url(self, mock_post):
        """Cloud metadata SSRF vector must be blocked."""
        result = self.service.export_to_external_service(
            patient_id='MRN-001',
            export_url='http://169.254.169.254/latest/meta-data',
            requesting_user_id=42,
        )
        assert result is False
        mock_post.assert_not_called()

    @patch('src.patients.export.requests.post')
    def test_allows_valid_allowlisted_url(self, mock_post):
        """A valid HTTPS URL on an allowlisted domain should proceed."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = self.service.export_to_external_service(
            patient_id='MRN-001',
            export_url='https://hie.medsecure.internal/api/import',
            requesting_user_id=42,
        )
        assert result is True
        mock_post.assert_called_once()

    @patch('src.patients.export.requests.post')
    def test_blocks_internal_localhost(self, mock_post):
        """Localhost URLs must be rejected."""
        result = self.service.export_to_external_service(
            patient_id='MRN-001',
            export_url='https://localhost:8080/admin',
            requesting_user_id=42,
        )
        assert result is False
        mock_post.assert_not_called()

    @patch('src.patients.export.requests.post')
    def test_blocks_private_network_ip(self, mock_post):
        """Private network IPs must be rejected."""
        result = self.service.export_to_external_service(
            patient_id='MRN-001',
            export_url='https://10.0.0.5/internal-api',
            requesting_user_id=42,
        )
        assert result is False
        mock_post.assert_not_called()
