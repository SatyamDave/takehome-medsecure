"""Tests for authentication login module - SQL injection fix (SEC-2025-1142)."""

import hashlib
from unittest.mock import patch, MagicMock
import pytest
from src.auth.login import AuthenticationService


# Test database config (not real credentials)
TEST_DB_CONFIG = {
    'host': 'localhost',
    'port': '5432',
    'dbname': 'medsecure_test',
    'user': 'test_user',
    'password': 'test_password',
}


class TestInputValidation:
    """Test input validation for authentication inputs."""

    def setup_method(self):
        self.service = AuthenticationService(TEST_DB_CONFIG)

    def test_validate_input_strips_whitespace(self):
        """Test that input is stripped of leading/trailing whitespace."""
        result = self.service._validate_input("  hello  ", "test_field")
        assert result == "hello"

    def test_validate_input_rejects_empty_string(self):
        """Test that empty strings are rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            self.service._validate_input("", "test_field")

    def test_validate_input_rejects_whitespace_only(self):
        """Test that whitespace-only strings are rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            self.service._validate_input("   ", "test_field")

    def test_validate_input_rejects_exceeding_max_length(self):
        """Test that inputs exceeding max length are rejected."""
        with pytest.raises(ValueError, match="exceeds maximum length"):
            self.service._validate_input("a" * 256, "test_field")

    def test_validate_input_custom_max_length(self):
        """Test custom max length enforcement."""
        with pytest.raises(ValueError, match="exceeds maximum length"):
            self.service._validate_input("a" * 65, "test_field", max_length=64)

    def test_validate_facility_id_valid_formats(self):
        """Test that valid facility IDs are accepted."""
        assert self.service._validate_facility_id("FAC-001") == "FAC-001"
        assert self.service._validate_facility_id("FAC001") == "FAC001"
        assert self.service._validate_facility_id("A") == "A"
        assert self.service._validate_facility_id("facility-123-abc") == "facility-123-abc"

    def test_validate_facility_id_rejects_sql_injection(self):
        """Test that facility IDs containing SQL injection payloads are rejected."""
        with pytest.raises(ValueError, match="Invalid facility_id format"):
            self.service._validate_facility_id("FAC-001' OR '1'='1")

    def test_validate_facility_id_rejects_special_characters(self):
        """Test that facility IDs with special characters are rejected."""
        with pytest.raises(ValueError, match="Invalid facility_id format"):
            self.service._validate_facility_id("FAC;DROP TABLE")

        with pytest.raises(ValueError, match="Invalid facility_id format"):
            self.service._validate_facility_id("FAC' --")

    def test_validate_facility_id_rejects_empty(self):
        """Test that empty facility IDs are rejected."""
        with pytest.raises(ValueError, match="Invalid facility_id format"):
            self.service._validate_facility_id("")


class TestAuthenticateUserParameterizedQuery:
    """Test that authenticate_user uses parameterized queries (not string concatenation)."""

    def setup_method(self):
        self.service = AuthenticationService(TEST_DB_CONFIG)

    @patch.object(AuthenticationService, '_get_connection')
    def test_query_uses_parameterized_format(self, mock_get_conn):
        """Verify the SQL query uses %s placeholders instead of string formatting."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None

        self.service.authenticate_user("testuser", "testpass", "FAC-001")

        # Verify cursor.execute was called with parameterized query
        call_args = mock_cursor.execute.call_args_list[0]
        query = call_args[0][0]
        params = call_args[0][1]

        # The query should use %s placeholders, NOT contain the actual values
        assert "%s" in query
        assert "testuser" not in query
        assert "FAC-001" not in query

        # Parameters should be passed as a tuple
        assert isinstance(params, tuple)
        assert len(params) == 3
        # First param: username, second: password_hash, third: facility_id
        assert params[0] == "testuser"
        assert params[1] == hashlib.md5("testpass".encode()).hexdigest()
        assert params[2] == "FAC-001"

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_username_is_treated_as_literal(self, mock_get_conn):
        """
        Test that SQL injection payloads in username are passed as literal
        parameter values, not interpolated into the query string.
        """
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None

        injection_username = "admin' OR '1'='1' --"
        self.service.authenticate_user(injection_username, "password", "FAC-001")

        call_args = mock_cursor.execute.call_args_list[0]
        query = call_args[0][0]
        params = call_args[0][1]

        # The injection payload must NOT appear in the query string itself
        assert "OR '1'='1'" not in query
        # It should be safely passed as a parameter
        assert params[0] == injection_username

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_facility_id_is_rejected(self, mock_get_conn):
        """Test that SQL injection in facility_id is blocked by input validation."""
        with pytest.raises(ValueError, match="Invalid facility_id format"):
            self.service.authenticate_user(
                "testuser", "testpass", "FAC-001' OR '1'='1"
            )
        # The database should never be contacted
        mock_get_conn.assert_not_called()

    @patch.object(AuthenticationService, '_get_connection')
    def test_successful_authentication_returns_session(self, mock_get_conn):
        """Test successful authentication flow returns user data with session token."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = {
            'user_id': 42,
            'username': 'doctor@example.com',
            'email': 'doctor@example.com',
            'role': 'physician',
            'facility_id': 'FAC-001',
            'last_login': None,
        }

        result = self.service.authenticate_user(
            "doctor@example.com", "securepass", "FAC-001"
        )

        assert result is not None
        assert result['user_id'] == 42
        assert result['username'] == 'doctor@example.com'
        assert result['role'] == 'physician'
        assert result['facility_id'] == 'FAC-001'
        assert 'session_token' in result
        assert 'session_expiry' in result

    @patch.object(AuthenticationService, '_get_connection')
    def test_failed_authentication_returns_none(self, mock_get_conn):
        """Test that failed authentication returns None."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None

        result = self.service.authenticate_user(
            "unknown_user", "wrongpass", "FAC-001"
        )

        assert result is None

    def test_empty_username_raises_error(self):
        """Test that empty username raises ValueError before DB contact."""
        with pytest.raises(ValueError, match="username cannot be empty"):
            self.service.authenticate_user("", "password", "FAC-001")

    def test_empty_password_raises_error(self):
        """Test that empty password raises ValueError before DB contact."""
        with pytest.raises(ValueError, match="password cannot be empty"):
            self.service.authenticate_user("testuser", "", "FAC-001")

    def test_empty_facility_id_raises_error(self):
        """Test that empty facility_id raises ValueError before DB contact."""
        with pytest.raises(ValueError, match="facility_id cannot be empty"):
            self.service.authenticate_user("testuser", "password", "")
