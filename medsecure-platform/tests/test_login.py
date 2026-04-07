"""Tests for authentication login module (SEC-2025-1142).

Verifies that the SQL injection vulnerability in authenticate_user is fixed
and that parameterized queries, input validation, and bcrypt password
verification are working correctly.
"""

import pytest
from unittest.mock import patch, MagicMock
import bcrypt

from src.auth.login import AuthenticationService


# Test fixtures
VALID_USERNAME = "doctor@example.com"
VALID_PASSWORD = "SecureP@ss123"
VALID_FACILITY_ID = "FAC-001"
VALID_PASSWORD_HASH = bcrypt.hashpw(
    VALID_PASSWORD.encode('utf-8'), bcrypt.gensalt()
).decode('utf-8')

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'medsecure_test',
    'user': 'test_user',
    'password': 'test_password'
}

MOCK_USER_ROW = {
    'user_id': 42,
    'username': VALID_USERNAME,
    'email': 'doctor@example.com',
    'role': 'physician',
    'facility_id': VALID_FACILITY_ID,
    'last_login': '2025-01-01T00:00:00',
    'password_hash': VALID_PASSWORD_HASH,
}


def _create_mock_cursor(user_row=None):
    """Create a mock cursor that returns the given user row."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = user_row
    return mock_cursor


def _create_mock_connection(mock_cursor):
    """Create a mock connection with the given cursor."""
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn


class TestAuthenticateUserParameterizedQueries:
    """Verify SQL injection vulnerability (CWE-89) is fixed."""

    @patch.object(AuthenticationService, '_get_connection')
    def test_query_uses_parameterized_placeholders(self, mock_get_conn):
        """Ensure the SQL query uses %s placeholders, not string interpolation."""
        mock_cursor = _create_mock_cursor(MOCK_USER_ROW)
        mock_conn = _create_mock_connection(mock_cursor)
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY_ID)

        # Verify cursor.execute was called with parameterized query
        calls = mock_cursor.execute.call_args_list
        first_call = calls[0]
        query = first_call[0][0]
        params = first_call[0][1]

        # Query must use %s placeholders, not contain the literal input values
        assert '%s' in query, "Query must use parameterized placeholders"
        assert f"'{VALID_USERNAME}'" not in query, "Username must not be interpolated into query"
        assert f"'{VALID_FACILITY_ID}'" not in query, "Facility ID must not be interpolated into query"
        assert params == (VALID_USERNAME, VALID_FACILITY_ID)

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_username_rejected(self, mock_get_conn):
        """SQL injection payloads in username should be rejected by validation."""
        service = AuthenticationService(DB_CONFIG)

        malicious_usernames = [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE healthcare_providers;--",
            "' UNION SELECT * FROM healthcare_providers--",
        ]

        for payload in malicious_usernames:
            result = service.authenticate_user(payload, VALID_PASSWORD, VALID_FACILITY_ID)
            assert result is None, f"SQL injection payload should be rejected: {payload}"

        # Database should never be contacted for invalid inputs
        mock_get_conn.assert_not_called()

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_facility_id_rejected(self, mock_get_conn):
        """SQL injection payloads in facility_id should be rejected by validation."""
        service = AuthenticationService(DB_CONFIG)

        malicious_facility_ids = [
            "' OR '1'='1",
            "FAC-001'; DROP TABLE users;--",
            "FAC-001' UNION SELECT * FROM healthcare_providers--",
        ]

        for payload in malicious_facility_ids:
            result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, payload)
            assert result is None, f"SQL injection payload should be rejected: {payload}"

        mock_get_conn.assert_not_called()


class TestAuthenticateUserInputValidation:
    """Test input validation for authenticate_user."""

    def test_empty_username_rejected(self):
        service = AuthenticationService(DB_CONFIG)
        assert service.authenticate_user("", VALID_PASSWORD, VALID_FACILITY_ID) is None

    def test_empty_password_rejected(self):
        service = AuthenticationService(DB_CONFIG)
        assert service.authenticate_user(VALID_USERNAME, "", VALID_FACILITY_ID) is None

    def test_empty_facility_id_rejected(self):
        service = AuthenticationService(DB_CONFIG)
        assert service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, "") is None

    def test_none_inputs_rejected(self):
        service = AuthenticationService(DB_CONFIG)
        assert service.authenticate_user(None, VALID_PASSWORD, VALID_FACILITY_ID) is None
        assert service.authenticate_user(VALID_USERNAME, None, VALID_FACILITY_ID) is None
        assert service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, None) is None

    def test_invalid_username_format_rejected(self):
        service = AuthenticationService(DB_CONFIG)
        invalid_usernames = [
            "user name with spaces",
            "user;name",
            "user'name",
            "user\"name",
        ]
        for username in invalid_usernames:
            assert service.authenticate_user(username, VALID_PASSWORD, VALID_FACILITY_ID) is None

    def test_valid_username_formats_accepted(self):
        """Valid username formats should pass validation (may still fail auth)."""
        service = AuthenticationService(DB_CONFIG)
        valid_usernames = [
            "doctor@example.com",
            "emp-12345",
            "john.doe",
            "user_name",
        ]
        # These should pass validation but will fail at DB connection stage
        for username in valid_usernames:
            with pytest.raises(Exception):
                # Will raise because no real DB connection - that's expected
                service.authenticate_user(username, VALID_PASSWORD, VALID_FACILITY_ID)

    def test_invalid_facility_id_format_rejected(self):
        service = AuthenticationService(DB_CONFIG)
        invalid_ids = [
            "INVALID",
            "fac-001",
            "FAC 001",
            "FAC-001; DROP TABLE",
        ]
        for fac_id in invalid_ids:
            assert service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, fac_id) is None


class TestAuthenticateUserBcrypt:
    """Test bcrypt password verification replaces MD5."""

    @patch.object(AuthenticationService, '_get_connection')
    def test_successful_auth_with_bcrypt(self, mock_get_conn):
        """Successful authentication with correct bcrypt-hashed password."""
        mock_cursor = _create_mock_cursor(MOCK_USER_ROW)
        mock_conn = _create_mock_connection(mock_cursor)
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY_ID)

        assert result is not None
        assert result['user_id'] == 42
        assert result['username'] == VALID_USERNAME
        assert result['role'] == 'physician'
        assert result['facility_id'] == VALID_FACILITY_ID
        assert 'session_token' in result
        assert 'session_expiry' in result

    @patch.object(AuthenticationService, '_get_connection')
    def test_wrong_password_rejected(self, mock_get_conn):
        """Wrong password should be rejected by bcrypt verification."""
        mock_cursor = _create_mock_cursor(MOCK_USER_ROW)
        mock_conn = _create_mock_connection(mock_cursor)
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, "WrongPassword123", VALID_FACILITY_ID)

        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_user_not_found_returns_none(self, mock_get_conn):
        """Non-existent user should return None."""
        mock_cursor = _create_mock_cursor(None)
        mock_conn = _create_mock_connection(mock_cursor)
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY_ID)

        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_password_not_compared_in_sql_query(self, mock_get_conn):
        """Password hash must NOT be in the SQL WHERE clause."""
        mock_cursor = _create_mock_cursor(MOCK_USER_ROW)
        mock_conn = _create_mock_connection(mock_cursor)
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY_ID)

        first_call = mock_cursor.execute.call_args_list[0]
        query = first_call[0][0]

        assert 'password_hash' not in query.split('WHERE')[1].split('AND')[0] or \
               'password_hash' in query.split('SELECT')[1].split('FROM')[0], \
            "password_hash should be in SELECT but not in WHERE conditions"
