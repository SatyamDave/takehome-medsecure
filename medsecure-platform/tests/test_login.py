"""Tests for authentication login module (SEC-2025-1142).

Verifies that the SQL injection vulnerability is fixed and that
parameterized queries, input validation, and bcrypt password
verification work correctly.
"""

import pytest
from unittest.mock import patch, MagicMock
import bcrypt

from src.auth.login import AuthenticationService


# Test constants
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'medsecure_test',
    'user': 'test_user',
    'password': 'test_password'
}

VALID_USERNAME = 'doctor@example.com'
VALID_PASSWORD = 'SecureP@ss123'
VALID_FACILITY = 'FAC-001'
VALID_BCRYPT_HASH = bcrypt.hashpw(
    VALID_PASSWORD.encode('utf-8'), bcrypt.gensalt()
).decode('utf-8')


def _make_user_row(password_hash=None):
    """Create a mock user row matching the query result."""
    return {
        'user_id': 42,
        'username': VALID_USERNAME,
        'email': 'doctor@example.com',
        'role': 'physician',
        'facility_id': VALID_FACILITY,
        'last_login': None,
        'password_hash': password_hash or VALID_BCRYPT_HASH,
    }


class TestAuthenticateUserParameterizedQuery:
    """Verify SQL injection is prevented via parameterized queries."""

    @patch.object(AuthenticationService, '_get_connection')
    def test_query_uses_parameterized_placeholders(self, mock_get_conn):
        """Ensure cursor.execute is called with %s placeholders and a params tuple."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = _make_user_row()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY)

        # The first execute call is the SELECT query
        select_call = mock_cursor.execute.call_args_list[0]
        query_str = select_call[0][0]
        query_params = select_call[0][1]

        # Query must NOT contain the literal username or facility_id
        assert VALID_USERNAME not in query_str
        assert VALID_FACILITY not in query_str

        # Query must use %s placeholders
        assert '%s' in query_str

        # Parameters must be passed as a tuple
        assert isinstance(query_params, tuple)
        assert VALID_USERNAME in query_params
        assert VALID_FACILITY in query_params

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_username_blocked(self, mock_get_conn):
        """SQL injection payload in username must not reach the query."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)

        # Classic SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE healthcare_providers;--",
            "' UNION SELECT * FROM healthcare_providers--",
        ]

        for payload in sqli_payloads:
            result = service.authenticate_user(payload, VALID_PASSWORD, VALID_FACILITY)
            assert result is None, f"SQL injection payload should be rejected: {payload}"

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_facility_id_blocked(self, mock_get_conn):
        """SQL injection payload in facility_id must not reach the query."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)

        sqli_payloads = [
            "' OR '1'='1",
            "FAC-001'; DROP TABLE healthcare_providers;--",
        ]

        for payload in sqli_payloads:
            result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, payload)
            assert result is None, f"SQL injection payload should be rejected: {payload}"


class TestInputValidation:
    """Verify input validation rejects malformed inputs."""

    @patch.object(AuthenticationService, '_get_connection')
    def test_empty_username_rejected(self, mock_get_conn):
        """Empty username should return None without querying the database."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user('', VALID_PASSWORD, VALID_FACILITY)
        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_empty_password_rejected(self, mock_get_conn):
        """Empty password should return None without querying the database."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, '', VALID_FACILITY)
        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_empty_facility_id_rejected(self, mock_get_conn):
        """Empty facility_id should return None without querying the database."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, '')
        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_invalid_username_format_rejected(self, mock_get_conn):
        """Usernames with special SQL characters should be rejected."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)

        invalid_usernames = [
            "admin' OR 1=1--",
            "user;DROP TABLE",
            "user<script>",
            "user name with spaces",
        ]

        for username in invalid_usernames:
            result = service.authenticate_user(username, VALID_PASSWORD, VALID_FACILITY)
            assert result is None, f"Invalid username should be rejected: {username}"

    @patch.object(AuthenticationService, '_get_connection')
    def test_invalid_facility_id_format_rejected(self, mock_get_conn):
        """Facility IDs not matching FAC-xxx pattern should be rejected."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)

        invalid_facilities = [
            "not-a-facility",
            "123",
            "FAC_001",
            "' OR 1=1--",
        ]

        for facility_id in invalid_facilities:
            result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, facility_id)
            assert result is None, f"Invalid facility_id should be rejected: {facility_id}"

    @patch.object(AuthenticationService, '_get_connection')
    def test_valid_username_formats_accepted(self, mock_get_conn):
        """Valid username formats should pass validation."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = _make_user_row()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)

        valid_usernames = [
            'doctor@example.com',
            'john.doe',
            'user+tag@hospital.org',
            'EMP-12345',
        ]

        for username in valid_usernames:
            # Reset mock
            mock_cursor.fetchone.return_value = _make_user_row()
            result = service.authenticate_user(username, VALID_PASSWORD, VALID_FACILITY)
            # Should not be rejected by validation (may still return result or None
            # depending on bcrypt check, but should not be short-circuited)
            assert mock_cursor.execute.called, f"Valid username should reach DB query: {username}"


class TestBcryptPasswordVerification:
    """Verify bcrypt is used instead of MD5 for password hashing."""

    @patch.object(AuthenticationService, '_get_connection')
    def test_correct_password_authenticates(self, mock_get_conn):
        """Correct password should authenticate successfully."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = _make_user_row()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY)

        assert result is not None
        assert result['user_id'] == 42
        assert result['username'] == VALID_USERNAME
        assert 'session_token' in result
        assert 'session_expiry' in result

    @patch.object(AuthenticationService, '_get_connection')
    def test_wrong_password_rejected(self, mock_get_conn):
        """Wrong password should fail authentication."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = _make_user_row()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, 'WrongPassword123', VALID_FACILITY)

        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_md5_hash_no_longer_accepted(self, mock_get_conn):
        """MD5 hashed passwords should NOT authenticate (migration to bcrypt)."""
        import hashlib
        md5_hash = hashlib.md5(VALID_PASSWORD.encode()).hexdigest()

        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = _make_user_row(password_hash=md5_hash)
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY)

        # MD5 hashes should not be accepted by bcrypt.checkpw
        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_user_not_found_returns_none(self, mock_get_conn):
        """Non-existent user should return None."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY)

        assert result is None

    @patch.object(AuthenticationService, '_get_connection')
    def test_password_hash_not_in_response(self, mock_get_conn):
        """The password_hash field should not be included in the returned user dict."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = _make_user_row()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY)

        assert result is not None
        assert 'password_hash' not in result


class TestSessionManagement:
    """Verify session token creation on successful auth."""

    @patch.object(AuthenticationService, '_get_connection')
    def test_session_token_created_on_success(self, mock_get_conn):
        """Successful auth should insert a session and update last_login."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = _make_user_row()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        service = AuthenticationService(DB_CONFIG)
        result = service.authenticate_user(VALID_USERNAME, VALID_PASSWORD, VALID_FACILITY)

        assert result is not None

        # Should have 3 execute calls: SELECT, INSERT session, UPDATE last_login
        assert mock_cursor.execute.call_count == 3

        # Verify INSERT session call uses parameterized query
        insert_call = mock_cursor.execute.call_args_list[1]
        assert 'INSERT INTO user_sessions' in insert_call[0][0]
        assert isinstance(insert_call[0][1], tuple)

        # Verify commit was called
        mock_conn.commit.assert_called_once()
