"""Tests for authentication login module (SEC-2025-1142) - SQL injection & bcrypt fix."""

import bcrypt
from unittest.mock import patch, MagicMock
from datetime import datetime

import pytest

from src.auth.login import AuthenticationService


# Helper to generate a bcrypt hash for test passwords
def _bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


class TestAuthenticateUser:
    """Test authenticate_user uses parameterized queries, validates input, and uses bcrypt."""

    def setup_method(self):
        """Set up test fixtures."""
        self.db_config = {
            'host': 'localhost',
            'port': 5432,
            'database': 'medsecure_test',
            'user': 'test_user',
            'password': 'test_password'
        }
        self.service = AuthenticationService(self.db_config)

    @patch.object(AuthenticationService, '_get_connection')
    def test_authenticate_uses_parameterized_query(self, mock_get_conn):
        """Verify the SQL query uses parameterized placeholders, not string concatenation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # Simulate no user found so we don't need to mock bcrypt verification
        mock_cursor.fetchone.return_value = None

        self.service.authenticate_user('testuser', 'password123', 'FAC-001')

        # Verify cursor.execute was called with a parameterized query (tuple of params)
        mock_cursor.execute.assert_called_once()
        call_args = mock_cursor.execute.call_args
        query = call_args[0][0]
        params = call_args[0][1]

        # Query must use %s placeholders, NOT contain the literal input values
        assert '%s' in query, "Query must use parameterized placeholders"
        assert "'testuser'" not in query, "Query must not contain literal username"
        assert "'FAC-001'" not in query, "Query must not contain literal facility_id"

        # Params must be a tuple with username and facility_id only
        # (password is verified via bcrypt in Python, not in the SQL query)
        assert isinstance(params, tuple), "Parameters must be passed as a tuple"
        assert len(params) == 2, "Must pass username and facility_id as params"
        assert params[0] == 'testuser'
        assert params[1] == 'FAC-001'

    @patch.object(AuthenticationService, '_get_connection')
    def test_password_not_in_sql_query(self, mock_get_conn):
        """Verify the password (or its hash) is NOT passed as a SQL parameter."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchone.return_value = None

        self.service.authenticate_user('testuser', 'password123', 'FAC-001')

        call_args = mock_cursor.execute.call_args
        params = call_args[0][1]

        # bcrypt verification happens in Python, not in SQL
        assert len(params) == 2, "Only username and facility_id should be SQL params"

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_username_is_prevented(self, mock_get_conn):
        """Verify SQL injection payloads in username are passed as parameters, not interpolated."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None
        mock_get_conn.return_value = mock_conn

        malicious_username = "admin' OR '1'='1' --"
        self.service.authenticate_user(malicious_username, 'password', 'FAC-001')

        call_args = mock_cursor.execute.call_args
        query = call_args[0][0]
        params = call_args[0][1]

        # The malicious string must be in params, NOT embedded in the query
        assert malicious_username not in query, "Malicious input must not be in query string"
        assert params[0] == malicious_username, "Malicious input must be passed as a parameter"

    @patch.object(AuthenticationService, '_get_connection')
    def test_sql_injection_in_facility_id_is_rejected(self, mock_get_conn):
        """Verify SQL injection payloads in facility_id are rejected by input validation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # facility_id with SQL injection should be rejected by regex validation
        malicious_facility = "FAC-001' OR '1'='1"
        result = self.service.authenticate_user('testuser', 'password', malicious_facility)

        assert result is None, "SQL injection in facility_id must be rejected"
        # The database should never be queried with malicious input
        mock_cursor.execute.assert_not_called()

    def test_empty_username_returns_none(self):
        """Verify empty username is rejected before database access."""
        result = self.service.authenticate_user('', 'password', 'FAC-001')
        assert result is None

    def test_empty_password_returns_none(self):
        """Verify empty password is rejected before database access."""
        result = self.service.authenticate_user('testuser', '', 'FAC-001')
        assert result is None

    def test_empty_facility_id_returns_none(self):
        """Verify empty facility_id is rejected before database access."""
        result = self.service.authenticate_user('testuser', 'password', '')
        assert result is None

    def test_none_username_returns_none(self):
        """Verify None username is rejected."""
        result = self.service.authenticate_user(None, 'password', 'FAC-001')
        assert result is None

    def test_none_password_returns_none(self):
        """Verify None password is rejected."""
        result = self.service.authenticate_user('testuser', None, 'FAC-001')
        assert result is None

    def test_none_facility_id_returns_none(self):
        """Verify None facility_id is rejected."""
        result = self.service.authenticate_user('testuser', 'password', None)
        assert result is None

    def test_invalid_facility_id_format_returns_none(self):
        """Verify facility_id with special characters is rejected."""
        invalid_ids = [
            "FAC-001'; DROP TABLE--",
            "FAC 001",
            "FAC_001!@#",
            "'; SELECT * FROM users;--",
        ]
        for fid in invalid_ids:
            result = self.service.authenticate_user('testuser', 'password', fid)
            assert result is None, f"facility_id '{fid}' should be rejected"

    def test_valid_facility_id_formats_accepted(self):
        """Verify legitimate facility_id formats pass validation."""
        # These should pass the regex check (but will fail at DB level since we don't mock)
        valid_ids = ['FAC-001', 'facility123', 'A', 'FAC-001-WEST']
        for fid in valid_ids:
            with patch.object(AuthenticationService, '_get_connection') as mock_get_conn:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value = mock_cursor
                mock_cursor.fetchone.return_value = None
                mock_get_conn.return_value = mock_conn

                # Should reach the database (not be rejected by validation)
                self.service.authenticate_user('testuser', 'password', fid)
                mock_cursor.execute.assert_called_once(), \
                    f"Valid facility_id '{fid}' should reach the database query"

    @patch.object(AuthenticationService, '_get_connection')
    def test_successful_authentication_returns_user_data(self, mock_get_conn):
        """Verify successful authentication returns expected user record with bcrypt."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # Generate a bcrypt hash for the test password
        test_password = 'securepass'
        hashed_password = _bcrypt_hash(test_password)

        mock_cursor.fetchone.return_value = {
            'user_id': 42,
            'username': 'dr.smith',
            'email': 'dr.smith@hospital.com',
            'role': 'physician',
            'facility_id': 'FAC-001',
            'last_login': datetime(2025, 1, 1),
            'password_hash': hashed_password
        }

        result = self.service.authenticate_user('dr.smith', test_password, 'FAC-001')

        assert result is not None
        assert result['user_id'] == 42
        assert result['username'] == 'dr.smith'
        assert result['email'] == 'dr.smith@hospital.com'
        assert result['role'] == 'physician'
        assert result['facility_id'] == 'FAC-001'
        assert 'session_token' in result
        assert 'session_expiry' in result

    @patch.object(AuthenticationService, '_get_connection')
    def test_wrong_password_rejected_with_bcrypt(self, mock_get_conn):
        """Verify that an incorrect password is rejected by bcrypt verification."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        # Hash the correct password with bcrypt
        hashed_password = _bcrypt_hash('correctpassword')

        mock_cursor.fetchone.return_value = {
            'user_id': 42,
            'username': 'dr.smith',
            'email': 'dr.smith@hospital.com',
            'role': 'physician',
            'facility_id': 'FAC-001',
            'last_login': datetime(2025, 1, 1),
            'password_hash': hashed_password
        }

        # Attempt authentication with wrong password
        result = self.service.authenticate_user('dr.smith', 'wrongpassword', 'FAC-001')
        assert result is None, "Wrong password must be rejected"

    @patch.object(AuthenticationService, '_get_connection')
    def test_md5_hash_no_longer_used(self, mock_get_conn):
        """Verify that MD5 hashing is no longer used for password comparison."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn
        mock_cursor.fetchone.return_value = None

        self.service.authenticate_user('testuser', 'password', 'FAC-001')

        # Check that hashlib.md5 is not imported or used
        import src.auth.login as login_module
        import inspect
        source = inspect.getsource(login_module)
        assert 'hashlib' not in source, "hashlib must not be imported"
        assert 'md5' not in source.lower(), "MD5 must not be used for password hashing"

    @patch.object(AuthenticationService, '_get_connection')
    def test_bcrypt_verification_with_bytes_hash(self, mock_get_conn):
        """Verify bcrypt works when password_hash is stored as bytes."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        test_password = 'securepass'
        # Store hash as bytes (as some DB drivers return)
        hashed_password = bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt())

        mock_cursor.fetchone.return_value = {
            'user_id': 42,
            'username': 'dr.smith',
            'email': 'dr.smith@hospital.com',
            'role': 'physician',
            'facility_id': 'FAC-001',
            'last_login': datetime(2025, 1, 1),
            'password_hash': hashed_password  # bytes, not str
        }

        result = self.service.authenticate_user('dr.smith', test_password, 'FAC-001')
        assert result is not None, "Should handle bytes password_hash from database"

    @patch.object(AuthenticationService, '_get_connection')
    def test_query_does_not_use_f_string(self, mock_get_conn):
        """Verify the query string itself has no f-string interpolation artifacts."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None
        mock_get_conn.return_value = mock_conn

        self.service.authenticate_user('anyuser', 'anypass', 'FAC-001')

        call_args = mock_cursor.execute.call_args
        query = call_args[0][0]

        # Ensure no single-quoted interpolation patterns remain in the query
        assert "'{" not in query, "Query must not contain f-string interpolation"
        assert "}'" not in query, "Query must not contain f-string interpolation"
