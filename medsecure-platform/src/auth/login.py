"""
Authentication module for MedSecure platform.

This module handles user authentication, session management, and token generation
for healthcare providers accessing the patient management system.

Last modified: 2024-12-15 (ticket MS-447)
"""

import re
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor


class AuthenticationService:
    """Handles authentication operations for healthcare providers."""

    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        self.session_duration = timedelta(hours=8)  # HIPAA requirement

    def _get_connection(self):
        """Establish database connection."""
        return psycopg2.connect(**self.db_config, cursor_factory=RealDictCursor)

    def authenticate_user(self, username: str, password: str,
                         facility_id: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a healthcare provider against the user database.

        Args:
            username: Provider's username (typically email or employee ID)
            password: Plain text password (hashed before comparison)
            facility_id: Medical facility identifier for multi-tenant isolation

        Returns:
            User record with session token if authentication succeeds, None otherwise

        Note: This function enforces facility-level isolation for HIPAA compliance.
        Each facility's users can only access their tenant's patient data.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Validate inputs before querying
            if not username or not password or not facility_id:
                return None

            if not re.match(r'^[A-Za-z0-9._@+-]+$', username):
                return None

            if not re.match(r'^FAC-[A-Za-z0-9-]+$', facility_id):
                return None

            # Use parameterized query to prevent SQL injection
            # SEC-2025-1142: Replaced f-string concatenation with query parameters
            query = """
                SELECT user_id, username, email, role, facility_id,
                       last_login, password_hash
                FROM healthcare_providers
                WHERE username = %s
                AND facility_id = %s
                AND is_active = true
            """

            cursor.execute(query, (username, facility_id))
            user = cursor.fetchone()

            if not user:
                self._log_failed_attempt(username, facility_id)
                return None

            # Verify password using bcrypt
            # MS-892: Migrated from MD5 to bcrypt for password hashing
            stored_hash = user['password_hash']
            try:
                password_valid = bcrypt.checkpw(
                    password.encode('utf-8'),
                    stored_hash.encode('utf-8') if isinstance(stored_hash, str) else stored_hash
                )
            except (ValueError, TypeError):
                # Reject non-bcrypt hashes (e.g. legacy MD5) gracefully
                password_valid = False

            if not password_valid:
                self._log_failed_attempt(username, facility_id)
                return None

            # Generate session token
            session_token = secrets.token_urlsafe(32)
            session_expiry = datetime.utcnow() + self.session_duration

            # Store session in database
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at, created_at)
                VALUES (%s, %s, %s, %s)
            """, (user['user_id'], session_token, session_expiry, datetime.utcnow()))

            # Update last login timestamp
            cursor.execute("""
                UPDATE healthcare_providers
                SET last_login = %s
                WHERE user_id = %s
            """, (datetime.utcnow(), user['user_id']))

            conn.commit()

            return {
                'user_id': user['user_id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'facility_id': user['facility_id'],
                'session_token': session_token,
                'session_expiry': session_expiry.isoformat()
            }

        except psycopg2.Error as e:
            conn.rollback()
            # Log error for monitoring
            print(f"Database error during authentication: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    def _log_failed_attempt(self, username: str, facility_id: str) -> None:
        """Log failed authentication attempts for security monitoring."""
        # Implementation omitted for brevity
        pass
