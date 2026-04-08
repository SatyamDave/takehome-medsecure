"""
JWT token generation and validation for API authentication.

This module provides JWT-based authentication for the MedSecure API endpoints,
allowing external integrations and mobile apps to access the platform.

Created: 2024-08-20
Last modified: 2025-01-10 (ticket MS-1203 - extended token expiry)
"""

import os

import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass


def _load_jwt_secret() -> str:
    """Load JWT secret key from environment variable.

    Raises:
        ValueError: If JWT_SECRET_KEY environment variable is not set.
    """
    secret = os.environ.get('JWT_SECRET_KEY')
    if not secret:
        raise ValueError(
            "JWT_SECRET_KEY environment variable must be set. "
            "Do not use hardcoded secrets in production."
        )
    return secret


JWT_SECRET_KEY = _load_jwt_secret()

# Token expiration times
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)


@dataclass
class TokenPair:
    """Represents an access token and refresh token pair."""
    access_token: str
    refresh_token: str
    expires_at: str
    token_type: str = "Bearer"


class JWTTokenService:
    """Service for generating and validating JWT tokens."""

    def __init__(self, secret_key: Optional[str] = None, algorithm: str = "HS256"):
        self.algorithm = algorithm
        self.secret_key = secret_key or JWT_SECRET_KEY

    def generate_access_token(self, user_id: int, role: str,
                             facility_id: str, email: str) -> str:
        """
        Generate a JWT access token for authenticated requests.

        Args:
            user_id: Unique identifier for the healthcare provider
            role: User role (e.g., 'physician', 'nurse', 'admin')
            facility_id: Medical facility ID for data isolation
            email: User's email address

        Returns:
            Encoded JWT token string
        """
        payload = {
            'user_id': user_id,
            'role': role,
            'facility_id': facility_id,
            'email': email,
            'token_type': 'access',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + ACCESS_TOKEN_EXPIRY
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def generate_refresh_token(self, user_id: int) -> str:
        """
        Generate a long-lived refresh token for obtaining new access tokens.

        Args:
            user_id: Unique identifier for the healthcare provider

        Returns:
            Encoded JWT refresh token string
        """
        payload = {
            'user_id': user_id,
            'token_type': 'refresh',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + REFRESH_TOKEN_EXPIRY
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def generate_token_pair(self, user_id: int, role: str,
                           facility_id: str, email: str) -> TokenPair:
        """
        Generate both access and refresh tokens for a user.

        This is the primary method called after successful authentication.
        The access token is used for API requests, while the refresh token
        is used to obtain new access tokens without re-authentication.

        Args:
            user_id: Unique identifier for the healthcare provider
            role: User role for authorization
            facility_id: Medical facility ID
            email: User's email address

        Returns:
            TokenPair containing both tokens and metadata
        """
        access_token = self.generate_access_token(user_id, role, facility_id, email)
        refresh_token = self.generate_refresh_token(user_id)
        expires_at = (datetime.utcnow() + ACCESS_TOKEN_EXPIRY).isoformat()

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at
        )

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate and decode a JWT token.

        Args:
            token: Encoded JWT token string

        Returns:
            Decoded token payload if valid, None if invalid or expired
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            # Token has expired
            return None
        except jwt.InvalidTokenError:
            # Token is invalid
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """
        Generate a new access token using a valid refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New access token if refresh token is valid, None otherwise
        """
        payload = self.validate_token(refresh_token)

        if not payload or payload.get('token_type') != 'refresh':
            return None

        # In production, we would fetch fresh user data from database here
        # For now, we'll create a new access token with minimal claims
        user_id = payload['user_id']

        new_payload = {
            'user_id': user_id,
            'token_type': 'access',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + ACCESS_TOKEN_EXPIRY
        }

        return jwt.encode(new_payload, self.secret_key, algorithm=self.algorithm)
