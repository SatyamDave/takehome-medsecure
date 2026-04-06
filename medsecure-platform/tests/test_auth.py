"""Tests for authentication module."""

import pytest
from src.auth.tokens import JWTTokenService


class TestJWTTokenService:
    """Test JWT token generation and validation."""

    def test_generate_access_token(self):
        """Test access token generation."""
        service = JWTTokenService()
        token = service.generate_access_token(
            user_id=42,
            role='physician',
            facility_id='FAC-001',
            email='doctor@example.com'
        )
        assert token is not None
        assert isinstance(token, str)

    def test_validate_token(self):
        """Test token validation."""
        service = JWTTokenService()
        token = service.generate_access_token(42, 'physician', 'FAC-001', 'test@example.com')
        payload = service.validate_token(token)
        assert payload is not None
        assert payload['user_id'] == 42
        assert payload['role'] == 'physician'
