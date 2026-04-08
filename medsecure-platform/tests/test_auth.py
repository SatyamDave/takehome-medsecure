"""Tests for authentication module."""

import os
import pytest
import jwt


# Set JWT_SECRET_KEY env var before importing the module
TEST_JWT_SECRET = "test-secret-key-for-unit-tests"
os.environ['JWT_SECRET_KEY'] = TEST_JWT_SECRET

from src.auth.tokens import JWTTokenService, _load_jwt_secret


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


class TestJWTSecretKeyFromEnv:
    """Test that JWT secret key is loaded from environment variable."""

    def test_secret_loaded_from_env(self):
        """Test that _load_jwt_secret reads from JWT_SECRET_KEY env var."""
        os.environ['JWT_SECRET_KEY'] = 'my-env-secret'
        secret = _load_jwt_secret()
        assert secret == 'my-env-secret'
        # Restore test secret
        os.environ['JWT_SECRET_KEY'] = TEST_JWT_SECRET

    def test_missing_env_var_raises_error(self):
        """Test that missing JWT_SECRET_KEY raises ValueError."""
        original = os.environ.pop('JWT_SECRET_KEY', None)
        try:
            with pytest.raises(ValueError, match="JWT_SECRET_KEY environment variable must be set"):
                _load_jwt_secret()
        finally:
            if original is not None:
                os.environ['JWT_SECRET_KEY'] = original

    def test_empty_env_var_raises_error(self):
        """Test that empty JWT_SECRET_KEY raises ValueError."""
        original = os.environ.get('JWT_SECRET_KEY')
        os.environ['JWT_SECRET_KEY'] = ''
        try:
            with pytest.raises(ValueError, match="JWT_SECRET_KEY environment variable must be set"):
                _load_jwt_secret()
        finally:
            if original is not None:
                os.environ['JWT_SECRET_KEY'] = original

    def test_no_hardcoded_secret_in_source(self):
        """Test that the old hardcoded secret is not present in the source."""
        import inspect
        source = inspect.getsource(_load_jwt_secret)
        assert "medsecure_prod_jwt_secret_2024_do_not_share" not in source

    def test_service_uses_env_secret(self):
        """Test that JWTTokenService uses the secret from the environment."""
        service = JWTTokenService()
        token = service.generate_access_token(1, 'admin', 'FAC-001', 'admin@test.com')

        # Decode with the env-provided secret to prove it was used for signing
        payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=['HS256'])
        assert payload['user_id'] == 1
        assert payload['role'] == 'admin'

    def test_service_accepts_custom_secret(self):
        """Test that JWTTokenService can accept a custom secret key."""
        custom_secret = "custom-test-secret"
        service = JWTTokenService(secret_key=custom_secret)
        token = service.generate_access_token(1, 'nurse', 'FAC-002', 'nurse@test.com')

        # Should decode with the custom secret
        payload = jwt.decode(token, custom_secret, algorithms=['HS256'])
        assert payload['user_id'] == 1

        # Should NOT decode with the default env secret
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(token, TEST_JWT_SECRET, algorithms=['HS256'])

    def test_token_forged_with_wrong_key_rejected(self):
        """Test that tokens signed with a different key are rejected."""
        service = JWTTokenService()
        # Forge a token with a different key
        forged_token = jwt.encode(
            {'user_id': 999, 'role': 'admin', 'token_type': 'access'},
            'attacker-key',
            algorithm='HS256'
        )
        # Service should reject it
        result = service.validate_token(forged_token)
        assert result is None
