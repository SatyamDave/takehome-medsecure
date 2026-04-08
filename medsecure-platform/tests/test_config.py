"""Tests for configuration security - hardcoded secrets (SEC-2025-1151)."""

import os
import pytest

from src.config import AppConfig, _require_secret


class TestRequireSecret:
    """Test the _require_secret helper function."""

    def test_returns_value_when_env_var_set(self, monkeypatch):
        """Test that _require_secret returns the value when the env var is set."""
        monkeypatch.setenv('TEST_SECRET_VAR', 'my-secret-value')
        assert _require_secret('TEST_SECRET_VAR') == 'my-secret-value'

    def test_raises_when_env_var_missing(self, monkeypatch):
        """Test that _require_secret raises ValueError when env var is not set."""
        monkeypatch.delenv('TEST_SECRET_VAR', raising=False)
        with pytest.raises(ValueError, match="TEST_SECRET_VAR environment variable must be set"):
            _require_secret('TEST_SECRET_VAR')

    def test_raises_when_env_var_empty(self, monkeypatch):
        """Test that _require_secret raises ValueError when env var is empty string."""
        monkeypatch.setenv('TEST_SECRET_VAR', '')
        with pytest.raises(ValueError, match="TEST_SECRET_VAR environment variable must be set"):
            _require_secret('TEST_SECRET_VAR')


class TestAppConfigSecrets:
    """Test that AppConfig requires secrets via environment variables."""

    def _set_required_secrets(self, monkeypatch):
        """Helper to set all required secret env vars for config creation."""
        monkeypatch.setenv('SECRET_KEY', 'test-secret-key-for-unit-tests')
        monkeypatch.setenv('DB_PASSWORD', 'test-db-password-for-unit-tests')
        monkeypatch.setenv('JWT_SECRET', 'test-jwt-secret-for-unit-tests')

    def test_config_created_with_all_secrets_set(self, monkeypatch):
        """Test that AppConfig can be created when all secrets are provided."""
        self._set_required_secrets(monkeypatch)
        config = AppConfig()
        assert config.secret_key == 'test-secret-key-for-unit-tests'
        assert config.db_password == 'test-db-password-for-unit-tests'
        assert config.jwt_secret == 'test-jwt-secret-for-unit-tests'

    def test_missing_secret_key_raises(self, monkeypatch):
        """Test that missing SECRET_KEY env var raises ValueError."""
        monkeypatch.delenv('SECRET_KEY', raising=False)
        monkeypatch.setenv('DB_PASSWORD', 'test-db-password')
        monkeypatch.setenv('JWT_SECRET', 'test-jwt-secret')
        with pytest.raises(ValueError, match="SECRET_KEY"):
            AppConfig()

    def test_missing_db_password_raises(self, monkeypatch):
        """Test that missing DB_PASSWORD env var raises ValueError."""
        monkeypatch.setenv('SECRET_KEY', 'test-secret-key')
        monkeypatch.delenv('DB_PASSWORD', raising=False)
        monkeypatch.setenv('JWT_SECRET', 'test-jwt-secret')
        with pytest.raises(ValueError, match="DB_PASSWORD"):
            AppConfig()

    def test_missing_jwt_secret_raises(self, monkeypatch):
        """Test that missing JWT_SECRET env var raises ValueError."""
        monkeypatch.setenv('SECRET_KEY', 'test-secret-key')
        monkeypatch.setenv('DB_PASSWORD', 'test-db-password')
        monkeypatch.delenv('JWT_SECRET', raising=False)
        with pytest.raises(ValueError, match="JWT_SECRET"):
            AppConfig()

    def test_no_hardcoded_default_for_secret_key(self, monkeypatch):
        """Verify the vulnerability is fixed: SECRET_KEY has no insecure default."""
        monkeypatch.delenv('SECRET_KEY', raising=False)
        monkeypatch.setenv('DB_PASSWORD', 'test-db-password')
        monkeypatch.setenv('JWT_SECRET', 'test-jwt-secret')
        with pytest.raises(ValueError):
            config = AppConfig()
            # Ensure the old hardcoded default is never used
            assert config.secret_key != 'medsecure-default-secret-change-in-prod'

    def test_no_hardcoded_default_for_db_password(self, monkeypatch):
        """Verify the vulnerability is fixed: DB_PASSWORD has no insecure default."""
        monkeypatch.setenv('SECRET_KEY', 'test-secret-key')
        monkeypatch.delenv('DB_PASSWORD', raising=False)
        monkeypatch.setenv('JWT_SECRET', 'test-jwt-secret')
        with pytest.raises(ValueError):
            config = AppConfig()
            assert config.db_password != 'changeme123'

    def test_no_hardcoded_default_for_jwt_secret(self, monkeypatch):
        """Verify the vulnerability is fixed: JWT_SECRET has no insecure default."""
        monkeypatch.setenv('SECRET_KEY', 'test-secret-key')
        monkeypatch.setenv('DB_PASSWORD', 'test-db-password')
        monkeypatch.delenv('JWT_SECRET', raising=False)
        with pytest.raises(ValueError):
            config = AppConfig()
            assert config.jwt_secret != 'jwt-secret-key-default'

    def test_all_missing_secrets_raises(self, monkeypatch):
        """Test that missing all secret env vars raises ValueError."""
        monkeypatch.delenv('SECRET_KEY', raising=False)
        monkeypatch.delenv('DB_PASSWORD', raising=False)
        monkeypatch.delenv('JWT_SECRET', raising=False)
        with pytest.raises(ValueError):
            AppConfig()
