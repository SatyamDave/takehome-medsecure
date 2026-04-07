"""Tests for application configuration security settings."""

import importlib
import os
import pytest
from unittest.mock import patch


def _reload_app_config():
    """Reload the config module to re-evaluate dataclass field defaults from env."""
    import src.config as config_module
    importlib.reload(config_module)
    return config_module.AppConfig


class TestDebugModeConfig:
    """Test that debug mode defaults to disabled for security."""

    def test_debug_defaults_to_false(self):
        """Debug mode must default to False when DEBUG env var is not set."""
        with patch.dict(os.environ, {}, clear=True):
            AppConfig = _reload_app_config()
            config = AppConfig()
            assert config.debug is False, "Debug mode must default to False"

    def test_debug_false_when_env_set_false(self):
        """Debug mode is False when DEBUG env var is explicitly 'false'."""
        with patch.dict(os.environ, {'DEBUG': 'false'}, clear=True):
            AppConfig = _reload_app_config()
            config = AppConfig()
            assert config.debug is False

    def test_debug_true_when_env_set_true(self):
        """Debug mode can be enabled via DEBUG env var when explicitly needed."""
        with patch.dict(os.environ, {'DEBUG': 'true'}, clear=True):
            AppConfig = _reload_app_config()
            config = AppConfig()
            assert config.debug is True

    def test_debug_case_insensitive(self):
        """DEBUG env var parsing is case-insensitive."""
        with patch.dict(os.environ, {'DEBUG': 'True'}, clear=True):
            AppConfig = _reload_app_config()
            config = AppConfig()
            assert config.debug is True

        with patch.dict(os.environ, {'DEBUG': 'FALSE'}, clear=True):
            AppConfig = _reload_app_config()
            config = AppConfig()
            assert config.debug is False

    def test_debug_arbitrary_value_is_false(self):
        """Any non-'true' value for DEBUG results in debug being False."""
        for value in ['yes', '1', 'on', 'enabled', 'random', '']:
            with patch.dict(os.environ, {'DEBUG': value}, clear=True):
                AppConfig = _reload_app_config()
                config = AppConfig()
                assert config.debug is False, (
                    f"DEBUG='{value}' should result in debug=False"
                )


class TestProductionValidation:
    """Test that production validation catches debug mode issues."""

    def test_production_debug_enabled_raises_critical(self):
        """Validation flags debug mode in production as CRITICAL."""
        from src.config import AppConfig
        config = AppConfig(environment='production', debug=True)
        issues = config.validate()
        assert any(
            'Debug mode' in issue and 'CRITICAL' in issue
            for issue in issues
        ), "Debug mode in production must be flagged as CRITICAL"

    def test_production_debug_disabled_no_debug_issue(self):
        """Validation does not flag debug when disabled in production."""
        from src.config import AppConfig
        config = AppConfig(environment='production', debug=False)
        issues = config.validate()
        assert not any(
            'Debug mode' in issue
            for issue in issues
        ), "No debug mode issue should be present when debug is disabled"

    def test_default_config_production_no_debug_issue(self):
        """Default config in production does not flag debug mode issue."""
        with patch.dict(os.environ, {'ENVIRONMENT': 'production'}, clear=True):
            AppConfig = _reload_app_config()
            config = AppConfig()
            assert config.debug is False
            issues = config.validate()
            assert not any(
                'Debug mode' in issue
                for issue in issues
            ), "Default production config must not have debug mode enabled"
