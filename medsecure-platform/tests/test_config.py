"""Tests for application configuration - debug mode (SEC-2025-1150)."""

import os
import importlib
import pytest
from unittest.mock import patch


def _reload_config(env_overrides=None):
    """Reload config module with the given environment overrides.

    Dataclass field defaults are evaluated at class-definition time,
    so we must reload the module to pick up new env-var values.
    """
    env = env_overrides or {}
    with patch.dict(os.environ, env, clear=True):
        import src.config as config_module
        importlib.reload(config_module)
        return config_module.AppConfig()


class TestDebugModeConfig:
    """Test that debug mode defaults to disabled (secure by default)."""

    def test_debug_defaults_to_false(self):
        """Test that debug mode is False when DEBUG env var is not set."""
        cfg = _reload_config()
        assert cfg.debug is False, "Debug must default to False when DEBUG env var is unset"

    def test_debug_false_when_env_set_false(self):
        """Test that debug mode is False when DEBUG=false."""
        cfg = _reload_config({'DEBUG': 'false'})
        assert cfg.debug is False

    def test_debug_true_only_when_explicitly_enabled(self):
        """Test that debug mode is True only when DEBUG=true is explicitly set."""
        cfg = _reload_config({'DEBUG': 'true'})
        assert cfg.debug is True

    def test_debug_case_insensitive(self):
        """Test that DEBUG env var is case-insensitive."""
        cfg = _reload_config({'DEBUG': 'True'})
        assert cfg.debug is True

        cfg = _reload_config({'DEBUG': 'FALSE'})
        assert cfg.debug is False

    def test_debug_invalid_value_defaults_to_false(self):
        """Test that non-'true' DEBUG values result in debug being False."""
        for value in ['1', 'yes', 'on', 'enabled', 'random', '']:
            cfg = _reload_config({'DEBUG': value})
            assert cfg.debug is False, (
                f"Debug must be False for DEBUG={value!r}"
            )

    def test_production_validation_no_debug_warning(self):
        """Test that validate() does not flag debug in production when debug is off."""
        cfg = _reload_config({'ENVIRONMENT': 'production', 'DEBUG': 'false'})
        issues = cfg.validate()
        debug_issues = [i for i in issues if 'debug' in i.lower() or 'Debug' in i]
        assert len(debug_issues) == 0, "No debug warnings expected when debug is disabled"

    def test_production_validation_flags_debug_enabled(self):
        """Test that validate() flags debug mode when explicitly enabled in production."""
        cfg = _reload_config({'ENVIRONMENT': 'production', 'DEBUG': 'true'})
        issues = cfg.validate()
        debug_issues = [i for i in issues if 'debug' in i.lower() or 'Debug' in i]
        assert len(debug_issues) > 0, "Should warn when debug is enabled in production"
