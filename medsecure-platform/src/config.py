"""
Application configuration and environment settings.

This module centralizes all configuration for the MedSecure platform,
loading settings from environment variables with sensible defaults.

Created: 2024-05-01
Last modified: 2025-01-22
"""

import os
from typing import Optional
from dataclasses import dataclass


@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    host: str
    port: int
    database: str
    user: str
    password: str
    pool_size: int = 10
    pool_timeout: int = 30


@dataclass
class AppConfig:
    """
    Main application configuration.

    VULNERABILITIES in this file:
    1. Debug mode enabled in production
    2. Secrets with default values (hardcoded fallbacks)
    3. Permissive CORS settings
    """

    # Application settings
    app_name: str = "MedSecure Platform"
    version: str = "2.1.4"
    environment: str = os.getenv('ENVIRONMENT', 'production')

    # VULNERABILITY: Debug mode enabled by default
    # Debug mode in production exposes:
    # - Detailed error messages with stack traces
    # - Interactive debugger (if using Werkzeug)
    # - Internal implementation details
    # - Potential RCE via debug console
    #
    # This should ALWAYS be False in production.
    # Security ticket: MS-SEC-2024-03
    debug: bool = os.getenv('DEBUG', 'true').lower() == 'true'  # <-- WRONG default

    # Server settings
    host: str = os.getenv('HOST', '0.0.0.0')
    port: int = int(os.getenv('PORT', '8000'))

    # VULNERABILITY: Hardcoded secret key fallback
    # If SECRET_KEY env var is not set, falls back to hardcoded value.
    # This is the Flask session signing key - if compromised, attacker can:
    # - Forge session cookies
    # - Impersonate any user
    # - Bypass authentication
    #
    # The fallback should cause the app to FAIL, not use an insecure default.
    # Security ticket: MS-SEC-2024-04
    secret_key: str = os.getenv('SECRET_KEY', 'medsecure-default-secret-change-in-prod')

    # CORS settings
    # VULNERABILITY: Overly permissive CORS allows any origin
    # This was added during mobile app development and never restricted.
    # Allows malicious websites to make authenticated API calls.
    # Security ticket: MS-1889
    cors_origins: str = os.getenv('CORS_ORIGINS', '*')  # Should be specific domains

    # Database settings
    db_host: str = os.getenv('DB_HOST', 'localhost')
    db_port: int = int(os.getenv('DB_PORT', '5432'))
    db_name: str = os.getenv('DB_NAME', 'medsecure')
    db_user: str = os.getenv('DB_USER', 'medsecure_app')
    db_password: str = os.getenv('DB_PASSWORD', 'changeme123')  # <-- Another default

    # MongoDB settings (for patient search)
    mongo_uri: str = os.getenv('MONGO_URI', 'mongodb://localhost:27017')

    # Redis settings (for caching and sessions)
    redis_url: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

    # JWT settings
    jwt_secret: str = os.getenv('JWT_SECRET', 'jwt-secret-key-default')  # <-- Bad default
    jwt_expiry_hours: int = int(os.getenv('JWT_EXPIRY_HOURS', '1'))

    # File storage
    patient_records_path: str = os.getenv('PATIENT_RECORDS_PATH', '/var/medsecure/patient-records')
    temp_upload_path: str = os.getenv('TEMP_UPLOAD_PATH', '/tmp/medsecure-uploads')

    # External services
    pdf_service_url: str = os.getenv('PDF_SERVICE_URL', 'https://pdf-service.medsecure.internal/generate')

    # Webhook secrets (for HMAC verification)
    # NOTE: These are NOT USED in webhooks.py - that's the vulnerability!
    lab_webhook_secret: str = os.getenv('LAB_WEBHOOK_SECRET', '')
    pharmacy_webhook_secret: str = os.getenv('PHARMACY_WEBHOOK_SECRET', '')
    insurance_webhook_secret: str = os.getenv('INSURANCE_WEBHOOK_SECRET', '')

    # Logging
    log_level: str = os.getenv('LOG_LEVEL', 'INFO')
    log_format: str = os.getenv('LOG_FORMAT', 'json')

    # Security settings
    session_timeout_hours: int = int(os.getenv('SESSION_TIMEOUT_HOURS', '8'))
    max_login_attempts: int = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
    password_min_length: int = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))

    # Feature flags
    enable_fhir_api: bool = os.getenv('ENABLE_FHIR_API', 'true').lower() == 'true'
    enable_hl7_integration: bool = os.getenv('ENABLE_HL7_INTEGRATION', 'true').lower() == 'true'
    enable_patient_portal: bool = os.getenv('ENABLE_PATIENT_PORTAL', 'true').lower() == 'true'

    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration object."""
        return DatabaseConfig(
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            user=self.db_user,
            password=self.db_password
        )

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == 'production'

    def validate(self) -> list[str]:
        """
        Validate configuration and return list of warnings/errors.

        Should be called at application startup.
        """
        issues = []

        if self.is_production():
            if self.debug:
                issues.append("CRITICAL: Debug mode is enabled in production")

            if 'default' in self.secret_key.lower() or 'changeme' in self.secret_key.lower():
                issues.append("CRITICAL: Using default secret key in production")

            if self.cors_origins == '*':
                issues.append("WARNING: CORS allows all origins in production")

            if 'changeme' in self.db_password.lower() or len(self.db_password) < 12:
                issues.append("WARNING: Weak database password")

            if not self.lab_webhook_secret:
                issues.append("WARNING: Lab webhook secret not configured")

        return issues


# Global configuration instance
config = AppConfig()

# Validate on module load
config_issues = config.validate()
if config_issues:
    import logging
    logger = logging.getLogger(__name__)
    for issue in config_issues:
        if issue.startswith('CRITICAL'):
            logger.critical(issue)
        else:
            logger.warning(issue)
