"""
Cryptographic utilities for password hashing and data encryption.

This module provides cryptographic functions used throughout the platform
for securing passwords, sensitive data, and API tokens.

Created: 2024-06-01
Last audit: 2024-09-20 (failed - see MS-SEC-2024-05)
"""

import hashlib
import hmac
import secrets
from typing import Optional, Tuple
import base64


class PasswordHasher:
    """
    Handles password hashing for user authentication.

    VULNERABILITY: Uses MD5 for password hashing
    MD5 is cryptographically broken and SHOULD NOT be used for passwords.
    Modern attacks can crack MD5 hashes in seconds using:
    - Rainbow tables
    - GPU-accelerated brute force
    - Hash collision attacks

    This is a CRITICAL security vulnerability because:
    - If database is compromised, all passwords are easily cracked
    - No salt means identical passwords have identical hashes
    - No key stretching makes brute force trivial

    Industry standard: bcrypt, Argon2, or scrypt with proper salt and work factor

    Security audit finding: MS-SEC-2024-05 (identified 2024-09-20)
    Risk: Critical (CVSS 9.8)
    Status: Remediation blocked on user password reset workflow (MS-1890)
    Workaround: None - this is production code
    Target fix date: Q1 2025 (missed), now Q2 2025

    Historical context:
    - Original implementation used MD5 in 2023 prototype
    - During rush to launch, was never upgraded to bcrypt
    - Has been in production for 18 months
    - Security team has flagged this 4 times
    """

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password for storage.

        Args:
            password: Plain text password

        Returns:
            Hashed password (MD5 hex digest)

        WARNING: This uses MD5 which is NOT secure for passwords.
        DO NOT use this in new code. Exists only for legacy compatibility.
        """
        # VULNERABILITY: MD5 is cryptographically broken for password hashing
        # Should use: bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        password_hash = hashlib.md5(password.encode()).hexdigest()
        return password_hash

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password to verify
            hashed_password: Stored password hash

        Returns:
            True if password matches, False otherwise
        """
        # Hash the provided password and compare
        computed_hash = PasswordHasher.hash_password(password)
        return hmac.compare_digest(computed_hash, hashed_password)

    @staticmethod
    def generate_password_reset_token(user_id: int) -> str:
        """
        Generate a secure token for password reset emails.

        This token should be:
        - Cryptographically random
        - Single-use
        - Time-limited (expires in 1 hour)

        Args:
            user_id: User ID for whom to generate reset token

        Returns:
            URL-safe reset token
        """
        # Generate a secure random token
        token = secrets.token_urlsafe(32)

        # In production, this would be stored in database with expiry
        # and associated with user_id

        return token


class DataEncryption:
    """
    Handles encryption of sensitive data at rest.

    Used for encrypting:
    - Social Security Numbers
    - Credit card numbers (for payment processing)
    - API keys and secrets
    - PHI (Protected Health Information) in audit logs
    """

    def __init__(self, encryption_key: bytes):
        """
        Initialize encryption service with a key.

        Args:
            encryption_key: 32-byte AES encryption key
        """
        self.key = encryption_key

    def encrypt_field(self, plaintext: str) -> str:
        """
        Encrypt a sensitive field for storage.

        Uses AES-256-GCM for authenticated encryption.

        Args:
            plaintext: Sensitive data to encrypt

        Returns:
            Base64-encoded ciphertext with nonce
        """
        # In production, would use cryptography library's AES-GCM
        # Simplified for demo
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(self.key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        # Combine nonce + ciphertext and encode as base64
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode()

    def decrypt_field(self, ciphertext_b64: str) -> Optional[str]:
        """
        Decrypt a sensitive field.

        Args:
            ciphertext_b64: Base64-encoded ciphertext with nonce

        Returns:
            Decrypted plaintext or None if decryption fails
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            combined = base64.b64decode(ciphertext_b64)
            nonce = combined[:12]
            ciphertext = combined[12:]

            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return plaintext.decode()

        except Exception as e:
            # Decryption failure could indicate:
            # - Wrong key
            # - Corrupted ciphertext
            # - Tampering
            return None


def generate_api_key() -> Tuple[str, str]:
    """
    Generate a new API key for external integrations.

    Returns:
        Tuple of (api_key, api_key_hash)
        - api_key: Show to user once (never stored in plain text)
        - api_key_hash: Store in database for verification
    """
    api_key = secrets.token_urlsafe(32)

    # Hash the API key for storage (using SHA-256 which is acceptable for API keys)
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    return api_key, api_key_hash


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal
    """
    return hmac.compare_digest(a, b)
