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

import bcrypt


class PasswordHasher:
    """
    Handles password hashing for user authentication.

    Uses bcrypt with automatic salting and configurable work factor
    for industry-standard password hashing.

    Security audit finding: MS-SEC-2024-05 (identified 2024-09-20)
    Remediated: Replaced MD5 with bcrypt (SEC-2025-1149)
    """

    # bcrypt work factor (cost parameter). 12 is the recommended minimum.
    BCRYPT_ROUNDS = 12

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password for storage using bcrypt.

        Bcrypt automatically generates a unique salt per hash and applies
        key stretching to resist brute-force attacks.

        Args:
            password: Plain text password

        Returns:
            Bcrypt hashed password string
        """
        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt(rounds=PasswordHasher.BCRYPT_ROUNDS)
        )
        return password_hash.decode()

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify a password against its bcrypt hash.

        Uses bcrypt's built-in constant-time comparison to prevent
        timing attacks.

        Args:
            password: Plain text password to verify
            hashed_password: Stored bcrypt hash

        Returns:
            True if password matches, False otherwise
        """
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

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
