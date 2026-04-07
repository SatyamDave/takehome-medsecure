"""Tests for cryptographic utilities - password hashing (SEC-2025-1149)."""

import pytest
import bcrypt

from src.utils.crypto import PasswordHasher


class TestPasswordHasher:
    """Test bcrypt-based password hashing."""

    def test_hash_password_returns_bcrypt_hash(self):
        """Test that hash_password returns a valid bcrypt hash, not MD5."""
        password = "SecureP@ssw0rd!"
        hashed = PasswordHasher.hash_password(password)

        # bcrypt hashes start with '$2b$' and are 60 characters long
        assert hashed.startswith("$2b$"), "Hash must be a bcrypt hash, not MD5"
        assert len(hashed) == 60

    def test_hash_password_includes_salt(self):
        """Test that hashing the same password twice produces different hashes (salted)."""
        password = "SamePassword123"
        hash1 = PasswordHasher.hash_password(password)
        hash2 = PasswordHasher.hash_password(password)

        assert hash1 != hash2, "Each hash must use a unique salt"

    def test_hash_password_not_md5(self):
        """Verify the vulnerability is fixed: output must not be an MD5 hex digest."""
        import hashlib

        password = "TestPassword"
        hashed = PasswordHasher.hash_password(password)
        md5_hash = hashlib.md5(password.encode()).hexdigest()

        assert hashed != md5_hash, "Password hash must not be MD5"
        # MD5 hex digests are exactly 32 hex characters
        assert len(hashed) != 32, "Hash length must not match MD5 output"

    def test_verify_password_correct(self):
        """Test that verify_password returns True for correct password."""
        password = "CorrectHorse!Battery"
        hashed = PasswordHasher.hash_password(password)

        assert PasswordHasher.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test that verify_password returns False for wrong password."""
        password = "CorrectPassword"
        wrong_password = "WrongPassword"
        hashed = PasswordHasher.hash_password(password)

        assert PasswordHasher.verify_password(wrong_password, hashed) is False

    def test_hash_password_uses_correct_work_factor(self):
        """Test that the bcrypt work factor matches the configured rounds."""
        password = "WorkFactorTest"
        hashed = PasswordHasher.hash_password(password)

        # bcrypt hash format: $2b$<rounds>$<salt+hash>
        rounds = int(hashed.split("$")[2])
        assert rounds == PasswordHasher.BCRYPT_ROUNDS

    def test_verify_password_empty_password(self):
        """Test hashing and verifying an empty password doesn't crash."""
        password = ""
        hashed = PasswordHasher.hash_password(password)

        assert PasswordHasher.verify_password(password, hashed) is True
        assert PasswordHasher.verify_password("notempty", hashed) is False

    def test_verify_password_unicode(self):
        """Test that unicode passwords are handled correctly."""
        password = "pässwörd_日本語_🔒"
        hashed = PasswordHasher.hash_password(password)

        assert PasswordHasher.verify_password(password, hashed) is True
        assert PasswordHasher.verify_password("different", hashed) is False
