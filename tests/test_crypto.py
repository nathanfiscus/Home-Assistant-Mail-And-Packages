"""Tests for the crypto module."""

import os
from base64 import b64decode

import pytest

from custom_components.mail_and_packages.crypto import Cryptographer


def test_encrypt_decrypt_round_trip():
    """Encrypt and decrypt a value and verify round-trip correctness."""
    crypto = Cryptographer(password="test-password")
    plaintext = "my-secret-token"

    encrypted = crypto.encrypt(plaintext)
    assert encrypted != plaintext
    assert crypto.decrypt(encrypted) == plaintext


def test_salt_is_16_bytes():
    """Verify that the generated salt is 16 bytes (128-bit)."""
    crypto = Cryptographer(password="any-password")
    salt_bytes = b64decode(crypto.salt.encode("utf-8"))
    assert len(salt_bytes) == 16


def test_salt_reuse_produces_same_results():
    """Same salt and password should produce consistent encryption/decryption."""
    password = "consistent-password"
    crypto1 = Cryptographer(password=password)
    salt = crypto1.salt
    iterations = crypto1.iterations

    encrypted = crypto1.encrypt("secret-value")

    # Re-create with the same salt and iterations
    crypto2 = Cryptographer(password=password, salt=salt, iterations=iterations)
    assert crypto2.decrypt(encrypted) == "secret-value"


def test_different_passwords_cannot_decrypt():
    """A token encrypted with one password cannot be decrypted with another."""
    crypto1 = Cryptographer(password="password-one")
    salt = crypto1.salt
    iterations = crypto1.iterations
    encrypted = crypto1.encrypt("secret")

    crypto2 = Cryptographer(password="password-two", salt=salt, iterations=iterations)
    with pytest.raises(Exception):
        crypto2.decrypt(encrypted)


def test_iterations_defaults_to_max():
    """Default iterations should be the highest setting for new encryptors."""
    crypto = Cryptographer(password="test")
    assert crypto.iterations == Cryptographer.ITERATIONS


def test_requires_rotation_fresh_token():
    """A freshly encrypted token should not require rotation."""
    crypto = Cryptographer(password="test")
    encrypted = crypto.encrypt("value")
    assert crypto.requires_rotation(encrypted) is False


def test_requires_rotation_legacy_token():
    """A token encrypted with legacy iterations should require rotation."""
    from base64 import urlsafe_b64encode
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    password = "legacy-password"
    crypto = Cryptographer(password=password)
    salt = b64decode(crypto.salt.encode("utf-8"))

    # Encrypt using legacy iteration count
    legacy_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=Cryptographer.LEGACY_ITERATIONS,
        backend=default_backend(),
    ).derive(password.encode("utf-8"))
    legacy_fernet = Fernet(urlsafe_b64encode(legacy_key))
    legacy_encrypted = legacy_fernet.encrypt(b"legacy-token").decode("utf-8")

    # Re-create crypto with the same salt so it can still decrypt
    crypto2 = Cryptographer(password=password, salt=crypto.salt)
    assert crypto2.requires_rotation(legacy_encrypted) is True


def test_rotate_upgrades_legacy_token():
    """Rotating a legacy-encrypted token should make it decryptable with current settings."""
    from base64 import urlsafe_b64encode
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    password = "rotate-test"
    crypto = Cryptographer(password=password)
    salt = b64decode(crypto.salt.encode("utf-8"))

    legacy_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=Cryptographer.LEGACY_ITERATIONS,
        backend=default_backend(),
    ).derive(password.encode("utf-8"))
    legacy_fernet = Fernet(urlsafe_b64encode(legacy_key))
    legacy_encrypted = legacy_fernet.encrypt(b"rotate-me").decode("utf-8")

    crypto2 = Cryptographer(password=password, salt=crypto.salt)
    rotated = crypto2.rotate(legacy_encrypted)
    assert crypto2.decrypt(rotated) == "rotate-me"
    assert crypto2.requires_rotation(rotated) is False


def test_custom_salt_accepted():
    """A custom base64 salt should be accepted and used correctly."""
    import base64

    custom_salt = base64.b64encode(os.urandom(16)).decode("utf-8")
    crypto = Cryptographer(password="my-pass", salt=custom_salt)
    assert crypto.salt == custom_salt


def test_invalid_salt_falls_back_to_new_salt():
    """An invalid base64 salt should silently generate a new random salt."""
    crypto = Cryptographer(password="my-pass", salt="!!!not-valid-base64!!!")
    # Should still work (new salt was generated)
    assert len(b64decode(crypto.salt)) == 16
    assert crypto.decrypt(crypto.encrypt("value")) == "value"
