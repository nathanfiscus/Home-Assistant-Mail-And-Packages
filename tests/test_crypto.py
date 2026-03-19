"""Tests for the Cryptographer class in crypto.py."""

import pytest
from cryptography.fernet import InvalidToken

from custom_components.mail_and_packages.crypto import Cryptographer


class TestCryptographer:
    """Tests for the Cryptographer class."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt returns the original plaintext."""
        c = Cryptographer("secret-password")
        plaintext = "my-oauth-token-value"
        ciphertext = c.encrypt(plaintext)
        assert c.decrypt(ciphertext) == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        """Encrypted output must not equal the plaintext."""
        c = Cryptographer("secret-password")
        plaintext = "access_token_abc123"
        ciphertext = c.encrypt(plaintext)
        assert ciphertext != plaintext

    def test_salt_generated_when_not_provided(self):
        """A random salt is generated when none is supplied."""
        c1 = Cryptographer("password")
        c2 = Cryptographer("password")
        # Two instances with the same password produce different salts
        assert c1.salt != c2.salt

    def test_salt_used_when_provided(self):
        """Supplied salt is stored as-is."""
        salt = b"\x00" * 16
        c = Cryptographer("password", salt=salt)
        assert c.salt == salt

    def test_salt_hex_is_valid_hex_string(self):
        """salt_hex returns a hex-encoded string with the correct length."""
        c = Cryptographer("password")
        hex_salt = c.salt_hex
        # 16 bytes → 32 hex chars
        assert len(hex_salt) == 32
        assert all(ch in "0123456789abcdef" for ch in hex_salt)

    def test_from_salt_hex_roundtrip(self):
        """from_salt_hex rebuilds a Cryptographer that can decrypt prior ciphertext."""
        c1 = Cryptographer("shared-secret")
        plaintext = "refresh_token_xyz"
        ciphertext = c1.encrypt(plaintext)
        salt_hex = c1.salt_hex

        c2 = Cryptographer.from_salt_hex("shared-secret", salt_hex)
        assert c2.decrypt(ciphertext) == plaintext

    def test_wrong_password_raises(self):
        """Decrypting with a different password raises an exception."""
        c_enc = Cryptographer("correct-password")
        ciphertext = c_enc.encrypt("secret")
        salt_hex = c_enc.salt_hex

        c_dec = Cryptographer.from_salt_hex("wrong-password", salt_hex)
        with pytest.raises(InvalidToken):
            c_dec.decrypt(ciphertext)

    def test_empty_plaintext(self):
        """Empty string can be encrypted and decrypted."""
        c = Cryptographer("password")
        assert c.decrypt(c.encrypt("")) == ""

    def test_unicode_plaintext(self):
        """Unicode strings are encrypted and decrypted correctly."""
        c = Cryptographer("password")
        plaintext = "tëst_tökën_üñícode"
        assert c.decrypt(c.encrypt(plaintext)) == plaintext
