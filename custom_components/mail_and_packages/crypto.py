"""Cryptography utilities for Mail and Packages OAuth token storage."""

from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 100_000
SALT_LENGTH = 16


class Cryptographer:
    """Encrypt and decrypt OAuth tokens using PBKDF2 + Fernet.

    The salt is generated randomly on first use and must be stored alongside the
    ciphertext so that the same key can be re-derived on decryption.
    """

    def __init__(self, password: str, salt: bytes | None = None) -> None:
        """Initialise the cryptographer.

        Args:
            password: The secret used to derive the encryption key (typically the
                      Home Assistant instance secret / client_secret).
            salt: Optional 16-byte salt.  A new random salt is generated when
                  omitted (i.e. on first encryption).

        """
        self.salt: bytes = salt if salt is not None else os.urandom(SALT_LENGTH)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* and return a base-64 encoded ciphertext string."""
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a base-64 encoded *ciphertext* and return the plaintext string."""
        return self._fernet.decrypt(ciphertext.encode()).decode()

    @property
    def salt_hex(self) -> str:
        """Return the salt as a hex string for storage in config entry data."""
        return self.salt.hex()

    @classmethod
    def from_salt_hex(cls, password: str, salt_hex: str) -> "Cryptographer":
        """Reconstruct a Cryptographer from a stored hex salt."""
        return cls(password, bytes.fromhex(salt_hex))
