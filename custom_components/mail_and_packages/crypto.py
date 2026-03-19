"""Token encryption for Mail and Packages OAuth support."""

import base64
import binascii
import logging
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_LOGGER = logging.getLogger(__name__)


class Cryptographer:
    """Encrypt/decrypt OAuth tokens using PBKDF2 + Fernet.

    Compatible with the email-oauth2-proxy token encryption scheme.
    """

    ITERATIONS = 1_200_000
    LEGACY_ITERATIONS = 100_000

    def __init__(
        self,
        password: str,
        salt: str = None,
        iterations: int = None,
    ) -> None:
        """Build a Fernet encryptor.

        Args:
            password: Encryption password (typically the HA secret key or client_secret).
            salt: Optional base64-encoded salt string; a new one is generated if not provided.
            iterations: Optional PBKDF2 iteration count; defaults to ITERATIONS.
        """
        self._salt: bytes

        if salt:
            try:
                self._salt = base64.b64decode(salt.encode("utf-8"))
            except (binascii.Error, UnicodeError):
                _LOGGER.info("Invalid token_salt; generating a new token_salt")
                self._salt = os.urandom(16)
        else:
            self._salt = os.urandom(16)

        stored_iterations = iterations if iterations is not None else self.LEGACY_ITERATIONS
        self._iterations_options = sorted(
            {self.ITERATIONS, stored_iterations, self.LEGACY_ITERATIONS},
            reverse=True,
        )
        self._fernets = [
            Fernet(
                base64.urlsafe_b64encode(
                    PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=self._salt,
                        iterations=iteration,
                        backend=default_backend(),
                    ).derive(password.encode("utf-8"))
                )
            )
            for iteration in self._iterations_options
        ]
        self.fernet = MultiFernet(self._fernets)

    @property
    def salt(self) -> str:
        """Return the current salt as base64 text."""
        return base64.b64encode(self._salt).decode("utf-8")

    @property
    def iterations(self) -> int:
        """Return the preferred iteration count for new secrets."""
        return self._iterations_options[0]

    def encrypt(self, value: str) -> str:
        """Encrypt a string value."""
        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str) -> str:
        """Decrypt a string value."""
        return self.fernet.decrypt(value.encode("utf-8")).decode("utf-8")

    def requires_rotation(self, value: str) -> bool:
        """Return whether an existing secret should be rotated to current settings."""
        try:
            self._fernets[0].decrypt(value.encode("utf-8"))
            return False
        except InvalidToken:
            try:
                self.decrypt(value)
                return True
            except InvalidToken:
                return False

    def rotate(self, value: str) -> str:
        """Rotate an encrypted value to the current preferred settings."""
        return self.fernet.rotate(value.encode("utf-8")).decode("utf-8")
