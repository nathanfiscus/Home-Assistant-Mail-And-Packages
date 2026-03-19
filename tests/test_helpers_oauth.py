"""Tests for OAuth-related helpers in helpers.py."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.core import HomeAssistant

from custom_components.mail_and_packages.const import (
    CONF_ACCESS_TOKEN_EXPIRY,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_ENCRYPTED_ACCESS_TOKEN,
    CONF_ENCRYPTED_REFRESH_TOKEN,
    CONF_OAUTH_PROVIDER,
    CONF_TOKEN_SALT,
)
from custom_components.mail_and_packages.crypto import Cryptographer
from custom_components.mail_and_packages.helpers import _resolve_oauth_access_token


@pytest.mark.asyncio
async def test_resolve_oauth_token_valid(hass: HomeAssistant):
    """Returns plaintext access token when token has not expired."""
    password = "test-client-secret"
    cryptographer = Cryptographer(password)
    access_token = "fresh_access_token_abc"
    encrypted_access = cryptographer.encrypt(access_token)

    config = {
        CONF_CLIENT_SECRET: password,
        CONF_TOKEN_SALT: cryptographer.salt_hex,
        CONF_ENCRYPTED_ACCESS_TOKEN: encrypted_access,
        CONF_ENCRYPTED_REFRESH_TOKEN: "",
        CONF_ACCESS_TOKEN_EXPIRY: int(time.time()) + 3600,  # 1 hour from now
    }

    result = await _resolve_oauth_access_token(hass, config)

    assert result == access_token


@pytest.mark.asyncio
async def test_resolve_oauth_token_missing_salt(hass: HomeAssistant, caplog):
    """Returns None and logs error when token salt is absent."""
    config = {
        CONF_CLIENT_SECRET: "secret",
        CONF_TOKEN_SALT: "",  # missing
        CONF_ENCRYPTED_ACCESS_TOKEN: "some_ciphertext",
        CONF_ACCESS_TOKEN_EXPIRY: int(time.time()) + 3600,
    }

    result = await _resolve_oauth_access_token(hass, config)

    assert result is None
    assert "OAuth token salt missing from config" in caplog.text


@pytest.mark.asyncio
async def test_resolve_oauth_token_missing_access_token(hass: HomeAssistant, caplog):
    """Returns None and logs error when encrypted access token is absent."""
    password = "test-client-secret"
    cryptographer = Cryptographer(password)

    config = {
        CONF_CLIENT_SECRET: password,
        CONF_TOKEN_SALT: cryptographer.salt_hex,
        CONF_ENCRYPTED_ACCESS_TOKEN: "",  # missing
        CONF_ACCESS_TOKEN_EXPIRY: int(time.time()) + 3600,
    }

    result = await _resolve_oauth_access_token(hass, config)

    assert result is None
    assert "OAuth access token missing from config" in caplog.text


@pytest.mark.asyncio
async def test_resolve_oauth_token_expired_refreshes(hass: HomeAssistant):
    """When token is expired, refresh is attempted and new token returned."""
    password = "test-secret"
    cryptographer = Cryptographer(password)
    old_access = "old_access_token"
    refresh_tok = "refresh_token_xyz"
    encrypted_access = cryptographer.encrypt(old_access)
    encrypted_refresh = cryptographer.encrypt(refresh_tok)

    new_access = "new_access_token_after_refresh"
    new_expires = int(time.time()) + 3600

    config = {
        CONF_CLIENT_SECRET: password,
        CONF_TOKEN_SALT: cryptographer.salt_hex,
        CONF_ENCRYPTED_ACCESS_TOKEN: encrypted_access,
        CONF_ENCRYPTED_REFRESH_TOKEN: encrypted_refresh,
        CONF_ACCESS_TOKEN_EXPIRY: int(time.time()) - 100,  # expired
        CONF_OAUTH_PROVIDER: "gmail",
        CONF_CLIENT_ID: "my-client-id",
    }

    with patch(
        "custom_components.mail_and_packages.oauth_handler.refresh_access_token",
        new=AsyncMock(
            return_value={"access_token": new_access, "expires_at": new_expires}
        ),
    ):
        result = await _resolve_oauth_access_token(hass, config)

    assert result == new_access
    # Config dict should be updated with new encrypted access token
    assert config[CONF_ACCESS_TOKEN_EXPIRY] == new_expires


@pytest.mark.asyncio
async def test_resolve_oauth_token_expired_no_refresh_token(
    hass: HomeAssistant, caplog
):
    """Returns None when token is expired and no refresh token is stored."""
    password = "test-secret"
    cryptographer = Cryptographer(password)
    encrypted_access = cryptographer.encrypt("old_access")

    config = {
        CONF_CLIENT_SECRET: password,
        CONF_TOKEN_SALT: cryptographer.salt_hex,
        CONF_ENCRYPTED_ACCESS_TOKEN: encrypted_access,
        CONF_ENCRYPTED_REFRESH_TOKEN: "",  # no refresh token
        CONF_ACCESS_TOKEN_EXPIRY: int(time.time()) - 100,  # expired
    }

    result = await _resolve_oauth_access_token(hass, config)

    assert result is None


@pytest.mark.asyncio
async def test_resolve_oauth_token_refresh_network_failure(hass: HomeAssistant, caplog):
    """Returns None when token refresh fails with a network/provider error."""
    password = "test-secret"
    cryptographer = Cryptographer(password)
    encrypted_access = cryptographer.encrypt("old_access")
    encrypted_refresh = cryptographer.encrypt("refresh_tok")

    config = {
        CONF_CLIENT_SECRET: password,
        CONF_TOKEN_SALT: cryptographer.salt_hex,
        CONF_ENCRYPTED_ACCESS_TOKEN: encrypted_access,
        CONF_ENCRYPTED_REFRESH_TOKEN: encrypted_refresh,
        CONF_ACCESS_TOKEN_EXPIRY: int(time.time()) - 100,  # expired
        CONF_OAUTH_PROVIDER: "gmail",
        CONF_CLIENT_ID: "cid",
    }

    with patch(
        "custom_components.mail_and_packages.oauth_handler.refresh_access_token",
        new=AsyncMock(side_effect=ValueError("Token refresh failed with status 400")),
    ):
        result = await _resolve_oauth_access_token(hass, config)

    assert result is None


@pytest.mark.asyncio
async def test_resolve_oauth_token_refresh_rotates_refresh_token(hass: HomeAssistant):
    """When provider returns a new refresh token, it is stored encrypted."""
    password = "test-secret"
    cryptographer = Cryptographer(password)
    old_access = "old_access"
    refresh_tok = "old_refresh_token"
    encrypted_access = cryptographer.encrypt(old_access)
    encrypted_refresh = cryptographer.encrypt(refresh_tok)

    new_access = "new_access_token"
    new_refresh = "new_refresh_token"
    new_expires = int(time.time()) + 3600

    config = {
        CONF_CLIENT_SECRET: password,
        CONF_TOKEN_SALT: cryptographer.salt_hex,
        CONF_ENCRYPTED_ACCESS_TOKEN: encrypted_access,
        CONF_ENCRYPTED_REFRESH_TOKEN: encrypted_refresh,
        CONF_ACCESS_TOKEN_EXPIRY: int(time.time()) - 100,  # expired
        CONF_OAUTH_PROVIDER: "gmail",
        CONF_CLIENT_ID: "cid",
    }

    with patch(
        "custom_components.mail_and_packages.oauth_handler.refresh_access_token",
        new=AsyncMock(
            return_value={
                "access_token": new_access,
                "refresh_token": new_refresh,
                "expires_at": new_expires,
            }
        ),
    ):
        result = await _resolve_oauth_access_token(hass, config)

    assert result == new_access
    # The new refresh token should be encrypted and stored in the config dict.
    # Verify by decrypting with the same cryptographer.
    stored_refresh = config[CONF_ENCRYPTED_REFRESH_TOKEN]
    decrypted_refresh = cryptographer.decrypt(stored_refresh)
    assert decrypted_refresh == new_refresh
