"""OAuth handler for Mail and Packages component.

Provides helper functions for OAuth2 authentication with Gmail and Outlook,
including URL generation, token exchange, token refresh, and user-email lookup.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import aiohttp

from .const import (
    OAUTH_PROVIDERS,
    OAUTH_SCOPE,
    OAUTH_TOKEN_URL,
)

_LOGGER = logging.getLogger(__name__)


def get_oauth_url(
    provider: str,
    client_id: str,
    redirect_uri: str,
    state: str,
) -> str:
    """Return the OAuth2 authorisation URL for *provider*.

    Args:
        provider:     ``"gmail"`` or ``"outlook"``.
        client_id:    The OAuth2 client ID registered with the provider.
        redirect_uri: The callback URL that the provider should redirect to.
        state:        An opaque value used to prevent CSRF attacks.

    Returns:
        A fully-qualified URL that the user should be redirected to.

    """
    provider_cfg = OAUTH_PROVIDERS.get(provider)
    if provider_cfg is None:
        raise ValueError(f"Unsupported OAuth provider: {provider!r}")

    auth_url = provider_cfg["auth_url"]
    scope = OAUTH_SCOPE[provider]

    params = (
        f"client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={scope}"
        f"&state={state}"
        f"&access_type=offline"
        f"&prompt=consent"
    )
    return f"{auth_url}?{params}"


async def exchange_code_for_token(
    provider: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange an authorisation *code* for access and refresh tokens.

    Args:
        provider:       ``"gmail"`` or ``"outlook"``.
        client_id:      OAuth2 client ID.
        client_secret:  OAuth2 client secret.
        code:           The authorisation code returned by the provider.
        redirect_uri:   Must match the redirect URI used in the auth request.

    Returns:
        A dict containing at least ``access_token``, ``refresh_token``,
        ``expires_in``, and a computed ``expires_at`` Unix timestamp.

    Raises:
        ValueError: If the provider is not supported or the token exchange fails.

    """
    token_url = OAUTH_TOKEN_URL.get(provider)
    if token_url is None:
        raise ValueError(f"Unsupported OAuth provider: {provider!r}")

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(token_url, data=payload) as resp:
            if resp.status != 200:
                text = await resp.text()
                _LOGGER.error(
                    "Token exchange failed (HTTP %s): %s", resp.status, text
                )
                raise ValueError(
                    f"Token exchange failed with status {resp.status}: {text}"
                )
            token_data: dict[str, Any] = await resp.json()

    if "error" in token_data:
        _LOGGER.error("Token exchange error: %s", token_data)
        raise ValueError(
            f"Token exchange error: {token_data.get('error_description', token_data['error'])}"
        )

    # Compute absolute expiry timestamp (5-minute safety margin)
    expires_in = int(token_data.get("expires_in", 3600))
    token_data["expires_at"] = int(time.time()) + expires_in - 300

    return token_data


async def refresh_access_token(
    provider: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
) -> dict[str, Any]:
    """Obtain a new access token using *refresh_token*.

    Args:
        provider:       ``"gmail"`` or ``"outlook"``.
        client_id:      OAuth2 client ID.
        client_secret:  OAuth2 client secret.
        refresh_token:  The long-lived refresh token.

    Returns:
        A dict containing at least ``access_token`` and a computed
        ``expires_at`` Unix timestamp.  ``refresh_token`` may also be present
        when the provider rotates the refresh token.

    Raises:
        ValueError: If the provider is not supported or the refresh fails.

    """
    token_url = OAUTH_TOKEN_URL.get(provider)
    if token_url is None:
        raise ValueError(f"Unsupported OAuth provider: {provider!r}")

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(token_url, data=payload) as resp:
            if resp.status != 200:
                text = await resp.text()
                _LOGGER.error(
                    "Token refresh failed (HTTP %s): %s", resp.status, text
                )
                raise ValueError(
                    f"Token refresh failed with status {resp.status}: {text}"
                )
            token_data: dict[str, Any] = await resp.json()

    if "error" in token_data:
        _LOGGER.error("Token refresh error: %s", token_data)
        raise ValueError(
            f"Token refresh error: {token_data.get('error_description', token_data['error'])}"
        )

    expires_in = int(token_data.get("expires_in", 3600))
    token_data["expires_at"] = int(time.time()) + expires_in - 300

    return token_data


async def get_user_email(provider: str, access_token: str) -> str:
    """Fetch the authenticated user's email address from the provider.

    Args:
        provider:     ``"gmail"`` or ``"outlook"``.
        access_token: A valid OAuth2 access token.

    Returns:
        The user's primary email address string.

    Raises:
        ValueError: If the provider is unsupported or the request fails.

    """
    provider_cfg = OAUTH_PROVIDERS.get(provider)
    if provider_cfg is None:
        raise ValueError(f"Unsupported OAuth provider: {provider!r}")

    userinfo_url = provider_cfg["userinfo_url"]
    headers = {"Authorization": f"Bearer {access_token}"}

    async with aiohttp.ClientSession() as session:
        async with session.get(userinfo_url, headers=headers) as resp:
            if resp.status != 200:
                text = await resp.text()
                _LOGGER.error(
                    "User-info request failed (HTTP %s): %s", resp.status, text
                )
                raise ValueError(
                    f"User-info request failed with status {resp.status}: {text}"
                )
            data: dict[str, Any] = await resp.json()

    # Gmail returns {"email": "..."}, Outlook returns {"mail": "..." or "userPrincipalName": "..."}
    email = (
        data.get("email")
        or data.get("mail")
        or data.get("userPrincipalName")
    )
    if not email:
        raise ValueError(f"Could not determine user email from provider response: {data}")

    return email


def is_token_expired(expires_at: int) -> bool:
    """Return ``True`` if the token has expired (or expires within 5 minutes)."""
    return int(time.time()) >= expires_at
