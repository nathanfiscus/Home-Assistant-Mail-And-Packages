"""OAuth handler for Mail and Packages."""

import functools as ft
import logging
import time
import urllib.parse
from typing import Any, Dict, Optional

import requests

_LOGGER = logging.getLogger(__name__)

GMAIL_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GMAIL_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_SCOPE = "https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email"
GMAIL_IMAP_HOST = "imap.gmail.com"

OUTLOOK_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
OUTLOOK_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
OUTLOOK_SCOPE = (
    "https://outlook.office.com/IMAP.AccessAsUser.All offline_access openid profile email"
)
OUTLOOK_IMAP_HOST = "outlook.office365.com"

IMAP_PORT = 993


def get_oauth_urls(provider: str) -> Dict[str, str]:
    """Return OAuth URLs and IMAP host for the given provider.

    Args:
        provider: "gmail" or "outlook"

    Returns:
        Dict with keys: auth_url, token_url, scope, imap_host, imap_port
    """
    if provider == "gmail":
        return {
            "auth_url": GMAIL_AUTH_URL,
            "token_url": GMAIL_TOKEN_URL,
            "scope": GMAIL_SCOPE,
            "imap_host": GMAIL_IMAP_HOST,
            "imap_port": IMAP_PORT,
        }
    if provider == "outlook":
        return {
            "auth_url": OUTLOOK_AUTH_URL,
            "token_url": OUTLOOK_TOKEN_URL,
            "scope": OUTLOOK_SCOPE,
            "imap_host": OUTLOOK_IMAP_HOST,
            "imap_port": IMAP_PORT,
        }
    raise ValueError(f"Unsupported provider: {provider}")


def build_authorization_url(
    provider: str,
    client_id: str,
    redirect_uri: str,
    state: str = "mail_and_packages",
) -> str:
    """Build the OAuth authorization URL for the given provider.

    Args:
        provider: "gmail" or "outlook"
        client_id: OAuth client ID
        redirect_uri: Callback URL registered with the OAuth provider
        state: CSRF protection state parameter

    Returns:
        Full authorization URL string
    """
    urls = get_oauth_urls(provider)
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": urls["scope"],
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    return f"{urls['auth_url']}?{query}"


async def exchange_code_for_token(
    hass: Any,
    provider: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> Optional[Dict[str, Any]]:
    """Exchange an authorization code for an access token.

    Args:
        hass: Home Assistant instance
        provider: "gmail" or "outlook"
        client_id: OAuth client ID
        client_secret: OAuth client secret
        code: Authorization code from OAuth callback
        redirect_uri: Same redirect URI used in the authorization request

    Returns:
        Token response dict or None on failure
    """
    urls = get_oauth_urls(provider)
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    try:
        response = await hass.async_add_executor_job(
            ft.partial(
                requests.post,
                urls["token_url"],
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
        )
        if response.status_code != 200:
            _LOGGER.error("Token exchange failed (%s): %s", response.status_code, response.text)
            return None
        return response.json()
    except requests.RequestException as err:
        _LOGGER.error("Token exchange request error: %s", err)
        return None


async def refresh_access_token(
    hass: Any,
    provider: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
) -> Optional[Dict[str, Any]]:
    """Refresh an expired access token.

    Args:
        hass: Home Assistant instance
        provider: "gmail" or "outlook"
        client_id: OAuth client ID
        client_secret: OAuth client secret
        refresh_token: Refresh token from initial token exchange

    Returns:
        Token response dict or None on failure
    """
    urls = get_oauth_urls(provider)
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    try:
        response = await hass.async_add_executor_job(
            ft.partial(
                requests.post,
                urls["token_url"],
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
        )
        if response.status_code != 200:
            _LOGGER.error("Token refresh failed (%s): %s", response.status_code, response.text)
            return None
        return response.json()
    except requests.RequestException as err:
        _LOGGER.error("Token refresh request error: %s", err)
        return None


async def get_user_email(
    hass: Any,
    provider: str,
    access_token: str,
) -> Optional[str]:
    """Retrieve the authenticated user's email address.

    Args:
        hass: Home Assistant instance
        provider: "gmail" or "outlook"
        access_token: Valid OAuth access token

    Returns:
        Email address string or None on failure
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        if provider == "gmail":
            response = await hass.async_add_executor_job(
                ft.partial(
                    requests.get,
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers=headers,
                    timeout=30,
                )
            )
            if response.status_code == 200:
                return response.json().get("email")
            _LOGGER.error("Gmail userinfo failed (%s): %s", response.status_code, response.text)
            return None

        if provider == "outlook":
            response = await hass.async_add_executor_job(
                ft.partial(
                    requests.get,
                    "https://graph.microsoft.com/v1.0/me",
                    headers=headers,
                    timeout=30,
                )
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("mail") or data.get("userPrincipalName")
            _LOGGER.error(
                "Outlook userinfo failed (%s): %s", response.status_code, response.text
            )
            return None

        _LOGGER.error("Unsupported provider: %s", provider)
        return None
    except requests.RequestException as err:
        _LOGGER.error("User email fetch error: %s", err)
        return None


def is_token_expired(expiry_timestamp: int, buffer_seconds: int = 300) -> bool:
    """Return True if the access token is expired or expires within buffer_seconds.

    Args:
        expiry_timestamp: Unix timestamp when token expires
        buffer_seconds: Seconds before expiry to consider token as expired (default 5 min)

    Returns:
        True if token is expired or expiring soon
    """
    return time.time() >= (expiry_timestamp - buffer_seconds)
