"""Tests for the OAuth handler module."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.mail_and_packages.oauth_handler import (
    GMAIL_AUTH_URL,
    GMAIL_IMAP_HOST,
    GMAIL_TOKEN_URL,
    IMAP_PORT,
    OUTLOOK_AUTH_URL,
    OUTLOOK_IMAP_HOST,
    OUTLOOK_TOKEN_URL,
    build_authorization_url,
    get_oauth_urls,
    is_token_expired,
)


# ---------------------------------------------------------------------------
# get_oauth_urls
# ---------------------------------------------------------------------------


def test_get_oauth_urls_gmail():
    """Gmail provider returns correct URLs and IMAP host."""
    urls = get_oauth_urls("gmail")
    assert urls["auth_url"] == GMAIL_AUTH_URL
    assert urls["token_url"] == GMAIL_TOKEN_URL
    assert urls["imap_host"] == GMAIL_IMAP_HOST
    assert urls["imap_port"] == IMAP_PORT
    assert "mail.google.com" in urls["scope"]


def test_get_oauth_urls_outlook():
    """Outlook provider returns correct URLs and IMAP host."""
    urls = get_oauth_urls("outlook")
    assert urls["auth_url"] == OUTLOOK_AUTH_URL
    assert urls["token_url"] == OUTLOOK_TOKEN_URL
    assert urls["imap_host"] == OUTLOOK_IMAP_HOST
    assert urls["imap_port"] == IMAP_PORT
    assert "IMAP.AccessAsUser.All" in urls["scope"]


def test_get_oauth_urls_unsupported():
    """Unsupported provider raises ValueError."""
    with pytest.raises(ValueError, match="Unsupported provider"):
        get_oauth_urls("yahoo")


# ---------------------------------------------------------------------------
# build_authorization_url
# ---------------------------------------------------------------------------


def test_build_authorization_url_gmail():
    """Authorization URL for Gmail contains required parameters."""
    url = build_authorization_url(
        provider="gmail",
        client_id="test-client-id",
        redirect_uri="http://homeassistant.local/callback",
    )
    assert GMAIL_AUTH_URL in url
    assert "client_id=test-client-id" in url
    assert "response_type=code" in url
    assert "mail_and_packages" in url  # state parameter


def test_build_authorization_url_outlook():
    """Authorization URL for Outlook contains required parameters."""
    url = build_authorization_url(
        provider="outlook",
        client_id="azure-client-id",
        redirect_uri="http://homeassistant.local/callback",
    )
    assert OUTLOOK_AUTH_URL in url
    assert "azure-client-id" in url
    assert "offline_access" in url  # scope should include offline_access for refresh token


def test_build_authorization_url_custom_state():
    """Custom state parameter is included in the URL."""
    url = build_authorization_url(
        provider="gmail",
        client_id="id",
        redirect_uri="http://localhost/cb",
        state="my-custom-state",
    )
    assert "my-custom-state" in url


# ---------------------------------------------------------------------------
# is_token_expired
# ---------------------------------------------------------------------------


def test_is_token_expired_future():
    """A token expiring in the future (beyond buffer) is not expired."""
    future_expiry = int(time.time()) + 600  # 10 minutes from now
    assert is_token_expired(future_expiry) is False


def test_is_token_expired_past():
    """A token with an expiry in the past is expired."""
    past_expiry = int(time.time()) - 60
    assert is_token_expired(past_expiry) is True


def test_is_token_expired_within_buffer():
    """A token expiring within the buffer period is considered expired."""
    near_expiry = int(time.time()) + 100  # within default 300s buffer
    assert is_token_expired(near_expiry) is True


def test_is_token_expired_custom_buffer():
    """Custom buffer seconds are respected."""
    expiry = int(time.time()) + 60
    assert is_token_expired(expiry, buffer_seconds=30) is False
    assert is_token_expired(expiry, buffer_seconds=120) is True


# ---------------------------------------------------------------------------
# exchange_code_for_token (mocked HTTP calls)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exchange_code_for_token_success():
    """Successful token exchange returns token dict."""
    from custom_components.mail_and_packages.oauth_handler import exchange_code_for_token

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "new-access-token",
        "refresh_token": "new-refresh-token",
        "expires_in": 3600,
    }

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock(return_value=mock_response)

    result = await exchange_code_for_token(
        mock_hass,
        provider="gmail",
        client_id="cid",
        client_secret="csecret",
        code="auth-code",
        redirect_uri="http://localhost/cb",
    )

    assert result is not None
    assert result["access_token"] == "new-access-token"
    assert result["refresh_token"] == "new-refresh-token"


@pytest.mark.asyncio
async def test_exchange_code_for_token_failure():
    """Failed token exchange (non-200) returns None."""
    from custom_components.mail_and_packages.oauth_handler import exchange_code_for_token

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Bad Request"

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock(return_value=mock_response)

    result = await exchange_code_for_token(
        mock_hass,
        provider="outlook",
        client_id="cid",
        client_secret="csecret",
        code="bad-code",
        redirect_uri="http://localhost/cb",
    )

    assert result is None


# ---------------------------------------------------------------------------
# refresh_access_token (mocked HTTP calls)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_access_token_success():
    """Successful token refresh returns new token dict."""
    from custom_components.mail_and_packages.oauth_handler import refresh_access_token

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "refreshed-token",
        "expires_in": 3600,
    }

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock(return_value=mock_response)

    result = await refresh_access_token(
        mock_hass,
        provider="gmail",
        client_id="cid",
        client_secret="csecret",
        refresh_token="old-refresh",
    )

    assert result is not None
    assert result["access_token"] == "refreshed-token"


@pytest.mark.asyncio
async def test_refresh_access_token_failure():
    """Failed token refresh returns None."""
    from custom_components.mail_and_packages.oauth_handler import refresh_access_token

    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock(return_value=mock_response)

    result = await refresh_access_token(
        mock_hass,
        provider="outlook",
        client_id="cid",
        client_secret="csecret",
        refresh_token="expired-refresh",
    )

    assert result is None


# ---------------------------------------------------------------------------
# get_user_email (mocked HTTP calls)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_user_email_gmail():
    """Gmail userinfo endpoint returns email address."""
    from custom_components.mail_and_packages.oauth_handler import get_user_email

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"email": "user@gmail.com"}

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock(return_value=mock_response)

    email = await get_user_email(mock_hass, "gmail", "access-token")
    assert email == "user@gmail.com"


@pytest.mark.asyncio
async def test_get_user_email_outlook():
    """Outlook Graph API returns email address."""
    from custom_components.mail_and_packages.oauth_handler import get_user_email

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "mail": "user@outlook.com",
        "userPrincipalName": "user@outlook.com",
    }

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock(return_value=mock_response)

    email = await get_user_email(mock_hass, "outlook", "access-token")
    assert email == "user@outlook.com"


@pytest.mark.asyncio
async def test_get_user_email_unsupported_provider():
    """Unsupported provider returns None."""
    from custom_components.mail_and_packages.oauth_handler import get_user_email

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock()

    email = await get_user_email(mock_hass, "yahoo", "access-token")
    assert email is None


@pytest.mark.asyncio
async def test_get_user_email_api_failure():
    """API failure returns None."""
    from custom_components.mail_and_packages.oauth_handler import get_user_email

    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.text = "Forbidden"

    mock_hass = MagicMock()
    mock_hass.async_add_executor_job = AsyncMock(return_value=mock_response)

    email = await get_user_email(mock_hass, "gmail", "bad-token")
    assert email is None
