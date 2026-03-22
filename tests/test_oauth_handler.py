"""Tests for oauth_handler.py."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from custom_components.mail_and_packages.oauth_handler import (
    exchange_code_for_token,
    get_oauth_url,
    get_user_email,
    is_token_expired,
    refresh_access_token,
)


def _make_mock_response(status: int, payload: dict | None = None, text: str = ""):
    """Create a mock aiohttp response context-manager."""
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=payload or {})
    resp.text = AsyncMock(return_value=text)

    @asynccontextmanager
    async def _ctx(*args, **kwargs):
        yield resp

    return _ctx


def _make_mock_session(post_cm=None, get_cm=None):
    """Return a mock aiohttp.ClientSession as a context-manager."""
    session = MagicMock()
    if post_cm is not None:
        session.post = post_cm
    if get_cm is not None:
        session.get = get_cm

    @asynccontextmanager
    async def _session_ctx():
        yield session

    return _session_ctx


# ---------------------------------------------------------------------------
# get_oauth_url
# ---------------------------------------------------------------------------


class TestGetOauthUrl:
    """Tests for get_oauth_url."""

    def test_gmail_url_contains_required_params(self):
        """Gmail auth URL includes client_id, redirect_uri, scope, and state."""
        url = get_oauth_url(
            provider="gmail",
            client_id="my-client-id",
            redirect_uri="https://example.com/callback",
            state="random-state-token",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert parsed.netloc == "accounts.google.com"
        assert params["client_id"] == ["my-client-id"]
        assert params["redirect_uri"] == ["https://example.com/callback"]
        assert params["state"] == ["random-state-token"]
        assert params["response_type"] == ["code"]

    def test_outlook_url_contains_required_params(self):
        """Outlook auth URL includes client_id, redirect_uri, scope, and state."""
        url = get_oauth_url(
            provider="outlook",
            client_id="outlook-client-id",
            redirect_uri="https://example.com/callback",
            state="csrf-state",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert parsed.netloc == "login.microsoftonline.com"
        assert params["client_id"] == ["outlook-client-id"]

    def test_invalid_provider_raises(self):
        """Unknown provider raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported OAuth provider"):
            get_oauth_url("yahoo", "cid", "https://cb.example", "state")


# ---------------------------------------------------------------------------
# exchange_code_for_token
# ---------------------------------------------------------------------------


class TestExchangeCodeForToken:
    """Tests for exchange_code_for_token."""

    @pytest.mark.asyncio
    async def test_successful_exchange(self):
        """Returns token dict with expires_at on a 200 response."""
        token_payload = {
            "access_token": "ACCESS",
            "refresh_token": "REFRESH",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_resp = _make_mock_response(200, payload=token_payload)
        mock_session = _make_mock_session(post_cm=mock_resp)

        with patch(
            "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
            new=mock_session,
        ):
            result = await exchange_code_for_token(
                provider="gmail",
                client_id="cid",
                client_secret="csecret",
                code="authcode123",
                redirect_uri="https://cb.example",
            )

        assert result["access_token"] == "ACCESS"
        assert result["refresh_token"] == "REFRESH"
        assert result["expires_at"] > int(time.time())

    @pytest.mark.asyncio
    async def test_http_error_raises(self):
        """Non-200 HTTP response raises ValueError."""
        mock_resp = _make_mock_response(400, text="Bad Request")
        mock_session = _make_mock_session(post_cm=mock_resp)

        with (
            patch(
                "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
                new=mock_session,
            ),
            pytest.raises(ValueError, match="Token exchange failed with status"),
        ):
            await exchange_code_for_token(
                provider="gmail",
                client_id="cid",
                client_secret="csecret",
                code="bad-code",
                redirect_uri="https://cb.example",
            )

    @pytest.mark.asyncio
    async def test_error_in_response_raises(self):
        """Provider error payload raises ValueError."""
        error_payload = {
            "error": "invalid_grant",
            "error_description": "Code has been used already.",
        }
        mock_resp = _make_mock_response(200, payload=error_payload)
        mock_session = _make_mock_session(post_cm=mock_resp)

        with (
            patch(
                "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
                new=mock_session,
            ),
            pytest.raises(ValueError, match="Code has been used already"),
        ):
            await exchange_code_for_token(
                provider="gmail",
                client_id="cid",
                client_secret="csecret",
                code="expired-code",
                redirect_uri="https://cb.example",
            )

    @pytest.mark.asyncio
    async def test_invalid_provider_raises(self):
        """Unknown provider raises ValueError before any HTTP call."""
        with pytest.raises(ValueError, match="Unsupported OAuth provider"):
            await exchange_code_for_token(
                provider="yahoo",
                client_id="cid",
                client_secret="csecret",
                code="code",
                redirect_uri="https://cb.example",
            )


# ---------------------------------------------------------------------------
# refresh_access_token
# ---------------------------------------------------------------------------


class TestRefreshAccessToken:
    """Tests for refresh_access_token."""

    @pytest.mark.asyncio
    async def test_successful_refresh(self):
        """Returns new access token and computed expires_at."""
        token_payload = {
            "access_token": "NEW_ACCESS",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_resp = _make_mock_response(200, payload=token_payload)
        mock_session = _make_mock_session(post_cm=mock_resp)

        with patch(
            "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
            new=mock_session,
        ):
            result = await refresh_access_token(
                provider="outlook",
                client_id="cid",
                client_secret="csecret",
                refresh_token="old-refresh-token",
            )

        assert result["access_token"] == "NEW_ACCESS"
        assert result["expires_at"] > int(time.time())

    @pytest.mark.asyncio
    async def test_refresh_token_rotated(self):
        """New refresh_token in response is included in returned dict."""
        token_payload = {
            "access_token": "NEW_ACCESS",
            "refresh_token": "NEW_REFRESH",
            "expires_in": 3600,
        }
        mock_resp = _make_mock_response(200, payload=token_payload)
        mock_session = _make_mock_session(post_cm=mock_resp)

        with patch(
            "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
            new=mock_session,
        ):
            result = await refresh_access_token(
                provider="gmail",
                client_id="cid",
                client_secret="csecret",
                refresh_token="old-refresh",
            )

        assert result["refresh_token"] == "NEW_REFRESH"

    @pytest.mark.asyncio
    async def test_http_error_raises(self):
        """Non-200 HTTP response raises ValueError."""
        mock_resp = _make_mock_response(401, text="Unauthorized")
        mock_session = _make_mock_session(post_cm=mock_resp)

        with (
            patch(
                "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
                new=mock_session,
            ),
            pytest.raises(ValueError, match="Token refresh failed with status"),
        ):
            await refresh_access_token(
                provider="gmail",
                client_id="cid",
                client_secret="csecret",
                refresh_token="expired-refresh",
            )

    @pytest.mark.asyncio
    async def test_provider_error_raises(self):
        """Error payload from provider raises ValueError."""
        error_payload = {
            "error": "invalid_grant",
            "error_description": "Token has been revoked.",
        }
        mock_resp = _make_mock_response(200, payload=error_payload)
        mock_session = _make_mock_session(post_cm=mock_resp)

        with (
            patch(
                "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
                new=mock_session,
            ),
            pytest.raises(ValueError, match="Token has been revoked"),
        ):
            await refresh_access_token(
                provider="gmail",
                client_id="cid",
                client_secret="csecret",
                refresh_token="revoked",
            )

    @pytest.mark.asyncio
    async def test_invalid_provider_raises(self):
        """Unknown provider raises ValueError before any HTTP call."""
        with pytest.raises(ValueError, match="Unsupported OAuth provider"):
            await refresh_access_token(
                provider="yahoo",
                client_id="cid",
                client_secret="csecret",
                refresh_token="rt",
            )


# ---------------------------------------------------------------------------
# get_user_email
# ---------------------------------------------------------------------------


class TestGetUserEmail:
    """Tests for get_user_email."""

    @pytest.mark.asyncio
    async def test_gmail_email_field(self):
        """Gmail response uses the 'email' field."""
        mock_resp = _make_mock_response(
            200, payload={"email": "user@gmail.com", "id": "123"}
        )
        mock_session = _make_mock_session(get_cm=mock_resp)

        with patch(
            "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
            new=mock_session,
        ):
            email = await get_user_email("gmail", "ACCESS_TOKEN")

        assert email == "user@gmail.com"

    @pytest.mark.asyncio
    async def test_outlook_mail_field(self):
        """Outlook response uses the 'mail' field."""
        mock_resp = _make_mock_response(
            200, payload={"mail": "user@outlook.com", "displayName": "Test User"}
        )
        mock_session = _make_mock_session(get_cm=mock_resp)

        with patch(
            "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
            new=mock_session,
        ):
            email = await get_user_email("outlook", "ACCESS_TOKEN")

        assert email == "user@outlook.com"

    @pytest.mark.asyncio
    async def test_outlook_user_principal_name_fallback(self):
        """Outlook falls back to userPrincipalName when 'mail' is absent."""
        mock_resp = _make_mock_response(
            200, payload={"userPrincipalName": "user@corp.onmicrosoft.com"}
        )
        mock_session = _make_mock_session(get_cm=mock_resp)

        with patch(
            "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
            new=mock_session,
        ):
            email = await get_user_email("outlook", "ACCESS_TOKEN")

        assert email == "user@corp.onmicrosoft.com"

    @pytest.mark.asyncio
    async def test_http_error_raises(self):
        """Non-200 response raises ValueError."""
        mock_resp = _make_mock_response(401, text="Unauthorized")
        mock_session = _make_mock_session(get_cm=mock_resp)

        with (
            patch(
                "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
                new=mock_session,
            ),
            pytest.raises(ValueError, match="User-info request failed with status"),
        ):
            await get_user_email("gmail", "BAD_TOKEN")

    @pytest.mark.asyncio
    async def test_missing_email_in_response_raises(self):
        """Response with no recognisable email field raises ValueError."""
        mock_resp = _make_mock_response(
            200, payload={"sub": "12345", "name": "No Email Here"}
        )
        mock_session = _make_mock_session(get_cm=mock_resp)

        with (
            patch(
                "custom_components.mail_and_packages.oauth_handler.aiohttp.ClientSession",
                new=mock_session,
            ),
            pytest.raises(ValueError, match="Could not determine user email"),
        ):
            await get_user_email("gmail", "ACCESS_TOKEN")

    @pytest.mark.asyncio
    async def test_invalid_provider_raises(self):
        """Unknown provider raises ValueError before any HTTP call."""
        with pytest.raises(ValueError, match="Unsupported OAuth provider"):
            await get_user_email("yahoo", "TOKEN")


# ---------------------------------------------------------------------------
# is_token_expired
# ---------------------------------------------------------------------------


class TestIsTokenExpired:
    """Tests for is_token_expired."""

    def test_past_timestamp_is_expired(self):
        """A timestamp in the past is considered expired."""
        past = int(time.time()) - 1
        assert is_token_expired(past) is True

    def test_far_future_timestamp_not_expired(self):
        """A timestamp well in the future is not expired."""
        future = int(time.time()) + 3600
        assert is_token_expired(future) is False

    def test_current_timestamp_is_expired(self):
        """The exact current second is considered expired."""
        now = int(time.time())
        assert is_token_expired(now) is True
