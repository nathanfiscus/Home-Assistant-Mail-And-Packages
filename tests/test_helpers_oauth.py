"""Tests for OAuth-related helper functions."""

import imaplib
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from custom_components.mail_and_packages.helpers import login, _test_login


# ---------------------------------------------------------------------------
# login() with XOAUTH2
# ---------------------------------------------------------------------------


def test_login_uses_xoauth2_when_access_token_provided():
    """login() calls authenticate with XOAUTH2 when access_token is given."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_conn = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.IMAP4_SSL.return_value = mock_conn
        mock_conn.authenticate.return_value = ("OK", [b"Success"])

        result = login(
            host="imap.gmail.com",
            port=993,
            user="user@gmail.com",
            access_token="my-access-token",
        )

        assert result == mock_conn
        mock_conn.authenticate.assert_called_once()
        call_args = mock_conn.authenticate.call_args
        assert call_args[0][0] == "XOAUTH2"
        # The lambda should produce the XOAUTH2 auth string
        auth_fn = call_args[0][1]
        auth_string = auth_fn(None)
        assert "user=user@gmail.com" in auth_string
        assert "Bearer my-access-token" in auth_string
        # Should NOT call login() for password auth
        mock_conn.login.assert_not_called()


def test_login_uses_password_when_no_access_token():
    """login() falls back to password auth when no access_token is given."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_conn = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.IMAP4_SSL.return_value = mock_conn
        mock_conn.login.return_value = ("OK", [b"Success"])

        result = login(
            host="imap.example.com",
            port=993,
            user="user@example.com",
            pwd="my-password",
        )

        assert result == mock_conn
        mock_conn.login.assert_called_once_with("user@example.com", "my-password")
        mock_conn.authenticate.assert_not_called()


def test_login_returns_false_on_connection_error():
    """login() returns False when IMAP connection fails."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_imap.IMAP4_SSL.side_effect = Exception("Connection refused")

        result = login(
            host="bad.host.example.com",
            port=993,
            user="user@example.com",
            pwd="password",
        )

        assert result is False


def test_login_returns_false_on_xoauth2_error():
    """login() returns False when XOAUTH2 authentication fails."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_conn = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.IMAP4_SSL.return_value = mock_conn
        mock_conn.authenticate.side_effect = Exception("Invalid credentials")

        result = login(
            host="imap.gmail.com",
            port=993,
            user="user@gmail.com",
            access_token="bad-token",
        )

        assert result is False


def test_login_returns_false_on_password_error():
    """login() returns False when password authentication fails."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_conn = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.IMAP4_SSL.return_value = mock_conn
        mock_conn.login.side_effect = Exception("Invalid username or password")

        result = login(
            host="imap.example.com",
            port=993,
            user="user@example.com",
            pwd="wrong-password",
        )

        assert result is False


# ---------------------------------------------------------------------------
# _test_login() with XOAUTH2
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_test_login_xoauth2_success():
    """_test_login() succeeds with access_token using XOAUTH2."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_conn = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.IMAP4_SSL.return_value = mock_conn
        mock_conn.authenticate.return_value = ("OK", [b"Success"])

        result = await _test_login(
            host="imap.gmail.com",
            port=993,
            user="user@gmail.com",
            access_token="valid-token",
        )

        assert result is True
        mock_conn.authenticate.assert_called_once()
        mock_conn.login.assert_not_called()


@pytest.mark.asyncio
async def test_test_login_password_success():
    """_test_login() succeeds with password using standard login."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_conn = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.IMAP4_SSL.return_value = mock_conn
        mock_conn.login.return_value = ("OK", [b"Success"])

        result = await _test_login(
            host="imap.example.com",
            port=993,
            user="user@example.com",
            pwd="password",
        )

        assert result is True
        mock_conn.login.assert_called_once()
        mock_conn.authenticate.assert_not_called()


@pytest.mark.asyncio
async def test_test_login_xoauth2_failure():
    """_test_login() returns False when XOAUTH2 auth fails."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_conn = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.IMAP4_SSL.return_value = mock_conn
        mock_conn.authenticate.side_effect = Exception("Authentication failed")

        result = await _test_login(
            host="imap.gmail.com",
            port=993,
            user="user@gmail.com",
            access_token="bad-token",
        )

        assert result is False


@pytest.mark.asyncio
async def test_test_login_connection_error():
    """_test_login() returns False on connection error."""
    with patch("custom_components.mail_and_packages.helpers.imaplib") as mock_imap:
        mock_imap.IMAP4_SSL.side_effect = Exception("Connection refused")

        result = await _test_login(
            host="bad-host.example.com",
            port=993,
            user="user@example.com",
            pwd="password",
        )

        assert result is False


# ---------------------------------------------------------------------------
# XOAUTH2 auth string format
# ---------------------------------------------------------------------------


def test_xoauth2_auth_string_format():
    """Verify the XOAUTH2 auth string follows the required format."""
    user = "testuser@gmail.com"
    token = "ya29.example-access-token"

    # Test the format used in login()
    auth_string = f"user={user}\x01auth=Bearer {token}\x01\x01"

    # The string must start with user=
    assert auth_string.startswith("user=testuser@gmail.com")
    # Must contain the bearer token
    assert "auth=Bearer ya29.example-access-token" in auth_string
    # Must end with double SOH (0x01)
    assert auth_string.endswith("\x01\x01")
