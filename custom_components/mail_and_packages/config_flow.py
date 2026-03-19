"""Adds config flow for Mail and Packages."""

import logging
import secrets
import ssl
from pathlib import Path
from typing import Any

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from aioimaplib import AioImapException
from homeassistant import config_entries
from homeassistant.components.http import HomeAssistantView
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_RESOURCES,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant, callback

from .const import (
    AUTH_METHOD_OAUTH,
    AUTH_METHOD_PASSWORD,
    CONF_ACCESS_TOKEN_EXPIRY,
    CONF_ALLOW_EXTERNAL,
    CONF_ALLOW_FORWARDED_EMAILS,
    CONF_AMAZON_CUSTOM_IMG,
    CONF_AMAZON_CUSTOM_IMG_FILE,
    CONF_AMAZON_DAYS,
    CONF_AMAZON_DOMAIN,
    CONF_AMAZON_FWDS,
    CONF_AUTH_METHOD,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_CUSTOM_IMG,
    CONF_CUSTOM_IMG_FILE,
    CONF_DURATION,
    CONF_ENCRYPTED_ACCESS_TOKEN,
    CONF_ENCRYPTED_REFRESH_TOKEN,
    CONF_FEDEX_CUSTOM_IMG,
    CONF_FEDEX_CUSTOM_IMG_FILE,
    CONF_FOLDER,
    CONF_FORWARDED_EMAILS,
    CONF_GENERATE_GRID,
    CONF_GENERATE_MP4,
    CONF_GENERIC_CUSTOM_IMG,
    CONF_GENERIC_CUSTOM_IMG_FILE,
    CONF_IMAGE_SECURITY,
    CONF_IMAP_SECURITY,
    CONF_IMAP_TIMEOUT,
    CONF_OAUTH_PROVIDER,
    CONF_PATH,
    CONF_SCAN_INTERVAL,
    CONF_STORAGE,
    CONF_TOKEN_SALT,
    CONF_UPS_CUSTOM_IMG,
    CONF_UPS_CUSTOM_IMG_FILE,
    CONF_USER_EMAIL,
    CONF_VERIFY_SSL,
    CONF_WALMART_CUSTOM_IMG,
    CONF_WALMART_CUSTOM_IMG_FILE,
    CONFIG_VER,
    DEFAULT_ALLOW_EXTERNAL,
    DEFAULT_ALLOW_FORWARDED_EMAILS,
    DEFAULT_AMAZON_CUSTOM_IMG,
    DEFAULT_AMAZON_CUSTOM_IMG_FILE,
    DEFAULT_AMAZON_DAYS,
    DEFAULT_AMAZON_DOMAIN,
    DEFAULT_AMAZON_FWDS,
    DEFAULT_CUSTOM_IMG,
    DEFAULT_CUSTOM_IMG_FILE,
    DEFAULT_FEDEX_CUSTOM_IMG,
    DEFAULT_FEDEX_CUSTOM_IMG_FILE,
    DEFAULT_FOLDER,
    DEFAULT_FORWARDED_EMAILS,
    DEFAULT_GENERIC_CUSTOM_IMG,
    DEFAULT_GENERIC_CUSTOM_IMG_FILE,
    DEFAULT_GIF_DURATION,
    DEFAULT_IMAGE_SECURITY,
    DEFAULT_IMAP_TIMEOUT,
    DEFAULT_PATH,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STORAGE,
    DEFAULT_UPS_CUSTOM_IMG,
    DEFAULT_UPS_CUSTOM_IMG_FILE,
    DEFAULT_WALMART_CUSTOM_IMG,
    DEFAULT_WALMART_CUSTOM_IMG_FILE,
    DOMAIN,
    OAUTH_CALLBACK_PATH,
    OAUTH_PROVIDERS,
)
from .helpers import (
    InvalidAuth,
    _check_ffmpeg,
    generate_service_email_domains,
    get_resources,
    login,
    validate_email_address,
)

ERROR_MAILBOX_FAIL = "Problem getting mailbox listing using 'INBOX' message"
IMAP_SECURITY = ["none", "SSL"]
AMAZON_SENSORS = ["amazon_packages", "amazon_delivered", "amazon_exception"]
_LOGGER = logging.getLogger(__name__)
AMAZON_EMAIL_ERROR = (
    "Amazon domain found in email: %s, this may cause errors when searching emails."
)
FORWARDED_EMAIL_ERROR = "A service domain was found in email: %s, this may cause errors when searching emails."  # pylint: disable=line-too-long

# Flows waiting for an OAuth callback keyed by *state* token.
_OAUTH_FLOW_CALLBACKS: dict[str, Any] = {}


class OAuthCallbackView(HomeAssistantView):
    """View that handles the OAuth2 redirect callback from the provider.

    When the user completes the OAuth authorisation the provider redirects to
    this endpoint with a ``code`` and ``state`` query parameter.  The ``state``
    value is used to look up the waiting config flow so that it can be resumed.
    """

    url = OAUTH_CALLBACK_PATH
    name = "auth:external:callback:mail_and_packages"
    requires_auth = False

    async def get(self, request):  # type: ignore[override]
        """Handle the OAuth callback GET request."""
        from aiohttp.web import HTTPFound, Response  # noqa: PLC0415

        state = request.query.get("state")
        code = request.query.get("code")
        error = request.query.get("error")

        if not state or state not in _OAUTH_FLOW_CALLBACKS:
            _LOGGER.warning("Received OAuth callback with unknown state: %s", state)
            return Response(
                text="Unknown OAuth state. Please restart the configuration flow.",
                content_type="text/plain",
                status=400,
            )

        future = _OAUTH_FLOW_CALLBACKS.pop(state)

        if error:
            _LOGGER.error("OAuth error from provider: %s", error)
            future.set_result({"error": error})
        elif code:
            future.set_result({"code": code})
        else:
            future.set_result({"error": "no_code"})

        return Response(
            text=(
                "Authentication received! You can close this window and return to"
                " Home Assistant."
            ),
            content_type="text/plain",
        )


def _get_schema_auth_method(user_input: dict | None, default_dict: dict) -> vol.Schema:
    """Schema for auth method selection step."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> Any:
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            vol.Required(
                CONF_AUTH_METHOD,
                default=_get_default(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD),
            ): vol.In([AUTH_METHOD_PASSWORD, AUTH_METHOD_OAUTH]),
        }
    )


def _get_schema_oauth_credentials(
    user_input: dict | None, default_dict: dict
) -> vol.Schema:
    """Schema for OAuth credentials step."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> Any:
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            vol.Required(
                CONF_OAUTH_PROVIDER,
                default=_get_default(CONF_OAUTH_PROVIDER, "gmail"),
            ): vol.In(list(OAUTH_PROVIDERS.keys())),
            vol.Required(
                CONF_CLIENT_ID,
                default=_get_default(CONF_CLIENT_ID, ""),
            ): cv.string,
            vol.Required(
                CONF_CLIENT_SECRET,
                default=_get_default(CONF_CLIENT_SECRET, ""),
            ): cv.string,
            vol.Required(CONF_HOST, default=_get_default(CONF_HOST, "")): cv.string,
            vol.Required(
                CONF_PORT, default=_get_default(CONF_PORT, 993)
            ): cv.port,
            vol.Required(
                CONF_IMAP_SECURITY, default=_get_default(CONF_IMAP_SECURITY, "SSL")
            ): vol.In(IMAP_SECURITY),
            vol.Optional(
                CONF_VERIFY_SSL, default=_get_default(CONF_VERIFY_SSL, False)
            ): cv.boolean,
        }
    )


async def _check_amazon_forwards(forwards: str, domain: str) -> tuple:
    """Validate and format amazon forward emails for user input.

    Returns tuple: dict of errors, list of email addresses
    """
    emails = forwards.split(",")
    errors = []

    # Validate each email address
    for email in emails:
        email = email.strip()

        if "@" in email:
            # Check for amazon domains
            if f"@{domain}" in email:
                _LOGGER.error(
                    AMAZON_EMAIL_ERROR,
                    email,
                )

        # No forwards
        elif forwards in ["", "(none)", '""']:
            forwards = []

        else:
            _LOGGER.error("Missing '@' in email address: %s", email)
            errors.append("invalid_email_format")

    if len(errors) == 0:
        errors.append("ok")

    return errors, forwards


async def _check_forwarded_emails(user_input: dict[str, Any]) -> list[str]:
    """Validate forwarded email addresses provided by the user.

    Use Voluptuous to make sure that none of the forwarded email addresses use domains
    that match any of the Mail service domains, as this was known to cause issues when
    searching for Amazon emails.

    Args:
        user_input (dict[str, Any]): The user input dictionary.

    Returns:
        list[str]: A list of error codes (e.g. "missing_forwarded_emails") or "ok" if the
                   email addresses are valid

    """
    forwarded_emails = user_input[CONF_FORWARDED_EMAILS]

    _LOGGER.debug("checking forwarded emails: '%s'", forwarded_emails)

    # No forwards
    if not forwarded_emails:
        _LOGGER.error(
            "Allowed forwarded emails but no forwards or '(none)' were entered."
        )
        return ["missing_forwarded_emails"]
    if forwarded_emails == "(none)":
        return ["ok"]

    errors = []

    service_email_domains = generate_service_email_domains(
        user_input.get(CONF_AMAZON_FWDS, [])
    )

    emails = [email.strip() for email in forwarded_emails.split(",")]
    for email in emails:
        _LOGGER.debug("validating email address %s", email)
        if not validate_email_address(email):
            _LOGGER.error("%s does not look like a valid email address", email)
            errors.append("invalid_email_format")
            continue

        domain = email.split("@")[1]
        if domain in service_email_domains:
            _LOGGER.error(
                FORWARDED_EMAIL_ERROR,
                email,
            )
    if len(errors) == 0:
        return ["ok"]

    return errors


def _validate_path_input(user_input: dict, errors: dict) -> None:
    """Validate path and file inputs."""
    # List of (Toggle Key, File Key, Error Key)
    file_checks = [
        (CONF_CUSTOM_IMG, CONF_CUSTOM_IMG_FILE, CONF_CUSTOM_IMG_FILE),
        (
            CONF_AMAZON_CUSTOM_IMG,
            CONF_AMAZON_CUSTOM_IMG_FILE,
            CONF_AMAZON_CUSTOM_IMG_FILE,
        ),
        (CONF_UPS_CUSTOM_IMG, CONF_UPS_CUSTOM_IMG_FILE, CONF_UPS_CUSTOM_IMG_FILE),
        (
            CONF_WALMART_CUSTOM_IMG,
            CONF_WALMART_CUSTOM_IMG_FILE,
            CONF_WALMART_CUSTOM_IMG_FILE,
        ),
        (
            CONF_FEDEX_CUSTOM_IMG,
            CONF_FEDEX_CUSTOM_IMG_FILE,
            CONF_FEDEX_CUSTOM_IMG_FILE,
        ),
        (
            CONF_GENERIC_CUSTOM_IMG,
            CONF_GENERIC_CUSTOM_IMG_FILE,
            CONF_GENERIC_CUSTOM_IMG_FILE,
        ),
    ]

    for toggle, file_key, error_key in file_checks:
        if user_input.get(toggle) and file_key in user_input:
            if not Path(user_input[file_key]).is_file():
                errors[error_key] = "file_not_found"

    if CONF_STORAGE in user_input:
        if not Path(user_input[CONF_STORAGE]).exists():
            errors[CONF_STORAGE] = "path_not_found"


async def _validate_user_input(user_input: dict) -> tuple:
    """Valididate user input from config flow.

    Returns tuple with error messages and modified user_input
    """
    errors = {}

    # Validate amazon forwarding email addresses
    if CONF_AMAZON_FWDS in user_input:
        if isinstance(user_input[CONF_AMAZON_FWDS], str):
            status, amazon_list = await _check_amazon_forwards(
                user_input[CONF_AMAZON_FWDS], user_input[CONF_AMAZON_DOMAIN]
            )
            if status[0] == "ok":
                user_input[CONF_AMAZON_FWDS] = amazon_list
            else:
                user_input[CONF_AMAZON_FWDS] = amazon_list
                errors[CONF_AMAZON_FWDS] = status[0]

    if CONF_FORWARDED_EMAILS in user_input:
        if isinstance(user_input[CONF_FORWARDED_EMAILS], str):
            status = await _check_forwarded_emails(user_input)

            if status[0] == "ok" and user_input[CONF_FORWARDED_EMAILS] == "(none)":
                # the user changed their mind, remove the flag and config entry
                user_input[CONF_ALLOW_FORWARDED_EMAILS] = False
                del user_input[CONF_FORWARDED_EMAILS]
            elif status[0] != "ok":
                errors[CONF_FORWARDED_EMAILS] = status[0]

    # Check for ffmpeg if option enabled
    if user_input[CONF_GENERATE_MP4]:
        if not await _check_ffmpeg():
            errors[CONF_GENERATE_MP4] = "ffmpeg_not_found"

    # Validate file paths
    _validate_path_input(user_input, errors)

    return errors, user_input


async def _get_mailboxes(
    hass: HomeAssistant,
    host: str,
    port: int,
    user: str,
    pwd: str,
    security: str,
    verify: bool,
    access_token: str | None = None,
) -> list:
    """Get list of mailbox folders from mail server."""
    _LOGGER.debug("Getting mailboxes, login...")
    try:
        account = await login(hass, host, port, user, pwd, security, verify, access_token)

    except (TimeoutError, AioImapException, ConnectionRefusedError) as err:
        _LOGGER.error("Unable to connect: %s", err)
        return []

    _LOGGER.debug("Attempting to get mailbox list...")
    result = await account.list('""', '"*"')
    status = result.result
    folderlist = result.lines
    _LOGGER.debug("Get mailbox status: %s folder list: %s", status, folderlist)
    mailboxes = []
    if status != "OK" or not isinstance(folderlist, list):
        _LOGGER.error("Error listing mailboxes ... using default")
        mailboxes.append(DEFAULT_FOLDER)
    else:
        mailboxes = await _parse_folder_list(folderlist)

    return mailboxes


async def _parse_folder_list(folderlist: list) -> list:
    """Parse folder list from IMAP server response."""
    mailboxes = []
    try:  # noqa: SIM105
        mailboxes.extend(i.decode().split(' "/" ')[1] for i in folderlist)
    except IndexError:
        pass

    try:  # noqa: SIM105
        mailboxes.extend(i.decode().split(' "." ')[1] for i in folderlist)
    except IndexError:
        pass

    if len(mailboxes) == 0:
        _LOGGER.error("Problem reading mailbox folders, using default.")
        mailboxes.append(DEFAULT_FOLDER)

    return mailboxes


def _get_schema_step_1(user_input: list, default_dict: list) -> Any:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> None:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            # auth_method has NO default so it is not injected into existing
            # password-based submissions (keeps backwards compatibility with
            # existing config-entry data that does not contain this key).
            vol.Optional(CONF_AUTH_METHOD): vol.In(
                [AUTH_METHOD_PASSWORD, AUTH_METHOD_OAUTH]
            ),
            vol.Optional(CONF_HOST, default=_get_default(CONF_HOST, "")): cv.string,
            vol.Optional(CONF_PORT, default=_get_default(CONF_PORT, 993)): cv.port,
            vol.Optional(CONF_USERNAME, default=_get_default(CONF_USERNAME, "")): cv.string,
            vol.Optional(CONF_PASSWORD, default=_get_default(CONF_PASSWORD, "")): cv.string,
            vol.Optional(
                CONF_IMAP_SECURITY, default=_get_default(CONF_IMAP_SECURITY, "SSL")
            ): vol.In(IMAP_SECURITY),
            vol.Optional(
                CONF_VERIFY_SSL, default=_get_default(CONF_VERIFY_SSL, False)
            ): cv.boolean,
        }
    )


async def _get_schema_step_2(
    data: list, user_input: list, default_dict: list, hass: HomeAssistant
) -> Any:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> None:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    # For OAuth configs, resolve the access_token for the mailbox listing
    access_token: str | None = None
    imap_user = data.get(CONF_USERNAME)
    if data.get(CONF_AUTH_METHOD) == AUTH_METHOD_OAUTH:
        from .helpers import _resolve_oauth_access_token  # noqa: PLC0415

        access_token = await _resolve_oauth_access_token(hass, dict(data))
        imap_user = data.get(CONF_USER_EMAIL, imap_user)

    return vol.Schema(
        {
            vol.Required(CONF_FOLDER, default=_get_default(CONF_FOLDER)): vol.In(
                await _get_mailboxes(
                    hass,
                    data[CONF_HOST],
                    data[CONF_PORT],
                    imap_user,
                    data.get(CONF_PASSWORD, ""),
                    data[CONF_IMAP_SECURITY],
                    data[CONF_VERIFY_SSL],
                    access_token,
                )
            ),
            vol.Required(
                CONF_RESOURCES, default=_get_default(CONF_RESOURCES)
            ): cv.multi_select(get_resources()),
            vol.Optional(
                CONF_SCAN_INTERVAL, default=_get_default(CONF_SCAN_INTERVAL)
            ): vol.All(vol.Coerce(int), vol.Range(min=5)),
            vol.Optional(
                CONF_IMAP_TIMEOUT, default=_get_default(CONF_IMAP_TIMEOUT)
            ): vol.All(vol.Coerce(int), vol.Range(min=10)),
            vol.Optional(
                CONF_DURATION, default=_get_default(CONF_DURATION)
            ): vol.Coerce(int),
            vol.Optional(
                CONF_ALLOW_FORWARDED_EMAILS,
                default=_get_default(CONF_ALLOW_FORWARDED_EMAILS, False),
            ): cv.boolean,
            vol.Optional(
                CONF_GENERATE_GRID, default=_get_default(CONF_GENERATE_GRID, False)
            ): cv.boolean,
            vol.Optional(
                CONF_GENERATE_MP4, default=_get_default(CONF_GENERATE_MP4, False)
            ): cv.boolean,
            vol.Optional(
                CONF_ALLOW_EXTERNAL, default=_get_default(CONF_ALLOW_EXTERNAL, False)
            ): cv.boolean,
            vol.Optional(
                CONF_CUSTOM_IMG, default=_get_default(CONF_CUSTOM_IMG, False)
            ): cv.boolean,
            vol.Optional(
                CONF_AMAZON_CUSTOM_IMG,
                default=_get_default(CONF_AMAZON_CUSTOM_IMG, False),
            ): cv.boolean,
            vol.Optional(
                CONF_UPS_CUSTOM_IMG, default=_get_default(CONF_UPS_CUSTOM_IMG, False)
            ): cv.boolean,
            vol.Optional(
                CONF_WALMART_CUSTOM_IMG,
                default=_get_default(CONF_WALMART_CUSTOM_IMG, False),
            ): cv.boolean,
            vol.Optional(
                CONF_FEDEX_CUSTOM_IMG,
                default=_get_default(CONF_FEDEX_CUSTOM_IMG, False),
            ): cv.boolean,
            vol.Optional(
                CONF_GENERIC_CUSTOM_IMG,
                default=_get_default(CONF_GENERIC_CUSTOM_IMG, False),
            ): cv.boolean,
        }
    )


def _get_schema_step_3(user_input: dict, default_dict: dict) -> Any:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> str:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    schema = {}

    # Only show custom image file field if custom image is enabled
    if user_input.get(CONF_CUSTOM_IMG):
        schema[
            vol.Optional(
                CONF_CUSTOM_IMG_FILE,
                default=_get_default(CONF_CUSTOM_IMG_FILE, DEFAULT_CUSTOM_IMG_FILE),
            )
        ] = cv.string

    # Only show Amazon custom image file field if Amazon custom image is enabled
    if user_input.get(CONF_AMAZON_CUSTOM_IMG):
        schema[
            vol.Optional(
                CONF_AMAZON_CUSTOM_IMG_FILE,
                default=_get_default(
                    CONF_AMAZON_CUSTOM_IMG_FILE, DEFAULT_AMAZON_CUSTOM_IMG_FILE
                ),
            )
        ] = cv.string

    # Only show UPS custom image file field if UPS custom image is enabled
    if user_input.get(CONF_UPS_CUSTOM_IMG):
        schema[
            vol.Optional(
                CONF_UPS_CUSTOM_IMG_FILE,
                default=_get_default(
                    CONF_UPS_CUSTOM_IMG_FILE, DEFAULT_UPS_CUSTOM_IMG_FILE
                ),
            )
        ] = cv.string

    # Only show Walmart custom image file field if Walmart custom image is enabled
    if user_input.get(CONF_WALMART_CUSTOM_IMG):
        schema[
            vol.Optional(
                CONF_WALMART_CUSTOM_IMG_FILE,
                default=_get_default(
                    CONF_WALMART_CUSTOM_IMG_FILE, DEFAULT_WALMART_CUSTOM_IMG_FILE
                ),
            )
        ] = cv.string

    # Only show FedEx custom image file field if FedEx custom image is enabled
    if user_input.get(CONF_FEDEX_CUSTOM_IMG):
        schema[
            vol.Optional(
                CONF_FEDEX_CUSTOM_IMG_FILE,
                default=_get_default(
                    CONF_FEDEX_CUSTOM_IMG_FILE, DEFAULT_FEDEX_CUSTOM_IMG_FILE
                ),
            )
        ] = cv.string

    # Only show Generic custom image file field if Generic custom image is enabled
    if user_input.get(CONF_GENERIC_CUSTOM_IMG):
        schema[
            vol.Optional(
                CONF_GENERIC_CUSTOM_IMG_FILE,
                default=_get_default(
                    CONF_GENERIC_CUSTOM_IMG_FILE, DEFAULT_GENERIC_CUSTOM_IMG_FILE
                ),
            )
        ] = cv.string

    return vol.Schema(schema)


def _get_schema_step_amazon(user_input: list, default_dict: list) -> Any:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> None:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            vol.Required(
                CONF_AMAZON_DOMAIN, default=_get_default(CONF_AMAZON_DOMAIN)
            ): cv.string,
            vol.Optional(
                CONF_AMAZON_FWDS, default=_get_default(CONF_AMAZON_FWDS)
            ): cv.string,
            vol.Optional(CONF_AMAZON_DAYS, default=_get_default(CONF_AMAZON_DAYS)): int,
        }
    )


def _get_schema_step_forwarded_emails(
    user_input: list, default_dict: list
) -> vol.Schema:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> list:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            vol.Required(
                CONF_FORWARDED_EMAILS, default=_get_default(CONF_FORWARDED_EMAILS)
            ): cv.string,
        }
    )


def _get_schema_step_storage(user_input: list, default_dict: list) -> Any:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> None:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            vol.Required(
                CONF_STORAGE, default=_get_default(CONF_STORAGE, DEFAULT_STORAGE)
            ): cv.string,
        }
    )


async def _validate_login(
    hass: HomeAssistant, user_input: dict[str, Any]
) -> dict[str, str]:
    """Validate login credentials."""
    errors = {}
    _LOGGER.debug("Testing login...")
    try:
        imap_client = await login(
            hass,
            host=user_input[CONF_HOST],
            port=user_input[CONF_PORT],
            user=user_input[CONF_USERNAME],
            pwd=user_input[CONF_PASSWORD],
            security=user_input[CONF_IMAP_SECURITY],
            verify=user_input[CONF_VERIFY_SSL],
        )
        result, data = await imap_client.select()

    except InvalidAuth:
        errors[CONF_USERNAME] = errors[CONF_PASSWORD] = "invalid_auth"
    except ssl.SSLError:
        errors["base"] = "ssl_error"
    except (TimeoutError, AioImapException, ConnectionRefusedError) as err:
        _LOGGER.error("Unable to connect: %s", err)
        errors["base"] = "cannot_connect"
    else:
        if result != "OK":
            errors["base"] = "missing_inbox"

    return errors


@config_entries.HANDLERS.register(DOMAIN)
class MailAndPackagesFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Mail and Packages."""

    VERSION = CONFIG_VER
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    def __init__(self):
        """Initialize."""
        self._entry = {}
        self._data = {}
        self._errors = {}
        self._oauth_state: str | None = None

    async def async_step_user(self, user_input=None):
        """Handle a flow initialized by the user.

        The step shows a combined form with an optional auth_method field and
        IMAP credentials.  When auth_method is ``"oauth"`` the OAuth
        credentials step is shown next.  When auth_method is ``"password"`` or
        absent (the common case for password-based configs) the existing IMAP
        login validation runs unchanged so that no existing tests break.
        """
        self._errors = {}

        if user_input is not None:
            auth_method = user_input.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD)

            if auth_method == AUTH_METHOD_OAUTH:
                self._data[CONF_AUTH_METHOD] = AUTH_METHOD_OAUTH
                return await self.async_step_oauth_credentials()

            # Password auth – validate that required IMAP fields are present
            missing = [
                f
                for f in (CONF_HOST, CONF_USERNAME, CONF_PASSWORD)
                if not user_input.get(f)
            ]
            for field in missing:
                self._errors[field] = "required"

            if not self._errors:
                self._data.update(user_input)
                # Remove auth_method from data so existing config entries are
                # not polluted with this key when it was not explicitly set.
                self._data.pop(CONF_AUTH_METHOD, None)
                self._errors = await _validate_login(self.hass, user_input)
                if self._errors == {}:
                    return await self.async_step_config_2()

            return await self._show_config_form(user_input)

        return await self._show_config_form(user_input)

    async def _show_config_form(self, user_input):
        """Show the IMAP connection / auth method configuration form."""
        defaults = {
            CONF_AUTH_METHOD: AUTH_METHOD_PASSWORD,
            CONF_PORT: DEFAULT_PORT,
            CONF_IMAP_SECURITY: "SSL",
            CONF_VERIFY_SSL: False,
        }

        return self.async_show_form(
            step_id="user",
            data_schema=_get_schema_step_1(user_input, defaults),
            errors=self._errors,
        )

    # ---------------------------------------------------------------------------
    # OAuth config steps
    # ---------------------------------------------------------------------------

    async def async_step_oauth_credentials(self, user_input=None):
        """Collect OAuth client credentials and IMAP server settings."""
        self._errors = {}

        if user_input is not None:
            # Validate that host is provided
            if not user_input.get(CONF_HOST):
                self._errors[CONF_HOST] = "required"
            if not user_input.get(CONF_CLIENT_ID):
                self._errors[CONF_CLIENT_ID] = "required"
            if not user_input.get(CONF_CLIENT_SECRET):
                self._errors[CONF_CLIENT_SECRET] = "required"

            if not self._errors:
                self._data.update(user_input)
                return await self.async_step_oauth_authorize()

        return self.async_show_form(
            step_id="oauth_credentials",
            data_schema=_get_schema_oauth_credentials(user_input, {}),
            errors=self._errors,
        )

    async def async_step_oauth_authorize(self, user_input=None):
        """Generate an OAuth authorization URL and wait for the callback."""
        import asyncio  # noqa: PLC0415

        from .oauth_handler import (  # noqa: PLC0415
            exchange_code_for_token,
            get_oauth_url,
            get_user_email,
        )

        provider = self._data[CONF_OAUTH_PROVIDER]
        client_id = self._data[CONF_CLIENT_ID]
        client_secret = self._data[CONF_CLIENT_SECRET]

        # Build the redirect URI using this HA instance's external/internal URL
        try:
            redirect_uri = self._build_redirect_uri()
        except RuntimeError as err:
            _LOGGER.error("Cannot determine redirect URI: %s", err)
            self._errors["base"] = "cannot_connect"
            return self.async_show_form(
                step_id="oauth_credentials",
                data_schema=_get_schema_oauth_credentials(None, self._data),
                errors=self._errors,
            )

        # Register OAuth callback view (idempotent)
        self.hass.http.register_view(OAuthCallbackView)

        # Generate a random state to prevent CSRF
        state = secrets.token_hex(16)
        self._oauth_state = state

        # Create a future that the callback view will resolve
        loop = self.hass.loop
        future: asyncio.Future = loop.create_future()
        _OAUTH_FLOW_CALLBACKS[state] = future

        auth_url = get_oauth_url(provider, client_id, redirect_uri, state)
        _LOGGER.debug("OAuth authorization URL: %s", auth_url)

        # Wait for the callback (up to 5 minutes)
        try:
            result = await asyncio.wait_for(future, timeout=300)
        except asyncio.TimeoutError:
            _OAUTH_FLOW_CALLBACKS.pop(state, None)
            self._errors["base"] = "oauth_timeout"
            return self.async_show_form(
                step_id="oauth_credentials",
                data_schema=_get_schema_oauth_credentials(None, self._data),
                errors=self._errors,
            )

        if "error" in result:
            self._errors["base"] = "oauth_error"
            _LOGGER.error("OAuth authorization error: %s", result["error"])
            return self.async_show_form(
                step_id="oauth_credentials",
                data_schema=_get_schema_oauth_credentials(None, self._data),
                errors=self._errors,
            )

        code = result["code"]

        # Exchange code for tokens
        try:
            token_data = await exchange_code_for_token(
                provider, client_id, client_secret, code, redirect_uri
            )
        except ValueError as err:
            _LOGGER.error("Token exchange failed: %s", err)
            self._errors["base"] = "oauth_token_error"
            return self.async_show_form(
                step_id="oauth_credentials",
                data_schema=_get_schema_oauth_credentials(None, self._data),
                errors=self._errors,
            )

        # Fetch user email
        try:
            user_email = await get_user_email(provider, token_data["access_token"])
        except ValueError as err:
            _LOGGER.error("Failed to fetch user email: %s", err)
            self._errors["base"] = "oauth_user_info_error"
            return self.async_show_form(
                step_id="oauth_credentials",
                data_schema=_get_schema_oauth_credentials(None, self._data),
                errors=self._errors,
            )

        # Encrypt tokens
        from .crypto import Cryptographer  # noqa: PLC0415

        crypto = Cryptographer(client_secret)
        self._data[CONF_USER_EMAIL] = user_email
        self._data[CONF_ENCRYPTED_ACCESS_TOKEN] = crypto.encrypt(
            token_data["access_token"]
        )
        self._data[CONF_TOKEN_SALT] = crypto.salt_hex
        self._data[CONF_ACCESS_TOKEN_EXPIRY] = token_data["expires_at"]

        if "refresh_token" in token_data:
            self._data[CONF_ENCRYPTED_REFRESH_TOKEN] = crypto.encrypt(
                token_data["refresh_token"]
            )

        # Do NOT store the plain-text access token – it lives only in memory
        # Proceed to step 2 (folder/resources/etc.)
        return await self.async_step_config_2()

    def _build_redirect_uri(self) -> str:
        """Build the OAuth callback redirect URI for this HA instance."""
        # Prefer the external URL if configured; fall back to internal URL
        base_url = (
            self.hass.config.external_url
            or self.hass.config.internal_url
        )
        if not base_url:
            raise RuntimeError(
                "No external or internal URL configured for Home Assistant"
            )
        return f"{base_url.rstrip('/')}{OAUTH_CALLBACK_PATH}"

    async def async_step_config_2(self, user_input=None):
        """Configure form step 2."""
        self._errors = {}
        if user_input is not None:
            self._errors, user_input = await _validate_user_input(user_input)
            self._data.update(user_input)
            _LOGGER.debug("RESOURCES: %s", self._data[CONF_RESOURCES])
            if len(self._errors) == 0:
                if self._data[CONF_ALLOW_FORWARDED_EMAILS]:
                    return await self.async_step_config_forwarded_emails()
                if any(
                    sensor in self._data[CONF_RESOURCES] for sensor in AMAZON_SENSORS
                ):
                    return await self.async_step_config_amazon()
                has_custom_image = (
                    self._data.get(CONF_CUSTOM_IMG)
                    or self._data.get(CONF_AMAZON_CUSTOM_IMG)
                    or self._data.get(CONF_UPS_CUSTOM_IMG)
                    or self._data.get(CONF_WALMART_CUSTOM_IMG)
                    or self._data.get(CONF_FEDEX_CUSTOM_IMG)
                    or self._data.get(CONF_GENERIC_CUSTOM_IMG)
                )
                if has_custom_image:
                    return await self.async_step_config_3()

                return self.async_create_entry(
                    title=self._data[CONF_HOST], data=self._data
                )
            return await self._show_config_2(user_input)

        return await self._show_config_2(user_input)

    async def _show_config_2(self, user_input):
        """Step 2 setup."""
        # Defaults
        defaults = {
            CONF_FOLDER: DEFAULT_FOLDER,
            CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
            CONF_PATH: self.hass.config.path() + DEFAULT_PATH,
            CONF_DURATION: DEFAULT_GIF_DURATION,
            CONF_IMAGE_SECURITY: DEFAULT_IMAGE_SECURITY,
            CONF_IMAP_TIMEOUT: DEFAULT_IMAP_TIMEOUT,
            CONF_GENERATE_GRID: False,
            CONF_GENERATE_MP4: False,
            CONF_ALLOW_EXTERNAL: DEFAULT_ALLOW_EXTERNAL,
            CONF_CUSTOM_IMG: DEFAULT_CUSTOM_IMG,
            CONF_AMAZON_CUSTOM_IMG: DEFAULT_AMAZON_CUSTOM_IMG,
            CONF_UPS_CUSTOM_IMG: DEFAULT_UPS_CUSTOM_IMG,
            CONF_WALMART_CUSTOM_IMG: DEFAULT_WALMART_CUSTOM_IMG,
            CONF_FEDEX_CUSTOM_IMG: DEFAULT_FEDEX_CUSTOM_IMG,
            CONF_GENERIC_CUSTOM_IMG: DEFAULT_GENERIC_CUSTOM_IMG,
            CONF_ALLOW_FORWARDED_EMAILS: DEFAULT_ALLOW_FORWARDED_EMAILS,
        }

        return self.async_show_form(
            step_id="config_2",
            data_schema=await _get_schema_step_2(
                self._data, user_input, defaults, self.hass
            ),
            errors=self._errors,
        )

    async def async_step_config_3(self, user_input=None):
        """Configure form step 2."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                return await self.async_step_config_storage()
            return await self._show_config_3(user_input)

        return await self._show_config_3(user_input)

    async def _show_config_3(self, user_input=None):  # pylint: disable=unused-argument
        """Step 3 setup."""
        # Defaults
        defaults = {
            CONF_CUSTOM_IMG_FILE: DEFAULT_CUSTOM_IMG_FILE,
            CONF_AMAZON_CUSTOM_IMG_FILE: DEFAULT_AMAZON_CUSTOM_IMG_FILE,
            CONF_UPS_CUSTOM_IMG_FILE: DEFAULT_UPS_CUSTOM_IMG_FILE,
            CONF_WALMART_CUSTOM_IMG_FILE: DEFAULT_WALMART_CUSTOM_IMG_FILE,
            CONF_FEDEX_CUSTOM_IMG_FILE: DEFAULT_FEDEX_CUSTOM_IMG_FILE,
            CONF_GENERIC_CUSTOM_IMG_FILE: DEFAULT_GENERIC_CUSTOM_IMG_FILE,
        }

        return self.async_show_form(
            step_id="config_3",
            data_schema=_get_schema_step_3(self._data, defaults),
            errors=self._errors,
        )

    async def async_step_config_amazon(self, user_input=None):
        """Configure form step amazon."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                if (
                    self._data.get(CONF_CUSTOM_IMG)
                    or self._data.get(CONF_AMAZON_CUSTOM_IMG)
                    or self._data.get(CONF_UPS_CUSTOM_IMG)
                    or self._data.get(CONF_WALMART_CUSTOM_IMG)
                    or self._data.get(CONF_GENERIC_CUSTOM_IMG)
                ):
                    return await self.async_step_config_3()
                return await self.async_step_config_storage()

            return await self._show_config_amazon(user_input)

        return await self._show_config_amazon(user_input)

    async def _show_config_amazon(self, user_input):
        """Step 3 setup."""
        # Defaults
        defaults = {
            CONF_AMAZON_DOMAIN: DEFAULT_AMAZON_DOMAIN,
            CONF_AMAZON_FWDS: DEFAULT_AMAZON_FWDS,
            CONF_AMAZON_DAYS: DEFAULT_AMAZON_DAYS,
        }

        return self.async_show_form(
            step_id="config_amazon",
            data_schema=_get_schema_step_amazon(user_input, defaults),
            errors=self._errors,
        )

    async def async_step_config_forwarded_emails(self, user_input=None):
        """Configure form step forwarded emails."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                if any(
                    sensor in self._data[CONF_RESOURCES] for sensor in AMAZON_SENSORS
                ):
                    return await self.async_step_config_amazon()
                if self._data[CONF_CUSTOM_IMG]:
                    return await self.async_step_config_3()

                return await self.async_step_config_storage()

            return await self._show_config_forwarded_emails(user_input)

        return await self._show_config_forwarded_emails(user_input)

    async def _show_config_forwarded_emails(self, user_input):
        """Configure forwarded emails setup."""
        # Defaults
        defaults = {
            CONF_FORWARDED_EMAILS: DEFAULT_FORWARDED_EMAILS,
        }

        return self.async_show_form(
            step_id="config_forwarded_emails",
            data_schema=_get_schema_step_forwarded_emails(user_input, defaults),
            errors=self._errors,
        )

    async def async_step_config_storage(self, user_input=None):
        """Configure form step storage."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                return self.async_create_entry(
                    title=self._data[CONF_HOST], data=self._data
                )
            return await self._show_config_storage(user_input)

        return await self._show_config_storage(user_input)

    async def _show_config_storage(self, user_input):
        """Step 3 setup."""
        # Defaults
        defaults = {
            CONF_STORAGE: DEFAULT_STORAGE,
        }

        return self.async_show_form(
            step_id="config_storage",
            data_schema=_get_schema_step_storage(user_input, defaults),
            errors=self._errors,
        )

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Add reconfigure step to allow to reconfigure a config entry."""
        self._entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        assert self._entry
        self._data = dict(self._entry.data)
        self._errors = {}

        if user_input is not None:
            self._data.update(user_input)
            self._errors = await _validate_login(
                self.hass,
                user_input,
            )
            if self._errors == {}:
                return await self.async_step_reconfig_2()

            return await self._show_reconfig_form(user_input)

        return await self._show_reconfig_form(user_input)

    async def _show_reconfig_form(self, user_input):
        """Show the configuration form to edit configuration data."""
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_get_schema_step_1(user_input, self._data),
            errors=self._errors,
        )

    async def async_step_reconfig_2(self, user_input=None):
        """Configure form step 2."""
        self._errors = {}
        _LOGGER.debug("Loading step 2...")
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(user_input)
            if len(self._errors) == 0:
                if self._data[CONF_ALLOW_FORWARDED_EMAILS]:
                    return await self.async_step_reconfig_forwarded_emails()

                if any(
                    sensor in self._data[CONF_RESOURCES] for sensor in AMAZON_SENSORS
                ):
                    return await self.async_step_reconfig_amazon()
                has_custom_image = (
                    self._data.get(CONF_CUSTOM_IMG)
                    or self._data.get(CONF_AMAZON_CUSTOM_IMG)
                    or self._data.get(CONF_UPS_CUSTOM_IMG)
                    or self._data.get(CONF_WALMART_CUSTOM_IMG)
                    or self._data.get(CONF_FEDEX_CUSTOM_IMG)
                    or self._data.get(CONF_GENERIC_CUSTOM_IMG)
                )
                if has_custom_image:
                    return await self.async_step_reconfig_3()

                return await self.async_step_reconfig_storage()

            return await self._show_reconfig_2(user_input)

        return await self._show_reconfig_2(user_input)

    async def _show_reconfig_2(self, user_input):
        """Step 2 setup."""
        return self.async_show_form(
            step_id="reconfig_2",
            data_schema=await _get_schema_step_2(
                self._data, user_input, self._data, self.hass
            ),
            errors=self._errors,
        )

    async def async_step_reconfig_3(self, user_input=None):
        """Configure form step 2."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                return await self.async_step_reconfig_storage()

            return await self._show_reconfig_3(user_input)

        return await self._show_reconfig_3(user_input)

    async def _show_reconfig_3(self, user_input=None):  # pylint: disable=unused-argument
        """Step 3 setup."""
        # Defaults
        defaults = {
            CONF_CUSTOM_IMG_FILE: DEFAULT_CUSTOM_IMG_FILE,
            CONF_AMAZON_CUSTOM_IMG_FILE: DEFAULT_AMAZON_CUSTOM_IMG_FILE,
            CONF_UPS_CUSTOM_IMG_FILE: DEFAULT_UPS_CUSTOM_IMG_FILE,
            CONF_WALMART_CUSTOM_IMG_FILE: DEFAULT_WALMART_CUSTOM_IMG_FILE,
            CONF_FEDEX_CUSTOM_IMG_FILE: DEFAULT_FEDEX_CUSTOM_IMG_FILE,
            CONF_GENERIC_CUSTOM_IMG_FILE: DEFAULT_GENERIC_CUSTOM_IMG_FILE,
        }

        return self.async_show_form(
            step_id="reconfig_3",
            data_schema=_get_schema_step_3(self._data, defaults),
            errors=self._errors,
        )

    async def async_step_reconfig_amazon(self, user_input=None):
        """Configure form step amazon."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                has_custom_image = (
                    self._data.get(CONF_CUSTOM_IMG)
                    or self._data.get(CONF_AMAZON_CUSTOM_IMG)
                    or self._data.get(CONF_UPS_CUSTOM_IMG)
                    or self._data.get(CONF_WALMART_CUSTOM_IMG)
                    or self._data.get(CONF_FEDEX_CUSTOM_IMG)
                    or self._data.get(CONF_GENERIC_CUSTOM_IMG)
                )
                if has_custom_image:
                    return await self.async_step_reconfig_3()

                return await self.async_step_reconfig_storage()

            return await self._show_reconfig_amazon(user_input)

        return await self._show_reconfig_amazon(user_input)

    async def _show_reconfig_amazon(self, user_input):
        """Step 3 setup."""
        if self._data[CONF_AMAZON_FWDS] == []:
            self._data[CONF_AMAZON_FWDS] = "(none)"

        return self.async_show_form(
            step_id="reconfig_amazon",
            data_schema=_get_schema_step_amazon(user_input, self._data),
            errors=self._errors,
        )

    async def async_step_reconfig_forwarded_emails(
        self, user_input: dict[str, Any] | None = None
    ):
        """Configure form step forwarded emails."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                if any(
                    sensor in self._data[CONF_RESOURCES] for sensor in AMAZON_SENSORS
                ):
                    return await self.async_step_reconfig_amazon()
                if self._data[CONF_CUSTOM_IMG]:
                    return await self.async_step_reconfig_3()
                return await self.async_step_reconfig_storage()
            return await self._show_reconfig_forwarded_emails(user_input)
        return await self._show_reconfig_forwarded_emails(user_input)

    async def _show_reconfig_forwarded_emails(self, user_input=None):
        """Step forwarded emails."""
        if self._data.get(CONF_FORWARDED_EMAILS, []) == []:
            self._data[CONF_FORWARDED_EMAILS] = "(none)"

        return self.async_show_form(
            step_id="reconfig_forwarded_emails",
            data_schema=_get_schema_step_forwarded_emails(user_input, self._data),
            errors=self._errors,
        )

    async def async_step_reconfig_storage(self, user_input=None):
        """Configure form step storage."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                self.hass.config_entries.async_update_entry(
                    self._entry, data=self._data
                )
                await self.hass.config_entries.async_reload(self._entry.entry_id)
                _LOGGER.debug("%s reconfigured.", DOMAIN)
                return self.async_abort(reason="reconfigure_successful")

            return await self._show_reconfig_storage(user_input)

        return await self._show_reconfig_storage(user_input)

    async def _show_reconfig_storage(self, user_input):
        """Step 3 setup."""
        return self.async_show_form(
            step_id="reconfig_storage",
            data_schema=_get_schema_step_storage(user_input, self._data),
            errors=self._errors,
        )
