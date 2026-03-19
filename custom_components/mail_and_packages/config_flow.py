"""Adds config flow for Mail and Packages."""

import logging
import time
import urllib.parse
from os import path
from typing import Any, Optional

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from aiohttp import web_response
from homeassistant import config_entries
from homeassistant.components.http import HomeAssistantView
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_RESOURCES,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.helpers.network import get_url

from .const import (
    AUTH_METHOD_OAUTH,
    AUTH_METHOD_PASSWORD,
    CONF_ACCESS_TOKEN_EXPIRY,
    CONF_ALLOW_EXTERNAL,
    CONF_AMAZON_DAYS,
    CONF_AMAZON_FWDS,
    CONF_AUTH_METHOD,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_CUSTOM_IMG,
    CONF_CUSTOM_IMG_FILE,
    CONF_DURATION,
    CONF_ENCRYPTED_ACCESS_TOKEN,
    CONF_ENCRYPTED_REFRESH_TOKEN,
    CONF_FOLDER,
    CONF_GENERATE_MP4,
    CONF_IMAGE_SECURITY,
    CONF_IMAP_TIMEOUT,
    CONF_OAUTH_PROVIDER,
    CONF_PATH,
    CONF_SCAN_INTERVAL,
    CONF_TOKEN_ITERATIONS,
    CONF_TOKEN_SALT,
    DEFAULT_ALLOW_EXTERNAL,
    DEFAULT_AMAZON_DAYS,
    DEFAULT_AMAZON_FWDS,
    DEFAULT_CUSTOM_IMG,
    DEFAULT_CUSTOM_IMG_FILE,
    DEFAULT_FOLDER,
    DEFAULT_GIF_DURATION,
    DEFAULT_IMAGE_SECURITY,
    DEFAULT_IMAP_TIMEOUT,
    DEFAULT_PATH,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    OAUTH_PROVIDER_GMAIL,
    OAUTH_PROVIDER_OUTLOOK,
)
from .crypto import Cryptographer
from .helpers import _check_ffmpeg, _test_login, get_resources, login
from .oauth_handler import (
    build_authorization_url,
    exchange_code_for_token,
    get_oauth_urls,
    get_user_email,
)

_LOGGER = logging.getLogger(__name__)

AUTH_CALLBACK_NAME = "api:mail_and_packages_oauth"
AUTH_CALLBACK_PATH = "/api/mail_and_packages/oauth_callback"
OAUTH_STATE = "mail_and_packages"


class MailAndPackagesOAuthCallbackView(HomeAssistantView):
    """OAuth callback view to capture the authorization code."""

    url = AUTH_CALLBACK_PATH
    name = AUTH_CALLBACK_NAME
    requires_auth = False

    def __init__(self):
        """Initialize the callback view."""
        self.token_url = ""

    @callback
    async def get(self, request):
        """Handle the GET request from the OAuth provider redirect."""
        self.token_url = str(request.url)
        return web_response.Response(
            headers={"content-type": "text/html"},
            text=(
                "<script>window.close()</script>"
                "Authorization received. You can close this window."
            ),
        )


async def _check_amazon_forwards(forwards: str) -> tuple:
    """Validate and format amazon forward emails for user input.

    Returns tuple: dict of errors, list of email addresses
    """
    amazon_forwards_list = []
    errors = []

    # Check for amazon domains
    if "@amazon" in forwards:
        errors.append("amazon_domain")

    # Check for commas
    if "," in forwards:
        amazon_forwards_list = forwards.split(",")

    # If only one address append it to the list
    elif forwards != "" or forwards:
        amazon_forwards_list.append(forwards)

    if len(errors) == 0:
        errors.append("ok")

    return errors, amazon_forwards_list


async def _validate_user_input(user_input: dict) -> tuple:
    """Valididate user input from config flow.

    Returns tuple with error messages and modified user_input
    """
    errors = {}

    # Validate amazon forwarding email addresses
    if isinstance(user_input[CONF_AMAZON_FWDS], str):
        status, amazon_list = await _check_amazon_forwards(user_input[CONF_AMAZON_FWDS])
        if status[0] == "ok":
            user_input[CONF_AMAZON_FWDS] = amazon_list
        else:
            user_input[CONF_AMAZON_FWDS] = amazon_list
            errors[CONF_AMAZON_FWDS] = status[0]

    # Check for ffmpeg if option enabled
    if user_input[CONF_GENERATE_MP4]:
        valid = await _check_ffmpeg()
    else:
        valid = True

    if not valid:
        errors[CONF_GENERATE_MP4] = "ffmpeg_not_found"

    # validate custom file exists
    if user_input[CONF_CUSTOM_IMG] and CONF_CUSTOM_IMG_FILE in user_input:
        valid = path.isfile(user_input[CONF_CUSTOM_IMG_FILE])
    else:
        valid = True

    if not valid:
        errors[CONF_CUSTOM_IMG_FILE] = "file_not_found"

    # validate scan interval
    if user_input[CONF_SCAN_INTERVAL] < 5:
        errors[CONF_SCAN_INTERVAL] = "scan_too_low"

    # validate imap timeout
    if user_input[CONF_IMAP_TIMEOUT] < 10:
        errors[CONF_IMAP_TIMEOUT] = "timeout_too_low"

    return errors, user_input


def _get_mailboxes(
    host: str,
    port: int,
    user: str,
    pwd: Optional[str] = None,
    access_token: Optional[str] = None,
) -> list:
    """Get list of mailbox folders from mail server."""
    account = login(host, port, user, pwd=pwd, access_token=access_token)

    status, folderlist = account.list()
    mailboxes = []
    if status != "OK":
        _LOGGER.error("Error listing mailboxes ... using default")
        mailboxes.append(DEFAULT_FOLDER)
    else:
        try:
            for i in folderlist:
                mailboxes.append(i.decode().split(' "/" ')[1])
        except IndexError:
            _LOGGER.error("Error creating folder array trying period")
            try:
                for i in folderlist:
                    mailboxes.append(i.decode().split(' "." ')[1])
            except IndexError:
                _LOGGER.error("Error creating folder array, using INBOX")
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
            vol.Required(CONF_HOST, default=_get_default(CONF_HOST)): str,
            vol.Required(CONF_PORT, default=_get_default(CONF_PORT)): vol.Coerce(int),
            vol.Required(CONF_USERNAME, default=_get_default(CONF_USERNAME)): str,
            vol.Required(CONF_PASSWORD, default=_get_default(CONF_PASSWORD)): str,
        }
    )


def _get_schema_oauth(user_input: list, default_dict: list) -> Any:
    """Get a schema for OAuth credential input."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> None:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            vol.Required(CONF_CLIENT_ID, default=_get_default(CONF_CLIENT_ID, "")): str,
            vol.Required(
                CONF_CLIENT_SECRET, default=_get_default(CONF_CLIENT_SECRET, "")
            ): str,
            vol.Required(
                CONF_OAUTH_PROVIDER,
                default=_get_default(CONF_OAUTH_PROVIDER, OAUTH_PROVIDER_OUTLOOK),
            ): vol.In([OAUTH_PROVIDER_GMAIL, OAUTH_PROVIDER_OUTLOOK]),
        }
    )


def _get_schema_step_2(data: list, user_input: list, default_dict: list) -> Any:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> None:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    # Determine auth method and get mailboxes accordingly
    auth_method = data.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD)
    if auth_method == AUTH_METHOD_OAUTH:
        access_token = data.get("_decrypted_access_token")
        if access_token:
            mailboxes = _get_mailboxes(
                data[CONF_HOST],
                data[CONF_PORT],
                data[CONF_USERNAME],
                access_token=access_token,
            )
        else:
            mailboxes = [DEFAULT_FOLDER]
    else:
        mailboxes = _get_mailboxes(
            data[CONF_HOST],
            data[CONF_PORT],
            data[CONF_USERNAME],
            pwd=data[CONF_PASSWORD],
        )

    return vol.Schema(
        {
            vol.Required(CONF_FOLDER, default=_get_default(CONF_FOLDER)): vol.In(
                mailboxes
            ),
            vol.Required(
                CONF_RESOURCES, default=_get_default(CONF_RESOURCES)
            ): cv.multi_select(get_resources()),
            vol.Optional(
                CONF_AMAZON_FWDS, default=_get_default(CONF_AMAZON_FWDS, "")
            ): str,
            vol.Optional(CONF_AMAZON_DAYS, default=_get_default(CONF_AMAZON_DAYS)): int,
            vol.Optional(
                CONF_SCAN_INTERVAL, default=_get_default(CONF_SCAN_INTERVAL)
            ): vol.All(vol.Coerce(int)),
            vol.Optional(
                CONF_IMAP_TIMEOUT, default=_get_default(CONF_IMAP_TIMEOUT)
            ): vol.All(vol.Coerce(int)),
            vol.Optional(
                CONF_DURATION, default=_get_default(CONF_DURATION)
            ): vol.Coerce(int),
            vol.Optional(
                CONF_GENERATE_MP4, default=_get_default(CONF_GENERATE_MP4)
            ): bool,
            vol.Optional(
                CONF_ALLOW_EXTERNAL, default=_get_default(CONF_ALLOW_EXTERNAL)
            ): bool,
            vol.Optional(CONF_CUSTOM_IMG, default=_get_default(CONF_CUSTOM_IMG)): bool,
        }
    )


def _get_schema_step_3(user_input: list, default_dict: list) -> Any:
    """Get a schema using the default_dict as a backup."""
    if user_input is None:
        user_input = {}

    def _get_default(key: str, fallback_default: Any = None) -> None:
        """Get default value for key."""
        return user_input.get(key, default_dict.get(key, fallback_default))

    return vol.Schema(
        {
            vol.Optional(
                CONF_CUSTOM_IMG_FILE,
                default=_get_default(CONF_CUSTOM_IMG_FILE, DEFAULT_CUSTOM_IMG_FILE),
            ): str,
        }
    )


def _get_schema_authorize(auth_url: str) -> Any:
    """Get the schema for the authorize step."""
    return vol.Schema(
        {
            vol.Required("auth_url_display", default=auth_url): cv.string,
            vol.Required("url"): cv.string,
        }
    )


@config_entries.HANDLERS.register(DOMAIN)
class MailAndPackagesFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Mail and Packages."""

    VERSION = 4
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    def __init__(self):
        """Initialize."""
        self._data = {}
        self._errors = {}
        self._callback_view = None
        self._auth_url = None

    async def async_step_user(self, user_input=None):
        """Handle a flow initialized by the user.

        Supports both the legacy password-based flow (for backward compatibility)
        and the new auth_method-based routing.  If the submitted data already
        contains CONF_HOST it is treated as a direct password-auth submission.
        """
        self._errors = {}

        if user_input is not None:
            auth_method = user_input.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD)

            if auth_method == AUTH_METHOD_OAUTH:
                self._data[CONF_AUTH_METHOD] = AUTH_METHOD_OAUTH
                return await self.async_step_oauth()

            # Password auth — either legacy direct submission or new-style redirect
            self._data[CONF_AUTH_METHOD] = AUTH_METHOD_PASSWORD

            if CONF_HOST in user_input:
                # Legacy-compatible: host/port/user/pwd submitted directly here
                self._data.update(user_input)
                valid = await _test_login(
                    user_input[CONF_HOST],
                    user_input[CONF_PORT],
                    user_input[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                )
                if not valid:
                    self._errors["base"] = "communication"
                else:
                    return await self.async_step_config_2()

                return await self._show_config_form(user_input)

            # New-style: only auth_method submitted, show the password form next
            return await self.async_step_password()

        return await self._show_config_form(user_input)

    async def _show_config_form(self, user_input):
        """Show the configuration form to edit configuration data."""
        # Defaults
        defaults = {
            CONF_PORT: DEFAULT_PORT,
        }

        return self.async_show_form(
            step_id="user",
            data_schema=_get_schema_step_1(user_input, defaults),
            errors=self._errors,
        )

    async def async_step_password(self, user_input=None):
        """Handle password-based IMAP authentication (explicit step)."""
        self._errors = {}

        if user_input is not None:
            self._data.update(user_input)
            self._data[CONF_AUTH_METHOD] = AUTH_METHOD_PASSWORD
            valid = await _test_login(
                user_input[CONF_HOST],
                user_input[CONF_PORT],
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
            )
            if not valid:
                self._errors["base"] = "communication"
            else:
                return await self.async_step_config_2()

            return await self._show_password_form(user_input)

        return await self._show_password_form(user_input)

    async def _show_password_form(self, user_input):
        """Show the password configuration form."""
        defaults = {
            CONF_PORT: DEFAULT_PORT,
        }

        return self.async_show_form(
            step_id="password",
            data_schema=_get_schema_step_1(user_input, defaults),
            errors=self._errors,
        )

    async def async_step_oauth(self, user_input=None):
        """Collect OAuth credentials (client_id, client_secret, provider)."""
        self._errors = {}

        if user_input is not None:
            self._data.update(user_input)
            return await self.async_step_authorize()

        return self.async_show_form(
            step_id="oauth",
            data_schema=_get_schema_oauth(user_input, {}),
            errors=self._errors,
            description_placeholders={
                "gmail_help": (
                    "Gmail: Create credentials at "
                    "https://console.cloud.google.com/apis/credentials"
                ),
                "outlook_help": (
                    "Outlook: Register an app at "
                    "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps"
                ),
            },
        )

    async def async_step_authorize(self, user_input=None):
        """Handle the OAuth authorization step."""
        self._errors = {}

        provider = self._data.get(CONF_OAUTH_PROVIDER, OAUTH_PROVIDER_OUTLOOK)
        redirect_uri = f"{get_url(self.hass)}{AUTH_CALLBACK_PATH}"

        self._auth_url = build_authorization_url(
            provider=provider,
            client_id=self._data[CONF_CLIENT_ID],
            redirect_uri=redirect_uri,
            state=OAUTH_STATE,
        )

        # Register OAuth callback view if not already registered
        if not self._callback_view:
            self._callback_view = MailAndPackagesOAuthCallbackView()
            self.hass.http.register_view(self._callback_view)

        if user_input is not None:
            error = await self._validate_oauth_response(user_input)
            if not error:
                return await self._async_complete_oauth()
            self._errors["url"] = error

        return self.async_show_form(
            step_id="authorize",
            description_placeholders={"auth_url": self._auth_url},
            data_schema=_get_schema_authorize(self._auth_url),
            errors=self._errors,
        )

    async def _validate_oauth_response(self, user_input: dict) -> Optional[str]:
        """Validate the OAuth callback URL and extract the authorization code.

        Returns None on success, error key string on failure.
        """
        url = user_input.get("url", "")

        if not url or "code=" not in url:
            _LOGGER.error("No authorization code found in URL: %s", url)
            return "invalid_url"

        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            state = query_params.get("state", [None])[0]
            if state != OAUTH_STATE:
                _LOGGER.error("Invalid OAuth state parameter: %s", state)
                return "invalid_url"

            code_list = query_params.get("code")
            if not code_list:
                _LOGGER.error("No 'code' in OAuth callback URL: %s", parsed_url.query)
                return "invalid_url"

            code = urllib.parse.unquote(code_list[0])
            if not code:
                _LOGGER.error("OAuth authorization code is empty")
                return "invalid_url"

            self._data["_auth_code"] = code
            return None
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Error extracting OAuth code from URL: %s", err)
            return "invalid_url"

    async def _async_complete_oauth(self):
        """Exchange the authorization code for tokens and store them."""
        provider = self._data[CONF_OAUTH_PROVIDER]
        redirect_uri = f"{get_url(self.hass)}{AUTH_CALLBACK_PATH}"

        tokens = await exchange_code_for_token(
            self.hass,
            provider=provider,
            client_id=self._data[CONF_CLIENT_ID],
            client_secret=self._data[CONF_CLIENT_SECRET],
            code=self._data["_auth_code"],
            redirect_uri=redirect_uri,
        )

        if not tokens:
            return self.async_abort(reason="token_request_failed")

        access_token = tokens.get("access_token", "")
        user_email = await get_user_email(self.hass, provider, access_token)

        if not user_email:
            return self.async_abort(reason="token_request_failed")

        # Encrypt tokens for storage
        crypto = Cryptographer(password=self._data[CONF_CLIENT_SECRET])
        encrypted_access_token = crypto.encrypt(access_token)
        encrypted_refresh_token = crypto.encrypt(tokens.get("refresh_token", ""))
        expiry = int(time.time()) + int(tokens.get("expires_in", 3600))

        # Set up IMAP connection details from provider
        oauth_urls = get_oauth_urls(provider)

        self._data.update(
            {
                CONF_HOST: oauth_urls["imap_host"],
                CONF_PORT: oauth_urls["imap_port"],
                CONF_USERNAME: user_email,
                CONF_ENCRYPTED_ACCESS_TOKEN: encrypted_access_token,
                CONF_ENCRYPTED_REFRESH_TOKEN: encrypted_refresh_token,
                CONF_ACCESS_TOKEN_EXPIRY: expiry,
                CONF_TOKEN_SALT: crypto.salt,
                CONF_TOKEN_ITERATIONS: crypto.iterations,
                # Temporary key for mailbox listing (not stored in config entry)
                "_decrypted_access_token": access_token,
            }
        )

        return await self.async_step_config_2()

    async def async_step_config_2(self, user_input=None):
        """Configure form step 2."""
        self._errors = {}
        if user_input is not None:
            self._errors, user_input = await _validate_user_input(user_input)
            self._data.update(user_input)
            if len(self._errors) == 0:
                if self._data[CONF_CUSTOM_IMG]:
                    return await self.async_step_config_3()
                return self._create_config_entry()
            return await self._show_config_2(user_input)

        return await self._show_config_2(user_input)

    def _create_config_entry(self):
        """Create the config entry, removing any temporary runtime keys."""
        data = {k: v for k, v in self._data.items() if not k.startswith("_")}
        auth_method = data.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD)
        if auth_method == AUTH_METHOD_OAUTH:
            title = data.get(CONF_USERNAME)
        else:
            title = data.get(CONF_HOST)
        return self.async_create_entry(title=title, data=data)

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
            CONF_AMAZON_FWDS: DEFAULT_AMAZON_FWDS,
            CONF_AMAZON_DAYS: DEFAULT_AMAZON_DAYS,
            CONF_GENERATE_MP4: False,
            CONF_ALLOW_EXTERNAL: DEFAULT_ALLOW_EXTERNAL,
            CONF_CUSTOM_IMG: DEFAULT_CUSTOM_IMG,
        }

        return self.async_show_form(
            step_id="config_2",
            data_schema=_get_schema_step_2(self._data, user_input, defaults),
            errors=self._errors,
        )

    async def async_step_config_3(self, user_input=None):
        """Configure form step 3."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                return self._create_config_entry()
            return await self._show_config_3(user_input)

        return await self._show_config_3(user_input)

    async def _show_config_3(self, user_input):
        """Step 3 setup."""
        defaults = {
            CONF_CUSTOM_IMG_FILE: DEFAULT_CUSTOM_IMG_FILE,
        }

        return self.async_show_form(
            step_id="config_3",
            data_schema=_get_schema_step_3(user_input, defaults),
            errors=self._errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Redirect to options flow."""
        return MailAndPackagesOptionsFlow(config_entry)


class MailAndPackagesOptionsFlow(config_entries.OptionsFlow):
    """Options flow for Mail and Packages."""

    def __init__(self, config_entry):
        """Initialize."""
        self.config = config_entry
        self._data = dict(config_entry.options)
        self._errors = {}

    def _get_auth_method(self) -> str:
        """Return the auth method from config entry or options."""
        return self._data.get(
            CONF_AUTH_METHOD,
            self.config.data.get(CONF_AUTH_METHOD, AUTH_METHOD_PASSWORD),
        )

    async def async_step_init(self, user_input=None):
        """Manage Mail and Packages options."""
        auth_method = self._get_auth_method()

        if auth_method == AUTH_METHOD_OAUTH:
            # OAuth entries skip re-authentication and go straight to settings
            return await self.async_step_options_2(user_input)

        if user_input is not None:
            self._data.update(user_input)

            valid = await _test_login(
                user_input[CONF_HOST],
                user_input[CONF_PORT],
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
            )
            if not valid:
                self._errors["base"] = "communication"
            else:
                return await self.async_step_options_2()

            return await self._show_options_form(user_input)

        return await self._show_options_form(user_input)

    async def _show_options_form(self, user_input):
        """Show the configuration form to edit location data."""
        return self.async_show_form(
            step_id="init",
            data_schema=_get_schema_step_1(user_input, self._data),
            errors=self._errors,
        )

    async def async_step_options_2(self, user_input=None):
        """Configure form step 2."""
        self._errors = {}
        if user_input is not None:
            self._errors, user_input = await _validate_user_input(user_input)
            self._data.update(user_input)
            if len(self._errors) == 0:
                if self._data[CONF_CUSTOM_IMG]:
                    return await self.async_step_options_3()
                return self.async_create_entry(title="", data=self._data)
            return await self._show_step_options_2(user_input)
        return await self._show_step_options_2(user_input)

    async def _show_step_options_2(self, user_input):
        """Step 2 of options."""
        # Merge config entry data into self._data for mailbox lookup
        merged = dict(self.config.data)
        merged.update(self._data)

        defaults = {
            CONF_FOLDER: self._data.get(CONF_FOLDER),
            CONF_SCAN_INTERVAL: self._data.get(CONF_SCAN_INTERVAL),
            CONF_PATH: self._data.get(CONF_PATH),
            CONF_DURATION: self._data.get(CONF_DURATION),
            CONF_IMAGE_SECURITY: self._data.get(CONF_IMAGE_SECURITY),
            CONF_IMAP_TIMEOUT: self._data.get(CONF_IMAP_TIMEOUT)
            or DEFAULT_IMAP_TIMEOUT,
            CONF_AMAZON_FWDS: self._data.get(CONF_AMAZON_FWDS) or DEFAULT_AMAZON_FWDS,
            CONF_AMAZON_DAYS: self._data.get(CONF_AMAZON_DAYS) or DEFAULT_AMAZON_DAYS,
            CONF_GENERATE_MP4: self._data.get(CONF_GENERATE_MP4),
            CONF_ALLOW_EXTERNAL: self._data.get(CONF_ALLOW_EXTERNAL),
            CONF_RESOURCES: self._data.get(CONF_RESOURCES),
            CONF_CUSTOM_IMG: self._data.get(CONF_CUSTOM_IMG) or DEFAULT_CUSTOM_IMG,
        }

        return self.async_show_form(
            step_id="options_2",
            data_schema=_get_schema_step_2(merged, user_input, defaults),
            errors=self._errors,
        )

    async def async_step_options_3(self, user_input=None):
        """Configure form step 3."""
        self._errors = {}
        if user_input is not None:
            self._data.update(user_input)
            self._errors, user_input = await _validate_user_input(self._data)
            if len(self._errors) == 0:
                return self.async_create_entry(title="", data=self._data)
            return await self._show_step_options_3(user_input)

        return await self._show_step_options_3(user_input)

    async def _show_step_options_3(self, user_input):
        """Step 3 setup."""
        # Defaults
        defaults = {
            CONF_CUSTOM_IMG_FILE: self._data.get(CONF_CUSTOM_IMG_FILE)
            or DEFAULT_CUSTOM_IMG_FILE,
        }

        return self.async_show_form(
            step_id="options_3",
            data_schema=_get_schema_step_3(user_input, defaults),
            errors=self._errors,
        )
