"""Config flow for Alarme Intelbras integration."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
    OptionsFlowWithConfigEntry,
)
from homeassistant.const import CONF_HOST, CONF_MAC, CONF_PIN, CONF_PORT
from homeassistant.core import callback
from homeassistant.helpers.device_registry import format_mac

from .const import DOMAIN
from .protocol import SYNC_NAME, ClientAMT, WrongPasswordError

_LOGGER = logging.getLogger(__name__)

CONF_REQUIRE_CODE = "require_code"

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST, default="amt.intelbras.com.br"): str,
        vol.Required(CONF_PORT, default=9009): int,
        vol.Required(CONF_MAC): str,
        vol.Required(CONF_PIN): str,
    }
)


STEP_RECONFIGURE_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT): int,
        vol.Required(CONF_PIN): str,
        vol.Required(CONF_REQUIRE_CODE): bool,
    }
)


class AN24NetConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Alarme Intelbras."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow handler."""
        return AN24NetOptionsFlow(config_entry)

    async def _test_connection(
        self, host: str, port: int, mac: str, pin: str
    ) -> tuple[str, str | None]:
        """Test connection and return (name, error)."""
        client = ClientAMT(host, port, mac, pin)
        task = asyncio.ensure_future(client.run())
        try:
            names = await client.sync(SYNC_NAME)
            return (names[0] if names else "Intelbras"), None
        except WrongPasswordError:
            return "", "invalid_auth"
        except Exception:
            return "", "cannot_connect"
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            name, error = await self._test_connection(
                user_input[CONF_HOST],
                user_input[CONF_PORT],
                user_input[CONF_MAC],
                user_input[CONF_PIN],
            )
            if error:
                errors["base"] = error
            else:
                user_input[CONF_MAC] = format_mac(user_input[CONF_MAC])
                await self.async_set_unique_id(user_input[CONF_MAC])
                self._abort_if_unique_id_configured()
                self._data = user_input
                self._name = name
                return await self.async_step_options()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_options(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle options during initial setup."""
        if user_input is not None:
            return self.async_create_entry(
                title=self._name,
                data=self._data,
                options=user_input,
            )

        return self.async_show_form(
            step_id="options",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_REQUIRE_CODE, default=True): bool,
                }
            ),
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reconfiguration."""
        entry: ConfigEntry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            _, error = await self._test_connection(
                user_input[CONF_HOST],
                user_input[CONF_PORT],
                entry.data[CONF_MAC],
                user_input[CONF_PIN],
            )
            if error:
                errors["base"] = error
            else:
                options = {CONF_REQUIRE_CODE: user_input.pop(CONF_REQUIRE_CODE)}
                return self.async_update_reload_and_abort(
                    entry,
                    data={**entry.data, **user_input},
                    options=options,
                )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self.add_suggested_values_to_schema(
                STEP_RECONFIGURE_DATA_SCHEMA,
                {
                    CONF_HOST: entry.data[CONF_HOST],
                    CONF_PORT: entry.data[CONF_PORT],
                    CONF_PIN: entry.data[CONF_PIN],
                    CONF_REQUIRE_CODE: entry.options.get(CONF_REQUIRE_CODE, True),
                },
            ),
            errors=errors,
        )


class AN24NetOptionsFlow(OptionsFlowWithConfigEntry):
    """Handle options for Alarme Intelbras."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle options step."""
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_REQUIRE_CODE,
                        default=self.options.get(CONF_REQUIRE_CODE, True),
                    ): bool,
                }
            ),
        )
