"""Config flow for Alarme Intelbras integration."""

from __future__ import annotations

import logging
from asyncio import TaskGroup
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_MAC, CONF_PIN, CONF_PORT
from homeassistant.helpers.device_registry import format_mac

from .const import DOMAIN
from .protocol import SYNC_NAME, ClientAMT

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST, default="amt.intelbras.com.br"): str,
        vol.Required(CONF_PORT, default=9009): int,
        vol.Required(CONF_MAC): str,
        vol.Required(CONF_PIN): str,
    }
)


class AN24NetConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Alarme Intelbras."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            client = ClientAMT(
                user_input[CONF_HOST],
                user_input[CONF_PORT],
                user_input[CONF_MAC],
                user_input[CONF_PIN],
            )

            try:
                async with TaskGroup() as tg:
                    task = tg.create_task(client.run())
                    [name] = await client.sync(SYNC_NAME)
                    task.cancel()
            except Exception:
                errors["base"] = "cannot_connect"
            else:
                user_input[CONF_MAC] = format_mac(user_input[CONF_MAC])
                await self.async_set_unique_id(user_input[CONF_MAC])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=name, data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )
