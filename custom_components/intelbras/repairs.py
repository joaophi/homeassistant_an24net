"""Repair flows for the Alarme Intelbras integration."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import data_entry_flow
from homeassistant.components.repairs import RepairsFlow
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PIN
from homeassistant.core import HomeAssistant

from .config_flow import CONF_REQUIRE_CODE
from .const import DOMAIN
from .coordinator import AMTCoordinator
from .protocol import WrongPasswordError


class BurglaryRepairFlow(RepairsFlow):
    """Repair flow to disarm the alarm after a burglary event."""

    def __init__(
        self, coordinator: AMTCoordinator, config_entry: ConfigEntry[AMTCoordinator]
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> data_entry_flow.FlowResult:
        """Handle the disarm step."""
        if not self._config_entry.options.get(CONF_REQUIRE_CODE, True):
            try:
                await self._coordinator.client.disarm(self._config_entry.data[CONF_PIN])
                return self.async_create_entry(data={})
            except (WrongPasswordError, Exception):
                pass

        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await self._coordinator.client.disarm(user_input[CONF_PIN])
                return self.async_create_entry(data={})
            except WrongPasswordError:
                errors["base"] = "invalid_auth"
            except Exception:
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({vol.Required(CONF_PIN): str}),
            errors=errors,
        )


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str | int | float | None] | None,
) -> RepairsFlow:
    """Create a fix flow for a repair issue."""
    entries = hass.config_entries.async_entries(DOMAIN)
    entry: ConfigEntry[AMTCoordinator] = entries[0]
    return BurglaryRepairFlow(entry.runtime_data, entry)
