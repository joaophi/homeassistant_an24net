"""The Alarme Intelbras integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .coordinator import AMTCoordinator
from .protocol import ServidorAMT

PLATFORMS: list[Platform] = [Platform.ALARM_CONTROL_PANEL, Platform.BINARY_SENSOR]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry[AMTCoordinator],
) -> bool:
    """Set up Alarme Intelbras from a config entry."""

    servidor = ServidorAMT(
        entry.data["host"],
        entry.data["port"],
        entry.data["mac"],
        entry.data["pin"],
    )
    entry.runtime_data = AMTCoordinator(hass, servidor)

    await entry.runtime_data.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: ConfigEntry[AMTCoordinator],
) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
