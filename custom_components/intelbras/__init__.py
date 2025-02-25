"""The Alarme Intelbras integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import format_mac

from .const import DOMAIN
from .coordinator import AMTCoordinator
from .protocol import ClientAMT

PLATFORMS: list[Platform] = [
    Platform.ALARM_CONTROL_PANEL,
    Platform.BINARY_SENSOR,
    Platform.SWITCH,
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry[AMTCoordinator],
) -> bool:
    """Set up Alarme Intelbras from a config entry."""

    device_registry = dr.async_get(hass)
    mac = format_mac(entry.data["mac"])
    enabled_zones: set[int] = {
        i
        for i in range(24)
        if (
            device_registry.async_get_device(
                identifiers={(DOMAIN, f"{mac}_zone_{i + 1:02}")}
            )
        )
    }

    def delete_stale() -> None:
        current_devices = {
            i
            for i, zone in enumerate(entry.runtime_data.data["status"]["zones"])
            if zone["enabled"]
        }
        deleted_devices = enabled_zones - current_devices
        enabled_zones.update(current_devices)

        for i in deleted_devices:
            enabled_zones.remove(i)
            device = device_registry.async_get_device(
                identifiers={(DOMAIN, f"{mac}_zone_{i + 1:02}")}
            )
            if device:
                device_registry.async_update_device(
                    device_id=device.id,
                    remove_config_entry_id=entry.entry_id,
                )

    client = ClientAMT(
        entry.data["host"],
        entry.data["port"],
        entry.data["mac"],
        entry.data["pin"],
    )
    entry.async_create_background_task(hass, client.run(), "client.run")

    entry.runtime_data = AMTCoordinator(hass, client)
    entry.async_on_unload(entry.runtime_data.async_add_listener(delete_stale))
    await entry.runtime_data.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: ConfigEntry[AMTCoordinator],
) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
