from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo, format_mac
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AMTCoordinator

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry[AMTCoordinator],
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up entry."""
    coordinator = config_entry.runtime_data
    entities: list[SwitchEntity] = [AMTPGMSwitch(coordinator)]
    if coordinator.client.is_proxy:
        entities.append(AMTDisableUpstreamSwitch(coordinator))
    async_add_entities(entities)

    enabled_zones: set[int] = set()

    def _check_device() -> None:
        current_devices = {
            i
            for i, zone in enumerate(config_entry.runtime_data.data["status"]["zones"])
            if zone["enabled"]
        }
        new_devices = current_devices - enabled_zones
        enabled_zones.update(new_devices)
        for i in new_devices:
            async_add_entities([AMTAnnulledSwitch(config_entry.runtime_data, i)])

    _check_device()
    # config_entry.async_on_unload(
    #     config_entry.runtime_data.async_add_listener(_check_device)
    # )


class AMTPGMSwitch(CoordinatorEntity[AMTCoordinator], SwitchEntity):  # type: ignore[misc]
    def __init__(self, coordinator: AMTCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = format_mac(coordinator.client.mac.hex(":")) + "_pgm"
        self._attr_has_entity_name = True
        self._attr_translation_key = "pgm"
        self._attr_entity_registry_enabled_default = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, format_mac(coordinator.client.mac.hex(":")))},
            name=coordinator.data["messages"]["name"],
            manufacturer="Intelbras",
            model="AN-24 Net",
        )

        self._attr_is_on = coordinator.data["status"]["pgm"]

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on."""
        await self.coordinator.client.pgm(on=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off."""
        await self.coordinator.client.pgm(on=False)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._attr_is_on = self.coordinator.data["status"]["pgm"]
        self.async_write_ha_state()


class AMTAnnulledSwitch(CoordinatorEntity[AMTCoordinator], SwitchEntity):  # type: ignore[misc]
    def __init__(self, coordinator: AMTCoordinator, index: int) -> None:
        super().__init__(coordinator, context=index)
        mac = format_mac(coordinator.client.mac.hex(":"))
        zone = coordinator.data["messages"]["zones"][index] or f"Zone {index + 1:02}"
        self._index = index
        self._attr_unique_id = f"{mac}_zone_{index + 1:02}_annulled"
        self._attr_has_entity_name = True
        self._attr_translation_key = "annulled"
        self._attr_entity_category = EntityCategory.CONFIG
        self._attr_entity_registry_enabled_default = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{mac}_zone_{index + 1:02}")},
            name=zone,
            via_device=(DOMAIN, mac),
        )

        self._attr_is_on = coordinator.data["status"]["zones"][index]["annulled"]

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the entity on."""
        annuled = [
            i + 1
            for i, zone in enumerate(self.coordinator.data["status"]["zones"])
            if zone["annulled"]
        ]
        annuled.append(self._index + 1)
        await self.coordinator.client.bypass(annuled)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the entity off."""
        annuled = [
            i + 1
            for i, zone in enumerate(self.coordinator.data["status"]["zones"])
            if zone["annulled"]
        ]
        if (self._index + 1) in annuled:
            annuled.remove(self._index + 1)
        await self.coordinator.client.bypass(annuled)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        state = self.coordinator.data["status"]["zones"][self._index]
        self._attr_is_on = state["annulled"]
        self.async_write_ha_state()


class AMTDisableUpstreamSwitch(CoordinatorEntity[AMTCoordinator], SwitchEntity):  # type: ignore[misc]
    """Switch to disable proxy upstream push forwarding to Intelbras cloud."""

    def __init__(self, coordinator: AMTCoordinator) -> None:
        super().__init__(coordinator)
        mac = format_mac(coordinator.client.mac.hex(":"))
        self._attr_unique_id = f"{mac}_disable_upstream"
        self._attr_has_entity_name = True
        self._attr_translation_key = "disable_upstream"
        self._attr_entity_category = EntityCategory.CONFIG
        self._attr_entity_registry_enabled_default = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, mac)},
            name=coordinator.data["messages"]["name"],
            manufacturer="Intelbras",
            model="AN-24 Net",
        )
        self._attr_is_on = not coordinator.data["status"]["upstream_push"]

    def _check_proxy(self) -> None:
        if not self.coordinator.client.is_proxy:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="not_proxied",
            )

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Disable upstream push forwarding."""
        self._check_proxy()
        await self.coordinator.client.set_upstream_push(enabled=False)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Enable upstream push forwarding."""
        self._check_proxy()
        await self.coordinator.client.set_upstream_push(enabled=True)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._attr_is_on = not self.coordinator.data["status"]["upstream_push"]
        self.async_write_ha_state()
