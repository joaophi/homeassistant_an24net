from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo, format_mac
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AMTCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry[AMTCoordinator],
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up entry."""
    async_add_entities([AMTEnergySensor(config_entry.runtime_data)])

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
            async_add_entities(
                AMTSensor(config_entry.runtime_data, i, prop, device_class, enabled)
                for prop, device_class, enabled in [
                    ("open", BinarySensorDeviceClass.OPENING, True),
                    ("violated", BinarySensorDeviceClass.PROBLEM, False),
                    ("stay", None, False),
                    ("low_battery", BinarySensorDeviceClass.BATTERY, True),
                ]
            )

    _check_device()
    # config_entry.async_on_unload(
    #     config_entry.runtime_data.async_add_listener(_check_device)
    # )


class AMTEnergySensor(CoordinatorEntity[AMTCoordinator], BinarySensorEntity):
    def __init__(self, coordinator: AMTCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = format_mac(coordinator.client.mac.hex(":")) + "_energy"
        self._attr_device_info = DeviceInfo(
            identifiers={
                # Serial numbers are unique identifiers within a specific domain
                (DOMAIN, format_mac(coordinator.client.mac.hex(":")))
            },
            name=coordinator.data["messages"]["name"],
        )
        self._attr_device_class = BinarySensorDeviceClass.PLUG
        self._attr_name = coordinator.data["messages"]["name"] + " Energy"

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._attr_is_on = not self.coordinator.data["status"]["no_energy"]
        self.async_write_ha_state()


class AMTSensor(CoordinatorEntity[AMTCoordinator], BinarySensorEntity):
    def __init__(
        self,
        coordinator: AMTCoordinator,
        index: int,
        property: str,
        device_class: BinarySensorDeviceClass | None,
        enabled: bool,
    ) -> None:
        super().__init__(coordinator, context=index)
        mac = format_mac(coordinator.client.mac.hex(":"))
        zone = coordinator.data["messages"]["zones"][index] or f"Zone {index + 1:02}"
        self._index = index
        self._property = property
        self._attr_unique_id = f"{mac}_zone_{index + 1:02}_{property}"
        self._attr_device_info = DeviceInfo(
            identifiers={
                # Serial numbers are unique identifiers within a specific domain
                (DOMAIN, f"{mac}_zone_{index + 1:02}")
            },
            name=zone,
            via_device=(DOMAIN, mac),
        )
        self._attr_name = f"{zone} {property.replace('_', ' ')}"
        self._attr_device_class = device_class
        self._attr_entity_registry_enabled_default = enabled

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        state = self.coordinator.data["status"]["zones"][self._index]
        self._attr_is_on = state[self._property]
        self.async_write_ha_state()
