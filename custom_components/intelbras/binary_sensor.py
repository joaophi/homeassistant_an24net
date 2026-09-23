from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .coordinator import AMTCoordinator

PARALLEL_UPDATES = 0

ZONE_PROPS: list[tuple[str, BinarySensorDeviceClass | None, EntityCategory | None]] = [
    ("open", BinarySensorDeviceClass.OPENING, None),
    ("violated", BinarySensorDeviceClass.PROBLEM, EntityCategory.DIAGNOSTIC),
    ("stay", None, EntityCategory.DIAGNOSTIC),
    ("low_battery", BinarySensorDeviceClass.BATTERY, EntityCategory.DIAGNOSTIC),
]


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
                AMTSensor(config_entry.runtime_data, i, prop, device_class, category)
                for prop, device_class, category in ZONE_PROPS
            )

    _check_device()
    config_entry.async_on_unload(
        config_entry.runtime_data.async_add_listener(_check_device)
    )


class AMTEnergySensor(CoordinatorEntity[AMTCoordinator], BinarySensorEntity):  # pyright: ignore[reportIncompatibleVariableOverride]
    def __init__(self, coordinator: AMTCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.mac}_energy"
        self._attr_device_info = coordinator.device_info
        self._attr_device_class = BinarySensorDeviceClass.PLUG
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_has_entity_name = True
        self._attr_translation_key = "energy"
        self._attr_is_on = not coordinator.data["status"]["no_energy"]

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._attr_is_on = not self.coordinator.data["status"]["no_energy"]
        self.async_write_ha_state()


class AMTSensor(CoordinatorEntity[AMTCoordinator], BinarySensorEntity):  # pyright: ignore[reportIncompatibleVariableOverride]
    def __init__(
        self,
        coordinator: AMTCoordinator,
        index: int,
        property: str,
        device_class: BinarySensorDeviceClass | None,
        category: EntityCategory | None,
    ) -> None:
        super().__init__(coordinator, context=index)
        self._index = index
        self._property = property
        self._attr_unique_id = f"{coordinator.mac}_zone_{index + 1:02}_{property}"
        self._attr_device_info = coordinator.zone_device_info(index)
        self._attr_has_entity_name = True
        if property != "open":
            self._attr_translation_key = property
        else:
            self._attr_name = None
        self._attr_device_class = device_class
        self._attr_entity_category = category
        self._attr_is_on = coordinator.data["status"]["zones"][index][property]

    @property
    def available(self) -> bool:  # pyright: ignore[reportIncompatibleVariableOverride]
        """Return if the zone is enabled and reporting over RF."""
        return super().available and self.coordinator.zone_available(self._index)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        state = self.coordinator.data["status"]["zones"][self._index]
        self._attr_is_on = state[self._property]
        self.async_write_ha_state()
