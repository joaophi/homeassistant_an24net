from homeassistant.components.alarm_control_panel import (
    AlarmControlPanelEntity,
    AlarmControlPanelEntityFeature,
    AlarmControlPanelState,
    CodeFormat,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
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
    async_add_entities([AMTAlarm(config_entry.runtime_data)])


class AMTAlarm(CoordinatorEntity[AMTCoordinator], AlarmControlPanelEntity):
    def __init__(self, coordinator: AMTCoordinator) -> None:
        CoordinatorEntity.__init__(self, coordinator, None)
        self._attr_unique_id = coordinator.servidor.mac.hex("_")
        self._attr_device_info = DeviceInfo(
            identifiers={
                # Serial numbers are unique identifiers within a specific domain
                (DOMAIN, self._attr_unique_id)
            },
            name=coordinator.data["messages"]["name"],
        )
        self._attr_name = coordinator.data["messages"]["name"]
        self.code_format = CodeFormat.NUMBER
        self.supported_features = (
            AlarmControlPanelEntityFeature.ARM_AWAY
            | AlarmControlPanelEntityFeature.TRIGGER
        )
        stay = any(
            zone["enabled"] and zone["stay"]
            for zone in self.coordinator.data["status"]["zones"]
        )
        if stay:
            self.supported_features |= AlarmControlPanelEntityFeature.ARM_HOME

    async def async_alarm_arm_away(self, code: str | None = None) -> None:
        pass

    async def async_alarm_arm_home(self, code: str | None = None) -> None:
        pass

    async def async_alarm_trigger(self, code: str | None = None) -> None:
        pass

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self.coordinator.data["status"]["sirenTriggered"]:
            self.alarm_state = AlarmControlPanelState.TRIGGERED
        elif self.coordinator.data["status"]["partitionAArmed"]:
            self.alarm_state = AlarmControlPanelState.ARMED_AWAY
        elif self.coordinator.data["status"]["partitionBArmed"]:
            self.alarm_state = AlarmControlPanelState.ARMED_HOME
        else:
            self.alarm_state = AlarmControlPanelState.DISARMED
        self.async_write_ha_state()
