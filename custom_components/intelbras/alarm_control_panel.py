from homeassistant.components.alarm_control_panel import (
    AlarmControlPanelEntity,
)
from homeassistant.components.alarm_control_panel.const import (
    AlarmControlPanelEntityFeature,
    AlarmControlPanelState,
    CodeFormat,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo, format_mac
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AMTCoordinator
from .protocol import OpenZoneError, WrongPasswordError

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry[AMTCoordinator],
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up entry."""
    async_add_entities([AMTAlarm(config_entry.runtime_data)])


class AMTAlarm(CoordinatorEntity[AMTCoordinator], AlarmControlPanelEntity):  # type: ignore[misc]
    def __init__(self, coordinator: AMTCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = format_mac(coordinator.client.mac.hex(":"))
        self._attr_has_entity_name = True
        self._attr_name = None
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._attr_unique_id)},
            name=coordinator.data["messages"]["name"],
            manufacturer="Intelbras",
            model="AN-24 Net",
        )
        self._attr_code_format = CodeFormat.NUMBER
        self._attr_supported_features = (
            AlarmControlPanelEntityFeature.ARM_AWAY
            | AlarmControlPanelEntityFeature.TRIGGER
        )

    async def async_alarm_disarm(self, code: str | None = None) -> None:
        if code is None:
            raise ValueError("Code is required to disarm the alarm")
        try:
            await self.coordinator.client.disarm(code)
        except WrongPasswordError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="wrong_password",
            )
        await self.coordinator.async_request_refresh()

    async def async_alarm_arm_away(self, code: str | None = None) -> None:
        if code is None:
            raise ValueError("Code is required to arm the alarm")
        try:
            await self.coordinator.client.arm(code)
        except WrongPasswordError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="wrong_password",
            )
        except OpenZoneError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="open_zone",
            )
        await self.coordinator.async_request_refresh()

    async def async_alarm_arm_home(self, code: str | None = None) -> None:
        if code is None:
            raise ValueError("Code is required to arm the alarm")
        try:
            await self.coordinator.client.arm(code, stay=True)
        except WrongPasswordError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="wrong_password",
            )
        except OpenZoneError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="open_zone",
            )
        await self.coordinator.async_request_refresh()

    async def async_alarm_trigger(self, code: str | None = None) -> None:
        if code is None:
            raise ValueError("Code is required to trigger the alarm")
        try:
            await self.coordinator.client.panic(code)
        except WrongPasswordError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="wrong_password",
            )
        await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        status = self.coordinator.data["status"]

        stay = any(zone["enabled"] and zone["stay"] for zone in status["zones"])
        features = (
            AlarmControlPanelEntityFeature.ARM_AWAY
            | AlarmControlPanelEntityFeature.TRIGGER
        )
        if stay:
            features |= AlarmControlPanelEntityFeature.ARM_HOME
        self._attr_supported_features = features

        if status["sirenTriggered"]:
            self._attr_alarm_state = AlarmControlPanelState.TRIGGERED
        elif status["partitionAArmed"]:
            self._attr_alarm_state = AlarmControlPanelState.ARMED_AWAY
        elif status["partitionBArmed"]:
            self._attr_alarm_state = AlarmControlPanelState.ARMED_HOME
        else:
            self._attr_alarm_state = AlarmControlPanelState.DISARMED

        self.async_write_ha_state()
