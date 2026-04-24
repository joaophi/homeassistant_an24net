from homeassistant.components.alarm_control_panel import (
    AlarmControlPanelEntity,
)
from homeassistant.components.alarm_control_panel.const import (
    AlarmControlPanelEntityFeature,
    AlarmControlPanelState,
    CodeFormat,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PIN
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import (
    CONNECTION_NETWORK_MAC,
    DeviceInfo,
    format_mac,
)
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .config_flow import CONF_REQUIRE_CODE
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
    async_add_entities([AMTAlarm(config_entry.runtime_data, config_entry)])


class AMTAlarm(CoordinatorEntity[AMTCoordinator], AlarmControlPanelEntity):  # type: ignore[misc]
    def __init__(
        self, coordinator: AMTCoordinator, config_entry: ConfigEntry[AMTCoordinator]
    ) -> None:
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = format_mac(coordinator.client.mac.hex(":"))
        self._attr_has_entity_name = True
        self._attr_name = None
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._attr_unique_id)},
            connections={(CONNECTION_NETWORK_MAC, self._attr_unique_id)},
            name=coordinator.data["messages"]["name"],
            manufacturer="Intelbras",
            model="AN-24 Net",
        )
        status = coordinator.data["status"]

        require_code = config_entry.options.get(CONF_REQUIRE_CODE, True)
        self._attr_code_format = CodeFormat.NUMBER if require_code else None
        self._attr_code_arm_required = require_code

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

    def _resolve_code(self, code: str | None) -> str:
        """Resolve the PIN code, falling back to stored PIN if not required."""
        if code:
            return code
        if not self._config_entry.options.get(CONF_REQUIRE_CODE, True):
            return self._config_entry.data[CONF_PIN]
        raise ValueError("Code is required")

    async def async_alarm_disarm(self, code: str | None = None) -> None:
        try:
            await self.coordinator.client.disarm(self._resolve_code(code))
        except WrongPasswordError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="wrong_password",
            )
        await self.coordinator.async_request_refresh()

    async def async_alarm_arm_away(self, code: str | None = None) -> None:
        try:
            await self.coordinator.client.arm(self._resolve_code(code))
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
        try:
            await self.coordinator.client.arm(self._resolve_code(code), stay=True)
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
        try:
            await self.coordinator.client.panic(self._resolve_code(code))
        except WrongPasswordError:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="wrong_password",
            )
        await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        require_code = self._config_entry.options.get(CONF_REQUIRE_CODE, True)
        self._attr_code_format = CodeFormat.NUMBER if require_code else None
        self._attr_code_arm_required = require_code

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
