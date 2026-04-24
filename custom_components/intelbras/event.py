"""Event entities for the Intelbras AN-24 Net alarm."""

from __future__ import annotations

from homeassistant.components.event import EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo, format_mac
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import DOMAIN, SIGNAL_PUSH_EVENT
from .coordinator import AMTCoordinator
from .protocol import (
    CID_EVENT_TYPES,
    SYSTEM_EVENT_TYPES,
    ZONE_EVENT_TYPES,
    EventRecord,
)

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry[AMTCoordinator],
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up event entities."""
    coordinator = config_entry.runtime_data
    events = coordinator.events

    # System event entity
    system_events = [e for e in events if e["zone"] == 0]
    latest_system = system_events[0] if system_events else None
    async_add_entities([AMTSystemEvent(coordinator, latest_system)])

    # Zone event entities for enabled zones
    enabled_zones: set[int] = set()

    def _check_zones() -> None:
        current_zones = {
            i
            for i, zone in enumerate(coordinator.data["status"]["zones"])
            if zone["enabled"]
        }
        new_zones = current_zones - enabled_zones
        enabled_zones.update(new_zones)
        for i in new_zones:
            zone_num = i + 1
            zone_events = [e for e in events if e["zone"] == zone_num]
            latest = zone_events[0] if zone_events else None
            async_add_entities([AMTZoneEvent(coordinator, i, latest)])

    _check_zones()


class AMTSystemEvent(EventEntity):
    """System-level events (power, arm/disarm, battery)."""

    _attr_event_types = SYSTEM_EVENT_TYPES
    _attr_has_entity_name = True
    _attr_translation_key = "system_event"

    def __init__(
        self,
        coordinator: AMTCoordinator,
        initial_event: EventRecord | None,
    ) -> None:
        mac = format_mac(coordinator.client.mac.hex(":"))
        self._attr_unique_id = f"{mac}_system_event"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, mac)},
        )
        self._initial_event = initial_event

    async def async_added_to_hass(self) -> None:
        """Set up initial state and real-time push listener."""
        await super().async_added_to_hass()
        if self._initial_event is not None:
            event_type = CID_EVENT_TYPES.get(
                (self._initial_event["qualifier"], self._initial_event["code"])
            )
            if event_type and event_type in self._attr_event_types:
                self._trigger_event(
                    event_type,
                    {"timestamp": self._initial_event["timestamp"]},
                )
                self.async_write_ha_state()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_PUSH_EVENT, self._handle_push_event
            )
        )

    @callback
    def _handle_push_event(self, event: EventRecord) -> None:
        """Handle a real-time push event from the alarm panel."""
        if event["zone"] != 0:
            return
        event_type = CID_EVENT_TYPES.get((event["qualifier"], event["code"]))
        if event_type and event_type in self._attr_event_types:
            self._trigger_event(event_type, {"timestamp": event["timestamp"]})
            self.async_write_ha_state()


class AMTZoneEvent(EventEntity):
    """Per-zone events (burglary, RF supervision, battery)."""

    _attr_event_types = ZONE_EVENT_TYPES
    _attr_has_entity_name = True
    _attr_translation_key = "zone_event"

    def __init__(
        self,
        coordinator: AMTCoordinator,
        index: int,
        initial_event: EventRecord | None,
    ) -> None:
        mac = format_mac(coordinator.client.mac.hex(":"))
        zone = coordinator.data["messages"]["zones"][index] or f"Zone {index + 1:02}"
        self._zone_num = index + 1
        self._attr_unique_id = f"{mac}_zone_{index + 1:02}_event"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{mac}_zone_{index + 1:02}")},
            name=zone,
            via_device=(DOMAIN, mac),
        )
        self._initial_event = initial_event

    async def async_added_to_hass(self) -> None:
        """Set up initial state and real-time push listener."""
        await super().async_added_to_hass()
        if self._initial_event is not None:
            event_type = CID_EVENT_TYPES.get(
                (self._initial_event["qualifier"], self._initial_event["code"])
            )
            if event_type and event_type in self._attr_event_types:
                self._trigger_event(
                    event_type,
                    {"timestamp": self._initial_event["timestamp"]},
                )
                self.async_write_ha_state()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_PUSH_EVENT, self._handle_push_event
            )
        )

    @callback
    def _handle_push_event(self, event: EventRecord) -> None:
        """Handle a real-time push event from the alarm panel."""
        if event["zone"] != self._zone_num:
            return
        event_type = CID_EVENT_TYPES.get((event["qualifier"], event["code"]))
        if event_type and event_type in self._attr_event_types:
            self._trigger_event(event_type, {"timestamp": event["timestamp"]})
            self.async_write_ha_state()
