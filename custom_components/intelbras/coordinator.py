"""The Alarme Intelbras integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from itertools import batched
from typing import TypedDict

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.issue_registry import (
    IssueSeverity,
    async_create_issue,
    async_delete_issue,
)
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN
from .protocol import (
    CID_EVENT_TYPES,
    SYNC_NAME,
    SYNC_ZONE,
    ClientAMT,
    EventRecord,
    Status,
    parse_push_event,
)

_LOGGER = logging.getLogger(__name__)


class Messages(TypedDict):
    name: str
    zones: list[str]


class Data(TypedDict):
    messages: Messages
    status: Status


class AMTCoordinator(DataUpdateCoordinator[Data]):
    def __init__(
        self,
        hass: HomeAssistant,
        client: ClientAMT,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="Alarme AMT",
            update_interval=timedelta(seconds=5),
            always_update=True,
        )
        self.client = client
        self.__messages: Messages = {
            "name": "AN24Net",
            "zones": [f"Zone {index + 1:02}" for index in range(24)],
        }
        self.__events: list[EventRecord] = []
        self.client.on_push = self._handle_push

    @callback
    def _handle_push(self, data: bytes) -> None:
        """Handle a PUSH_COMMAND from the alarm panel."""
        try:
            event = parse_push_event(data)
            self._process_repair_event(event)
            self._apply_push_to_status(event)
        except Exception:
            _LOGGER.warning("Failed to parse push event: %s", data.hex(":"))

    @callback
    def _apply_push_to_status(self, event: EventRecord) -> None:
        """Update coordinator status from a push event."""
        status = self.data["status"]
        event_type = CID_EVENT_TYPES.get((event["qualifier"], event["code"]))
        zone = event["zone"]

        if event_type == "arm":
            status["partitionAArmed"] = True
        elif event_type == "disarm":
            status["partitionAArmed"] = False
            status["partitionBArmed"] = False
            status["sirenTriggered"] = False
        elif event_type == "burglary" and 1 <= zone <= 24:
            status["zones"][zone - 1]["violated"] = True
            status["sirenTriggered"] = True
        elif event_type == "burglary_restore" and 1 <= zone <= 24:
            status["zones"][zone - 1]["violated"] = False
        elif event_type == "power_failure":
            status["no_energy"] = True
        elif event_type == "power_restore":
            status["no_energy"] = False
        elif event_type == "low_battery" and 1 <= zone <= 24:
            status["zones"][zone - 1]["low_battery"] = True
        elif event_type == "battery_restore" and 1 <= zone <= 24:
            status["zones"][zone - 1]["low_battery"] = False
        else:
            return

        self.async_set_updated_data(self.data)

    def _zone_name(self, zone: int) -> str:
        """Get the display name for a zone number."""
        if 1 <= zone <= 24:
            return self.__messages["zones"][zone - 1] or f"Zone {zone:02}"
        return f"Zone {zone:02}"

    @callback
    def _process_repair_event(self, event: EventRecord) -> None:
        """Create or delete repair issues based on event type."""
        zone = event["zone"]
        if zone == 0:
            return
        event_type = CID_EVENT_TYPES.get((event["qualifier"], event["code"]))
        if event_type == "rf_supervision_failure":
            self._create_zone_issue("rf_supervision_failure", zone)
        elif event_type == "rf_supervision_restore":
            async_delete_issue(self.hass, DOMAIN, f"rf_supervision_failure_{zone}")

    @callback
    def _create_zone_issue(self, issue_type: str, zone: int) -> None:
        """Create a repair issue for a zone."""
        async_create_issue(
            self.hass,
            DOMAIN,
            f"{issue_type}_{zone}",
            is_fixable=False,
            severity=IssueSeverity.WARNING,
            translation_key=issue_type,
            translation_placeholders={"zone": self._zone_name(zone)},
        )

    def _scan_unresolved_issues(self) -> None:
        """Scan the ring buffer for unresolved RF failures and low battery."""
        rf_status: dict[int, str] = {}
        battery_status: dict[int, str] = {}

        for event in self.__events:  # newest first
            zone = event["zone"]
            if zone == 0:
                continue
            event_type = CID_EVENT_TYPES.get((event["qualifier"], event["code"]))
            if event_type in ("rf_supervision_failure", "rf_supervision_restore") and zone not in rf_status:
                rf_status[zone] = event_type
            if event_type in ("low_battery", "battery_restore") and zone not in battery_status:
                battery_status[zone] = event_type

        for zone, event_type in rf_status.items():
            if event_type == "rf_supervision_failure":
                self._create_zone_issue("rf_supervision_failure", zone)

        for zone, event_type in battery_status.items():
            if event_type == "low_battery":
                self._create_zone_issue("low_battery", zone)

    async def _async_setup(self) -> None:
        try:
            [name] = await self.client.sync(SYNC_NAME)

            zones: list[str] = []
            for indexes in batched(range(24), n=8):
                data = await self.client.sync(SYNC_ZONE, bytes(indexes))
                zones.extend(data)

            self.__messages = {
                "name": name,
                "zones": zones,
            }
        except Exception:
            _LOGGER.warning("Failed to fetch device names, using defaults")

        try:
            self.__events = await self.client.fetch_events()
            self._scan_unresolved_issues()
        except Exception:
            _LOGGER.warning("Failed to fetch event log")

    async def _async_update_data(self) -> Data:
        try:
            data = await self.client.status()
        except Exception as ex:
            raise UpdateFailed("Erro ao atualizar os dados") from ex

        for i, zone in enumerate(data["zones"]):
            if not zone["enabled"]:
                continue
            zone_num = i + 1
            if zone["low_battery"]:
                self._create_zone_issue("low_battery", zone_num)
            else:
                async_delete_issue(self.hass, DOMAIN, f"low_battery_{zone_num}")

        return {
            "status": data,
            "messages": self.__messages,
        }
