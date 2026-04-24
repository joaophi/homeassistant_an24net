"""The Alarme Intelbras integration."""

from __future__ import annotations

import logging
from copy import deepcopy
from datetime import timedelta
from time import monotonic
from itertools import batched
from typing import TypedDict

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
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
    WrongPasswordError,
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
        )
        self.client = client
        self.__messages: Messages = {
            "name": "AN24Net",
            "zones": [f"Zone {index + 1:02}" for index in range(24)],
        }
        self.__events: list[EventRecord] = []
        self.__last_failed = False
        self.__messages_last_sync = 0.0
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
        data: Data = deepcopy(self.data)
        status = data["status"]
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
        elif event_type == "pgm_activate":
            status["pgm"] = True
        elif event_type == "pgm_deactivate":
            status["pgm"] = False
        else:
            return

        self.async_set_updated_data(data)

    def _zone_name(self, zone: int) -> str:
        """Get the display name for a zone number."""
        if 1 <= zone <= 24:
            return self.__messages["zones"][zone - 1] or f"Zone {zone:02}"
        return f"Zone {zone:02}"

    @callback
    def _process_repair_event(self, event: EventRecord) -> None:
        """Create or delete repair issues based on event type."""
        event_type = CID_EVENT_TYPES.get((event["qualifier"], event["code"]))
        zone = event["zone"]

        if event_type == "rf_supervision_failure" and zone:
            self._create_zone_issue("rf_supervision_failure", zone)
        elif event_type == "rf_supervision_restore" and zone:
            async_delete_issue(self.hass, DOMAIN, f"rf_supervision_failure_{zone}")
        elif event_type == "system_battery_low":
            async_create_issue(
                self.hass,
                DOMAIN,
                "system_battery_low",
                is_fixable=False,
                severity=IssueSeverity.WARNING,
                translation_key="system_battery_low",
            )
        elif event_type == "system_battery_restore":
            async_delete_issue(self.hass, DOMAIN, "system_battery_low")
        elif event_type == "burglary" and zone:
            async_create_issue(
                self.hass,
                DOMAIN,
                f"burglary_{zone}",
                is_fixable=True,
                severity=IssueSeverity.CRITICAL,
                translation_key="burglary",
                translation_placeholders={"zone": self._zone_name(zone)},
            )
        elif event_type == "burglary_restore" and zone:
            async_delete_issue(self.hass, DOMAIN, f"burglary_{zone}")
        elif event_type == "disarm":
            for i in range(1, 25):
                async_delete_issue(self.hass, DOMAIN, f"burglary_{i}")

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

    def _scan_unresolved_issues(self, enabled_zones: set[int]) -> None:
        """Scan the ring buffer for unresolved RF failures, battery, and system issues."""
        rf_status: dict[int, str] = {}
        battery_status: dict[int, str] = {}
        system_battery: str | None = None

        for event in self.__events:  # newest first
            zone = event["zone"]
            event_type = CID_EVENT_TYPES.get((event["qualifier"], event["code"]))
            if (
                event_type in ("system_battery_low", "system_battery_restore")
                and system_battery is None
            ):
                system_battery = event_type
            if zone == 0:
                continue
            if (
                event_type in ("rf_supervision_failure", "rf_supervision_restore")
                and zone not in rf_status
            ):
                rf_status[zone] = event_type
            if (
                event_type in ("low_battery", "battery_restore")
                and zone not in battery_status
            ):
                battery_status[zone] = event_type

        for zone, event_type in rf_status.items():
            if event_type == "rf_supervision_failure" and zone in enabled_zones:
                self._create_zone_issue("rf_supervision_failure", zone)

        for zone, event_type in battery_status.items():
            if event_type == "low_battery" and zone in enabled_zones:
                self._create_zone_issue("low_battery", zone)

        if system_battery == "system_battery_low":
            async_create_issue(
                self.hass,
                DOMAIN,
                "system_battery_low",
                is_fixable=False,
                severity=IssueSeverity.WARNING,
                translation_key="system_battery_low",
            )

    async def _sync_messages(self) -> None:
        """Fetch device name and zone labels from the panel."""
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
            self.__messages_last_sync = monotonic()
        except Exception:
            _LOGGER.warning("Failed to fetch device names, using defaults")

    async def _sync_events(self, status: Status | None = None) -> None:
        """Fetch event log and scan for unresolved issues."""
        try:
            self.__events = await self.client.fetch_events()
            if status is None:
                status = await self.client.status()
            enabled_zones = {
                i + 1 for i, z in enumerate(status["zones"]) if z["enabled"]
            }
            self._scan_unresolved_issues(enabled_zones)
        except Exception:
            _LOGGER.warning("Failed to fetch event log")

    async def _async_setup(self) -> None:
        await self._sync_messages()
        await self._sync_events()

    async def _async_update_data(self) -> Data:
        try:
            data = await self.client.status()
        except WrongPasswordError as ex:
            self.__last_failed = True
            raise ConfigEntryAuthFailed from ex
        except Exception as ex:
            self.__last_failed = True
            raise UpdateFailed("Erro ao atualizar os dados") from ex

        if self.__last_failed:
            self.__last_failed = False
            _LOGGER.info("Connection recovered, re-fetching events and messages")
            await self._sync_messages()
            await self._sync_events(data)
        elif monotonic() - self.__messages_last_sync > 1800:
            await self._sync_messages()

        for i, zone in enumerate(data["zones"]):
            zone_num = i + 1
            if zone["enabled"] and zone["low_battery"]:
                self._create_zone_issue("low_battery", zone_num)
            else:
                async_delete_issue(self.hass, DOMAIN, f"low_battery_{zone_num}")

        return {
            "status": data,
            "messages": self.__messages,
        }
