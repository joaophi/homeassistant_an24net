"""The Alarme Intelbras integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from itertools import batched
from typing import TypedDict

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import SIGNAL_PUSH_EVENT
from .protocol import (
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

    @property
    def events(self) -> list[EventRecord]:
        """Events from the ring buffer, newest first."""
        return self.__events

    @callback
    def _handle_push(self, data: bytes) -> None:
        """Handle a PUSH_COMMAND from the alarm panel."""
        try:
            event = parse_push_event(data)
            async_dispatcher_send(self.hass, SIGNAL_PUSH_EVENT, event)
        except Exception:
            _LOGGER.warning("Failed to parse push event: %s", data.hex(":"))

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
        except Exception:
            _LOGGER.warning("Failed to fetch event log")

    async def _async_update_data(self) -> Data:
        try:
            data = await self.client.status()
        except Exception as ex:
            raise UpdateFailed("Erro ao atualizar os dados") from ex
        return {
            "status": data,
            "messages": self.__messages,
        }
