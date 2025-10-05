"""The Alarme Intelbras integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from itertools import batched
from typing import TypedDict

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .protocol import SYNC_NAME, SYNC_ZONE, ClientAMT, Status

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

    async def _async_setup(self) -> None:
        [name] = await self.client.sync(SYNC_NAME)

        zones: list[str] = []
        for indexes in batched(range(24), n=8):
            data = await self.client.sync(SYNC_ZONE, bytes(indexes))
            zones.extend(data)

        self.__messages: Messages = {
            "name": name,
            "zones": zones,
        }

    async def _async_update_data(self) -> Data:
        try:
            data = await self.client.status()
        except Exception as ex:
            raise UpdateFailed("Erro ao atualizar os dados") from ex
        return {
            "status": data,
            "messages": self.__messages,
        }
