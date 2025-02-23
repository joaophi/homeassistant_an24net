"""The Alarme Intelbras integration."""

from __future__ import annotations

from datetime import timedelta
from itertools import batched
import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .protocol import SYNC_NAME, SYNC_ZONE, ClientAMT

_LOGGER = logging.getLogger(__name__)


class AMTCoordinator(DataUpdateCoordinator):
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
        self.__messages = {}

    async def _async_setup(self) -> None:
        [self.__messages["name"]] = await self.client.sync(SYNC_NAME)

        self.__messages["zones"] = []
        for indexes in batched(range(24), n=8):
            data = await self.client.sync(
                SYNC_ZONE,
                bytes(indexes),
            )
            self.__messages["zones"].extend(data)

    async def _async_update_data(self):
        try:
            data = await self.client.status()
        except Exception as ex:
            raise UpdateFailed("Erro ao atualizar os dados") from ex
        return {
            "status": data,
            "messages": self.__messages,
        }
