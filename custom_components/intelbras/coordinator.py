"""The Alarme Intelbras integration."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .protocol import SYNC_NAME, SYNC_USER, SYNC_ZONE, ServidorAMT

_LOGGER = logging.getLogger(__name__)


class AMTCoordinator(DataUpdateCoordinator):
    def __init__(
        self,
        hass: HomeAssistant,
        servidor: ServidorAMT,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="Alarme AMT",
            update_interval=timedelta(seconds=5),
            always_update=True,
        )
        self.servidor = servidor
        self.__messages = {}

    async def _async_setup(self) -> None:
        await self.servidor.connect()

        [self.__messages["name"]] = await self.servidor.sync(SYNC_NAME)

        self.__messages["zones"] = []
        for i in range(3):
            data = await self.servidor.sync(
                SYNC_ZONE,
                bytes(range(i * 8, (i * 8) + 8)),
            )
            self.__messages["zones"].extend(data)

        self.__messages["users"] = []
        for i in range(3):
            data = await self.servidor.sync(
                SYNC_USER,
                bytes(range(i * 10, (i * 10) + 10)),
            )
            self.__messages["users"].extend(data)

    async def _async_update_data(self):
        data = await self.servidor.status()
        return {
            "status": data,
            "messages": self.__messages,
        }
