"""Support for modified ANM 24 NET G2 firmware (auto-detected).

Attached to every entry. On stock firmware the panel never sends custom
frames, so nothing here ever activates and behavior stays stock.

Zone push (0xF3): the firmware sends the full MY_HOME status (53 bytes, RTC
zeroed) on every zone/status change plus a heartbeat. While those arrive,
each one is applied immediately and polling slows down; without them for a
while, stock polling resumes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from time import monotonic

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval

from .coordinator import DEFAULT_POLL, AMTCoordinator
from .protocol import READ_IDLE_TIMEOUT, parse_status

_LOGGER = logging.getLogger(__name__)

ZONE_PUSH = 0xF3

# Poll this slowly while pushes arrive (they carry every change).
SLOW_POLL = timedelta(seconds=30)
# Back to stock polling after this long without a push. The 1.0.7 firmware
# heartbeat is ~71 s (planned ~30 s), so keep this well above it.
PUSH_STALE = 180.0
# Read timeout while polling slowly (must exceed SLOW_POLL with margin).
SLOW_READ_IDLE_TIMEOUT = 90.0
CHECK_EVERY = timedelta(seconds=30)


@callback
def async_attach(
    hass: HomeAssistant, coordinator: AMTCoordinator
) -> Callable[[], None]:
    """Listen for custom-firmware frames; returns the detach callable."""
    client = coordinator.client
    last_push: float | None = None

    def set_slow(slow: bool) -> None:
        interval = SLOW_POLL if slow else DEFAULT_POLL
        if coordinator.update_interval != interval:
            _LOGGER.info(
                "%s zone pushes from the panel; polling every %s",
                "Receiving" if slow else "No recent",
                interval,
            )
            coordinator.update_interval = interval
        client.read_idle_timeout = SLOW_READ_IDLE_TIMEOUT if slow else READ_IDLE_TIMEOUT

    @callback
    def on_frame(command: int, data: bytes) -> None:
        nonlocal last_push
        if command != ZONE_PUSH:
            return
        # data is None until the first refresh (HA types it as always set).
        if coordinator.data is None:  # pyright: ignore[reportUnnecessaryComparison]
            return
        status = parse_status(data)
        status["upstream_push"] = coordinator.data["status"]["upstream_push"]
        last_push = monotonic()
        set_slow(True)
        coordinator.apply_status(status)

    @callback
    def check_stale(_now: datetime) -> None:
        if last_push is not None and monotonic() - last_push > PUSH_STALE:
            set_slow(False)

    client.custom_listeners.append(on_frame)
    cancel_check = async_track_time_interval(hass, check_stale, CHECK_EVERY)

    @callback
    def detach() -> None:
        if on_frame in client.custom_listeners:
            client.custom_listeners.remove(on_frame)
        cancel_check()
        set_slow(False)

    return detach
