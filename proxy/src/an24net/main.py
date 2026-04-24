from asyncio import StreamReader, StreamWriter, Task, TaskGroup
import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from itertools import count
import logging
import signal
import sys

from an24net.protocol import (
    START_COMMAND,
    MAC_COMMAND,
    VERSION_COMMAND,
    TIME_COMMAND,
    PING_COMMAND,
    PUSH_COMMAND,
    OK,
    XOR_COMMAND,
    CONNECTION_COMMAND,
    CONN_NOT_FOUND,
    CONN_SUCCESS,
    command_to_str,
    frame_hex,
    read_command,
    send_command,
)


class AlarmConnection:
    def __init__(self, writer: StreamWriter) -> None:
        self.writer = writer
        self.on_push: list[Callable[[tuple[int, bytes]], None]] = []
        self._lock = asyncio.Lock()
        self._pending: asyncio.Future[tuple[int, bytes]] | None = None

    async def request(self, command: int, data: bytes) -> tuple[int, bytes]:
        """Send a command to the alarm and wait for its response.

        Serialized by lock so only one command is in-flight at a time.
        """
        async with self._lock:
            self._pending = asyncio.Future[tuple[int, bytes]]()
            try:
                await send_command(self.writer, command, data)
                async with asyncio.timeout(5):
                    return await self._pending
            finally:
                self._pending = None

    def resolve(self, command: int, data: bytes) -> bool:
        """Route a response from the alarm to the pending requester."""
        if self._pending is not None and not self._pending.done():
            self._pending.set_result((command, data))
            return True
        return False


OPEN_CONNECTIONS: dict[bytes, AlarmConnection] = {}
_conn_ids = count(1)


async def handle(
    _logger: logging.Logger,
    reader: StreamReader,
    writer: StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    addr = f"{peer[0]}:{peer[1]}" if peer else "unknown"
    _logger = _logger.getChild(f"conn{next(_conn_ids)}")
    _logger.info(f"new connection from {addr}")

    async with TaskGroup() as tg:

        async def __downstream_client(data: bytes) -> None:
            mac = data[9:15]
            logger = _logger.getChild(f"client[{mac.hex(':')}]")
            alarm = OPEN_CONNECTIONS.get(mac, None)
            if not alarm:
                logger.warning("alarm not connected, rejecting")
                writer.write(bytes([CONN_NOT_FOUND]))
                await writer.drain()
                return

            logger.info("connected")
            writer.write(bytes([CONN_SUCCESS, 0x0E]))
            await writer.drain()

            push_queue = asyncio.Queue[tuple[int, bytes]]()
            cb = push_queue.put_nowait
            alarm.on_push.append(cb)

            try:

                async def __handle_push() -> None:
                    while True:
                        _, data = await push_queue.get()
                        logger.info(
                            f"→ {command_to_str(PUSH_COMMAND, data)} | {frame_hex(PUSH_COMMAND, data)}"
                        )
                        await send_command(writer, PUSH_COMMAND, data)

                async def __handle_server() -> None:
                    while True:
                        command, data = await read_command(reader)
                        logger.info(
                            f"← {command_to_str(command, data)} | {frame_hex(command, data)}"
                        )

                        try:
                            _, response = await alarm.request(command, data)
                        except TimeoutError:
                            logger.warning(
                                f"timeout waiting for alarm response to {command_to_str(command, data)}"
                            )
                            continue
                        logger.info(
                            f"→ {command_to_str(command, response)} | {frame_hex(command, response)}"
                        )
                        await send_command(writer, command, response)

                async with asyncio.TaskGroup() as tg:
                    tg.create_task(__handle_push())
                    tg.create_task(__handle_server())
            finally:
                alarm.on_push.remove(cb)

        async def __downstream_alarm() -> None:
            logger = _logger.getChild("alarm")

            logger.info(f"→ MAC | {frame_hex(MAC_COMMAND, b'')}")
            await send_command(writer, MAC_COMMAND)
            command, mac = await read_command(reader)
            if command != MAC_COMMAND:
                raise Exception("Invalid data")
            logger.info(f"← MAC: {mac.hex(':')} | {frame_hex(MAC_COMMAND, mac)}")

            logger.info(f"→ VERSION | {frame_hex(VERSION_COMMAND, b'')}")
            await send_command(writer, VERSION_COMMAND)
            command, version = await read_command(reader)
            if command != VERSION_COMMAND:
                raise Exception("Invalid data")
            logger.info(
                f"← VERSION: {version.decode('ascii', errors='replace')} | {frame_hex(VERSION_COMMAND, version)}"
            )

            alarm = AlarmConnection(writer)
            OPEN_CONNECTIONS[mac] = alarm
            try:
                tg.create_task(__upstream(alarm, mac, version))

                while True:
                    command, data = await read_command(reader)
                    logger.info(
                        f"← {command_to_str(command, data)} | {frame_hex(command, data)}"
                    )

                    if command == PUSH_COMMAND:
                        for cb in alarm.on_push:
                            cb((command, data))
                        await send_command(writer, OK)
                    elif command == TIME_COMMAND:
                        tz = -data[0]
                        now = datetime.now(tz=timezone(timedelta(hours=tz)))
                        time_data = bytes.fromhex(
                            f"{now.year - 2000:02} {now.month:02} {now.day:02} 04 {now.hour:02} {now.minute:02} {now.second:02}"
                        )
                        logger.info(
                            f"→ TIME: {now} | {frame_hex(TIME_COMMAND, time_data)}"
                        )
                        await send_command(writer, TIME_COMMAND, time_data)
                    elif command == PING_COMMAND:
                        await send_command(writer, OK)
                    elif alarm.resolve(command, data):
                        await send_command(writer, OK)
                    else:
                        logger.info("→ OK | fe")
                        await send_command(writer, OK)
            finally:
                OPEN_CONNECTIONS.pop(mac)

        async def __downstream() -> None:
            while True:
                command, data = await read_command(reader)
                _logger.info(
                    f"← {command_to_str(command, data)} | {frame_hex(command, data)}"
                )

                if command == XOR_COMMAND:
                    _logger.info(f"→ 0x00 (no encryption) | {frame_hex(0x00, b'')}")
                    await send_command(writer, 0x00)
                elif command == START_COMMAND:
                    _logger.info("→ OK | fe")
                    await send_command(writer, OK)
                    return await __downstream_alarm()
                elif command == CONNECTION_COMMAND:
                    return await __downstream_client(data)
                else:
                    raise Exception("Invalid data")

        async def __upstream(
            alarm: AlarmConnection,
            mac: bytes,
            version: bytes,
        ) -> None:
            logger = _logger.getChild("upstream")

            while True:
                try:
                    u_reader, u_writer = await asyncio.open_connection(
                        host="amt.intelbras.com.br",
                        port=9009,
                    )
                    logger.info("connected to amt.intelbras.com.br:9009")

                    start_data = b"\x45\x12\x12\x52\x57\x19"
                    logger.info(
                        f"→ {command_to_str(START_COMMAND, start_data)} | {frame_hex(START_COMMAND, start_data)}"
                    )
                    await send_command(u_writer, START_COMMAND, start_data)
                    command, _ = await read_command(u_reader)
                    if command != OK:
                        raise Exception("Invalid data")
                    logger.info("← OK | fe")

                    async def __ping() -> None:
                        while True:
                            await asyncio.sleep(30)
                            logger.info(f"→ PING | {frame_hex(PING_COMMAND, b'')}")
                            await send_command(u_writer, PING_COMMAND)

                    push_queue = asyncio.Queue[tuple[int, bytes]]()
                    cb = push_queue.put_nowait
                    alarm.on_push.append(cb)

                    async def __handle_push() -> None:
                        try:
                            while True:
                                _, data = await push_queue.get()
                                logger.info(
                                    f"→ {command_to_str(PUSH_COMMAND, data)} | {frame_hex(PUSH_COMMAND, data)}"
                                )
                                await send_command(u_writer, PUSH_COMMAND, data)
                        finally:
                            alarm.on_push.remove(cb)

                    async def __handle_server() -> None:
                        while True:
                            command, data = await read_command(u_reader)
                            logger.info(
                                f"← {command_to_str(command, data)} | {frame_hex(command, data)}"
                            )

                            if command == OK:
                                continue
                            elif command == MAC_COMMAND:
                                response = mac
                            elif command == VERSION_COMMAND:
                                response = version
                            else:
                                logger.info(
                                    f"↓ relay to alarm: {command_to_str(command, data)}"
                                )
                                try:
                                    _, response = await alarm.request(command, data)
                                except TimeoutError:
                                    logger.warning(
                                        f"timeout waiting for alarm response to {command_to_str(command, data)}"
                                    )
                                    continue

                            logger.info(
                                f"→ {command_to_str(command, response)} | {frame_hex(command, response)}"
                            )
                            await send_command(u_writer, command, response)

                    async with asyncio.TaskGroup() as tg:
                        tg.create_task(__handle_push())
                        tg.create_task(__handle_server())
                        tg.create_task(__ping())

                except Exception:
                    logger.exception("upstream connection error")
                    await asyncio.sleep(5)

        tg.create_task(__downstream())


async def main() -> None:
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s: %(message)s")

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    tasks: set[Task[None]] = set()

    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    if task:
        tasks.add(task)

    def cancel() -> None:
        for task in tasks:
            task.cancel()

    loop.add_signal_handler(signal.SIGINT, cancel)
    loop.add_signal_handler(signal.SIGTERM, cancel)

    async def handler(reader: StreamReader, writer: StreamWriter) -> None:
        task = asyncio.current_task()
        if task:
            tasks.add(task)
        try:
            await handle(logger, reader, writer)
        except* (
            asyncio.IncompleteReadError,
            ConnectionResetError,
            BrokenPipeError,
            ConnectionError,
        ):
            logger.info("connection closed")
        except* Exception:
            logger.exception("connection error")
        finally:
            writer.close()
            if task:
                tasks.discard(task)

    logger.info("Serving on 0.0.0.0:9009")
    server = await asyncio.start_server(handler, "0.0.0.0", 9009)
    await server.serve_forever()


def run() -> None:
    asyncio.run(main())
