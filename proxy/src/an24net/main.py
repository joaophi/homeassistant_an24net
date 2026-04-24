from asyncio import Queue, QueueFull, StreamReader, StreamWriter, Task, TaskGroup
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import logging
import signal
import sys
from typing import Optional

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
    command_to_str,
    read_command,
    send_command,
)


class Listenable[T]:
    def __init__(self) -> None:
        self._listeners: list[Queue[T]] = []

    def emit(self, data: T) -> None:
        for listener in self._listeners:
            try:
                listener.put_nowait(data)
            except QueueFull:
                pass

    def add_listener(self, queue: Optional[Queue[T]] = None) -> Queue[T]:
        queue = queue or Queue[T]()
        self._listeners.append(queue)
        return queue

    def remove_listener(self, queue: Queue[T]) -> None:
        self._listeners.remove(queue)

    def listeners(self) -> int:
        return len(self._listeners)

    @contextmanager
    def listener(self, queue: Optional[Queue[T]] = None):
        queue = self.add_listener(queue)
        try:
            yield queue
        finally:
            self.remove_listener(queue)


OPEN_CONNECTIONS: dict[bytes, tuple[StreamWriter, Listenable[tuple[int, bytes]]]] = {}


async def handle(
    _logger: logging.Logger,
    reader: StreamReader,
    writer: StreamWriter,
) -> None:
    _logger.info("New connection")

    async with TaskGroup() as tg:

        async def __downstream_client(data: bytes) -> None:
            logger = _logger.getChild("downstream_client")

            mac = data[9:15]
            logger.info(f"MAC: {mac.hex(':')}")

            alarm = OPEN_CONNECTIONS.get(mac, None)
            if not alarm:
                writer.write(b"\xe4")
                await writer.drain()
                return

            writer.write(b"\xe6\x0e")
            await writer.drain()

            async def __handle_push() -> None:
                with alarm[1].listener() as listener:
                    while True:
                        command, data = await listener.get()
                        if command == PUSH_COMMAND:
                            logger.info(f"sending {command_to_str(command, data)}")
                            await send_command(writer, PUSH_COMMAND, data)

            async def __handle_server() -> None:
                while True:
                    command, data = await read_command(reader)
                    logger.info(f"received: cmd=0x{command:02x} data={data.hex(':')}")

                    try:
                        with alarm[1].listener() as listener:
                            await send_command(alarm[0], command, data)
                            async with asyncio.timeout(5):
                                while True:
                                    command_, data = await listener.get()
                                    if command_ == command:
                                        response = data
                                        break
                    except TimeoutError:
                        logger.warning(
                            f"timeout waiting for response to cmd=0x{command:02x}"
                        )
                        continue
                    logger.info(
                        f"sending: cmd=0x{command:02x} data={response.hex(':')}"
                    )
                    await send_command(writer, command, response)

            async with asyncio.TaskGroup() as tg:
                tg.create_task(__handle_push())
                tg.create_task(__handle_server())

        async def __downstream_alarm() -> None:
            logger = _logger.getChild("downstream_alarm")

            logger.info("sending MAC REQUEST")
            await send_command(writer, MAC_COMMAND)
            command, mac = await read_command(reader)
            if command != MAC_COMMAND:
                raise Exception("Invalid data")
            logger.info(f"MAC: {mac.hex(':')}")

            logger.info("sending VERSION REQUEST")
            await send_command(writer, VERSION_COMMAND)
            command, version = await read_command(reader)
            if command != VERSION_COMMAND:
                raise Exception("Invalid data")
            logger.info(f"Version: {version}")

            receive = Listenable[tuple[int, bytes]]()
            OPEN_CONNECTIONS[mac] = (writer, receive)
            try:
                tg.create_task(__upstream(receive, mac, version))

                while True:
                    command, data = await read_command(reader)
                    logger.info(f"received: {command_to_str(command, data)}")
                    receive.emit((command, data))

                    if command == TIME_COMMAND:
                        tz = -data[0]
                        now = datetime.now(tz=timezone(timedelta(hours=tz)))
                        logger.info(f"sending TIME: {now}")
                        await send_command(
                            writer,
                            TIME_COMMAND,
                            bytes.fromhex(
                                f"{now.year - 2000:02} {now.month:02} {now.day:02} 04 {now.hour:02} {now.minute:02} {now.second:02}"
                            ),
                        )
                    else:
                        logger.info("sending OK")
                        await send_command(writer, OK)
            finally:
                OPEN_CONNECTIONS.pop(mac)

        async def __downstream() -> None:
            logger = _logger.getChild("downstream")

            while True:
                command, data = await read_command(reader)
                logger.info(f"received {command_to_str(command, data)}")

                if command == XOR_COMMAND:
                    logger.info("sending 0x00 - no encryption")
                    await send_command(writer, 0x00)
                elif command == START_COMMAND:
                    logger.info("sending OK")
                    await send_command(writer, OK)

                    return await __downstream_alarm()
                elif command == CONNECTION_COMMAND:
                    return await __downstream_client(data)
                else:
                    raise Exception("Invalid data")

        async def __upstream(
            receive: Listenable[tuple[int, bytes]],
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
                    logger.info("connected")

                    logger.info("sending START")
                    await send_command(
                        u_writer,
                        START_COMMAND,
                        b"\x45\x12\x12\x52\x57\x19",
                    )
                    command, _ = await read_command(u_reader)
                    if command != OK:
                        raise Exception("Invalid data")
                    logger.info("start ok received")

                    async def __ping() -> None:
                        while True:
                            await asyncio.sleep(30)
                            logger.info("sending PING")
                            await send_command(u_writer, PING_COMMAND)

                    async def __handle_push() -> None:
                        with receive.listener() as listener:
                            while True:
                                command, data = await listener.get()
                                if command == PUSH_COMMAND:
                                    logger.info(
                                        f"sending {command_to_str(command, data)}"
                                    )
                                    await send_command(u_writer, PUSH_COMMAND, data)

                    async def __handle_server() -> None:
                        while True:
                            command, data = await read_command(u_reader)
                            logger.info(
                                f"received cmd=0x{command:02x} data={data.hex(':')}"
                            )

                            if command == OK:
                                continue
                            elif command == MAC_COMMAND:
                                response = mac
                            elif command == VERSION_COMMAND:
                                response = version
                            else:
                                logger.info(
                                    f"sending to client cmd=0x{command:02x} data={data.hex(':')}"
                                )
                                try:
                                    with receive.listener() as listener:
                                        await send_command(writer, command, data)
                                        async with asyncio.timeout(5):
                                            while True:
                                                command_, data = await listener.get()
                                                if command_ == command:
                                                    response = data
                                                    break
                                except TimeoutError:
                                    logger.warning(
                                        f"timeout waiting for response to cmd=0x{command:02x}"
                                    )
                                    continue

                            logger.info(
                                f"sending cmd=0x{command:02x} data={response.hex(':')}"
                            )
                            await send_command(u_writer, command, response)

                    async with asyncio.TaskGroup() as tg:
                        tg.create_task(__handle_push())
                        tg.create_task(__handle_server())
                        tg.create_task(__ping())

                except Exception:
                    logger.exception("error")
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
        except Exception:
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
