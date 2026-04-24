import asyncio
import contextlib
from collections.abc import Callable
from typing import TypedDict

START_COMMAND = 0x94
MAC_COMMAND = 0xC4
VERSION_COMMAND = 0xC0
TIME_COMMAND = 0x80
PING_COMMAND = 0xF7
PUSH_COMMAND = 0xB4
OK = 0xFE
MY_HOME = 0xE9
ISEC = 0xE7
XOR_COMMAND = 0xFB
CONNECTION_COMMAND = 0xE5


def panic(*, audible: bool) -> bytes:
    return b"\x01" if audible else b"\x00"


def pgm(*, on: bool) -> bytes:
    return b"\x4c\x31" if on else b"\x44\x31"


class MyHomeCommands:
    ARM = (0x41, lambda: b"\x41")
    BYPASS = (0x42, bytes)
    DISARM = (0x44, bytes)
    PANIC = (0x45, panic)
    STATUS = (0x5A, bytes)
    MESSAGES = (0xF1, bytes)
    PGM = (0x50, pgm)


def my_home_to_str(data: bytes) -> str:
    if data[0] == OK:
        return "OK"
    if data[0] == 0x21 and data[-1] == 0x21:
        password = data[1:5].decode("ascii")
        command = data[5]
        data = data[6:-1]
        if command == MyHomeCommands.ARM[0]:
            command = "ARM"
        elif command == MyHomeCommands.DISARM[0]:
            command = "DISARM"
        elif command == MyHomeCommands.PANIC[0] and data == MyHomeCommands.PANIC[1](
            audible=True
        ):
            command = "PANIC_AUDIBLE"
        elif command == MyHomeCommands.PANIC[0] and data == MyHomeCommands.PANIC[1](
            audible=False
        ):
            command = "PANIC_SILENT"
        elif command == MyHomeCommands.STATUS[0]:
            command = "STATUS"
        elif command == 0x00 and data[2] == MyHomeCommands.MESSAGES[0]:
            command = "MESSAGES"
            if data[5] == SYNC_EVENT:
                command += " EVENT"
            elif data[5] == SYNC_NAME:
                command += " NAME"
            elif data[5] == SYNC_USER:
                command += " USER"
            elif data[5] == SYNC_ZONE:
                command += " ZONE"
            else:
                command += f" 0x{data[5]:02x}"
        else:
            command = f"0x{command:02x}" + (f": {data.hex(':')}" if data else "")
        return f"CMD = {command}, PASSWORD = {password}"
    try:
        type, messages = parse_sync(data)
        if type == SYNC_EVENT:
            sync = "EVENT"
        elif type == SYNC_NAME:
            sync = "NAME"
        elif type == SYNC_USER:
            sync = "USER"
        elif type == SYNC_ZONE:
            sync = "ZONE"
        else:
            sync = f"0x{type:02x}"
        return f"SYNC = {sync}, MESSAGES = {messages}"
    except Exception:
        pass

    try:
        status = parse_status(data)
        return str(status)
    except Exception:
        pass

    return data.hex(":")


def command_to_str(command: int, data: bytes) -> str:
    if command == START_COMMAND:
        return "START"
    if command == MAC_COMMAND:
        return "MAC" + (f": {data.hex(':')}" if data else "")
    if command == VERSION_COMMAND:
        return "VERSION" + (f": {data.decode('ascii')}" if data else "")
    if command == TIME_COMMAND:
        return "TIME" + (f": tz={-data[0]}" if data else "")
    if command == PING_COMMAND:
        return "PING"
    if command == PUSH_COMMAND:
        return "PUSH" + (f": {data.hex(':')}" if data else "")
    if command == OK:
        return "OK"
    if command == ISEC:
        return "ISEC" + (f": {data.hex(':')}" if data else "")
    if command == MY_HOME:
        return "MY_HOME" + (f": {my_home_to_str(data)}" if data else "")
    return f"0x{command:02x}" + (f": {data.hex(':')}" if data else "")


def create_command(command: int, data: bytes = b"") -> bytes:
    data = bytes([len(data) + 1, command, *data])
    return bytes([*data, checksum(data)])


def connection_data(mac: bytes) -> bytes:
    uuid = b""
    token = b""
    return bytes(
        [
            0x06,
            *uuid.zfill(8),
            *mac,
            checksum(token),
            0x45,
            *[0x00 for _ in range(4)],
            0x03,
            0x00,  # LANGUAGE,
            *token,
        ]
    )


def encrypt(data: bytes, key: int) -> bytes:
    return bytes([x ^ key for x in data])


class BatteryStatus(TypedDict):
    envoltorio: bool
    primeiroNivel: bool
    segundoNivel: bool
    terceiroNivel: bool
    envoltorioPisc: bool


class ZoneStatus(TypedDict):
    open: bool
    violated: bool
    annulled: bool
    stay: bool
    enabled: bool
    low_battery: bool


class Status(TypedDict):
    version: int
    partitionedPanel: bool
    partitionAArmed: bool
    partitionBArmed: bool
    sirenTriggered: bool
    battery: BatteryStatus
    zones: list[ZoneStatus]
    pgm: bool
    no_energy: bool


def parse_status(data: bytes) -> Status:
    open_zones = int.from_bytes(data[:3], byteorder="little")
    violated_zones = int.from_bytes(data[6:9], byteorder="little")
    annulled_zones = int.from_bytes(data[12:15], byteorder="little")
    stay_zones = int.from_bytes(data[50:53], byteorder="little")
    enabled_zones = int.from_bytes(data[47:50], byteorder="little")
    low_battery = int.from_bytes(data[38:41], byteorder="little")

    return {
        "version": int(data[19]),
        "partitionedPanel": bool(data[20] & (1 << 0)),
        "partitionAArmed": bool(data[21] & (1 << 0)),
        "partitionBArmed": bool(data[21] & (1 << 1)),
        "sirenTriggered": bool(data[37] & (1 << 2)),
        "battery": {
            "envoltorio": bool(data[30] & (1 << 0)),
            "primeiroNivel": bool(data[30] & (1 << 1)),
            "segundoNivel": bool(data[30] & (1 << 2)),
            "terceiroNivel": bool(data[30] & (1 << 3)),
            "envoltorioPisc": bool(data[30] & (1 << 4)),
        },
        "zones": [
            {
                "open": bool(open_zones & (1 << i)),
                "violated": bool(violated_zones & (1 << i)),
                "annulled": bool(annulled_zones & (1 << i)),
                "stay": bool(stay_zones & (1 << i)),
                "enabled": bool(enabled_zones & (1 << i)),
                "low_battery": bool(low_battery & (1 << i)),
            }
            for i in range(24)
        ],
        "pgm": bool(data[37] & (1 << 6)),
        "no_energy": bool(data[28] & (1 << 0)),
    }


CHAR_MAP = {
    126: 226,
    127: 227,
    128: 225,
    129: 224,
    130: 234,
    131: 233,
    132: 237,
    133: 244,
    134: 243,
    135: 245,
    136: 250,
    137: 252,
    138: 231,
    139: 193,
    140: 192,
    141: 195,
    142: 194,
    143: 201,
    144: 202,
    145: 205,
    146: 211,
    147: 212,
    148: 213,
    149: 218,
    150: 220,
    151: 199,
    158: 176,
    159: 185,
    160: 178,
    161: 179,
}


def parse_char(char: int) -> str:
    return chr(CHAR_MAP.get(char, char))


def parse_sync(data: bytes) -> tuple[int, list[str]]:
    if data[1] != MyHomeCommands.MESSAGES[0] or data[7] != 0xE0:
        raise ValueError("Invalid sync data")
    type = data[6]
    result: list[str] = []
    buffer = ""
    idx = 9
    while idx < len(data):
        if data[idx] == 0x00 or len(buffer) >= 14:
            result.append(buffer.strip())
            buffer = ""
        else:
            buffer += parse_char(data[idx])
        idx += 1

    if buffer:
        result.append(buffer[:-1].strip())

    return type, result


def my_home_data(password: str, command: int, data: bytes = b"") -> bytes:
    return bytes([0x21, *map(ord, password), command, *data, 0x21])


def null_zone_data(zones: list[int]) -> bytes:
    data = [0] * 3
    for i in zones:
        x = i - 1
        data[x // 8] |= 1 << (x % 8)
    return bytes(data)


SYNC_EVENT = 0x30
SYNC_NAME = 0x31
SYNC_USER = 0x32
SYNC_ZONE = 0x33


def bcd(b: int) -> int:
    """Decode BCD byte."""
    return (b >> 4) * 10 + (b & 0x0F)


def cid_decode(b8: int, b9: int) -> tuple[int, int]:
    """Decode Contact ID qualifier and event code.

    Returns (qualifier, code). qualifier: 1=event/trouble, 3=restore.
    """
    q = b8 >> 4
    d1 = b8 & 0x0F
    d2 = (b9 >> 4) if (b9 >> 4) != 0xA else 0
    d3 = (b9 & 0x0F) if (b9 & 0x0F) != 0xA else 0
    return q, d1 * 100 + d2 * 10 + d3


CID_EVENT_TYPES: dict[tuple[int, int], str] = {
    (1, 130): "burglary",
    (3, 130): "burglary_restore",
    (1, 147): "rf_supervision_failure",
    (3, 147): "rf_supervision_restore",
    (1, 301): "power_failure",
    (3, 301): "power_restore",
    (1, 302): "system_battery_low",
    (3, 302): "system_battery_restore",
    (1, 384): "low_battery",
    (3, 384): "battery_restore",
    (1, 401): "disarm",
    (3, 401): "arm",
}

ZONE_EVENT_TYPES = [
    "burglary",
    "burglary_restore",
    "rf_supervision_failure",
    "rf_supervision_restore",
    "low_battery",
    "battery_restore",
]

SYSTEM_EVENT_TYPES = [
    "power_failure",
    "power_restore",
    "system_battery_low",
    "system_battery_restore",
    "arm",
    "disarm",
]


class EventRecord(TypedDict):
    timestamp: str
    qualifier: int
    code: int
    zone: int
    ring_index: int


def parse_event_record(rec: bytes) -> EventRecord:
    """Parse a 15-byte event record from the ring buffer."""
    q, code = cid_decode(rec[8], rec[9])
    return {
        "timestamp": (
            f"20{bcd(rec[2]):02d}-{bcd(rec[3]):02d}-{bcd(rec[4]):02d}"
            f"T{bcd(rec[5]):02d}:{bcd(rec[6]):02d}:{bcd(rec[7]):02d}"
        ),
        "qualifier": q,
        "code": code,
        "zone": rec[12] if rec[12] != 0x0A else 0,
        "ring_index": rec[1],
    }


def parse_push_event(data: bytes) -> EventRecord:
    """Parse a PUSH_COMMAND (0xB4) payload.

    Format: [header] [account*4] [msg_type*2] [qualifier] [code*3]
            [group*2] [zone*3] [timestamp*6] [timestamp*6]
    Each CID field is one byte per digit (0x0A = 0).
    Timestamp is plain integers: day, month, year, hour, minute, second.
    """
    qualifier = data[7]
    d1 = data[8]
    d2 = data[9] if data[9] != 0x0A else 0
    d3 = data[10] if data[10] != 0x0A else 0
    code = d1 * 100 + d2 * 10 + d3

    z1 = data[13] if data[13] != 0x0A else 0
    z2 = data[14] if data[14] != 0x0A else 0
    z3 = data[15] if data[15] != 0x0A else 0
    zone = z1 * 100 + z2 * 10 + z3

    day, month, year = data[16], data[17], data[18]
    hour, minute, second = data[19], data[20], data[21]

    return {
        "timestamp": f"20{year:02d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}",
        "qualifier": qualifier,
        "code": code,
        "zone": zone,
        "ring_index": -1,
    }


def sync_data(type: int, indexes: bytes = b"\x00") -> bytes:
    data = bytes(
        [
            0x00,
            0x00,
            MyHomeCommands.MESSAGES[0],  # COMANDO_MENSAGENS
            0x00,
            len(indexes) + 2,
            type,
            0xE0,
            *indexes,
        ]
    )
    return bytes([*data, checksum(data)])


def checksum(data: bytes) -> int:
    i = 0
    for x in data:
        i ^= x
    return i ^ 255


class ChecksumError(Exception):
    def __init__(self, data: bytes, expected: int) -> None:
        self.data = data
        self.checksum = expected
        super().__init__(f"Invalid checksum: {data.hex(':')} != {expected:02x}")


async def read_command(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    [length] = await reader.readexactly(1)

    if length == PING_COMMAND:
        return PING_COMMAND, b""
    if length == OK:
        return OK, b""

    data = await reader.readexactly(length)
    [checksum_] = await reader.readexactly(1)
    if checksum_ != checksum(bytes([length, *data])):
        if data[0] == MY_HOME and data[1] == 0x00:
            return data[0], bytes([*data[1:], checksum_])
        raise ChecksumError(bytes([length, *data]), checksum_)

    return data[0], data[1:]


async def send_command(
    writer: asyncio.StreamWriter,
    command: int,
    data: bytes = b"",
    key: int | None = None,
):
    if command in (PING_COMMAND, OK):
        data = bytes([command])
    else:
        data = create_command(command, data)

    if key:
        data = encrypt(data, key)

    writer.write(data)
    await writer.drain()


class OpenZoneError(Exception): ...


class WrongPasswordError(Exception): ...


class ClientAMT:
    def __init__(self, host: str, port: int, mac: str, pin: str) -> None:
        self.host = host
        self.port = port
        self.mac = bytes.fromhex(mac.replace(":", ""))
        self.pin = pin
        self._send = asyncio.Queue[tuple[int, bytes, asyncio.Future[None]]]()
        self._receive: list[asyncio.Queue[tuple[int, bytes]]] = []
        self._status = None
        self._request_lock = asyncio.Lock()
        # Called when PUSH_COMMAND (0xB4) is received from the panel.
        # Set by the coordinator to parse Contact ID events and dispatch them.
        self.on_push: Callable[[bytes], None] | None = None

    async def run(self) -> None:
        async def read(reader: asyncio.StreamReader) -> None:
            while True:
                command, data = await read_command(reader)
                if command == PUSH_COMMAND and self.on_push is not None:
                    self.on_push(data)
                for queue in self._receive:
                    with contextlib.suppress(asyncio.QueueFull):
                        queue.put_nowait((command, data))

        async def write(writer: asyncio.StreamWriter) -> None:
            while True:
                command, data, future = await self._send.get()
                try:
                    await send_command(writer, command, data)
                    future.set_result(None)
                except Exception as ex:
                    future.set_exception(ex)
                    raise

        while True:
            writer: asyncio.StreamWriter | None = None
            try:
                async with asyncio.timeout(10):
                    reader, writer = await asyncio.open_connection(self.host, self.port)

                    await send_command(writer, XOR_COMMAND)
                    key, _ = await read_command(reader)

                    data = connection_data(self.mac)
                    await send_command(writer, CONNECTION_COMMAND, data, key)

                    [result] = await reader.readexactly(1)
                    if result in (228, 253):
                        raise Exception("Central não conectada")
                    if result == 232:
                        raise Exception("Outro dispositivo conectado")
                    if result != 230:
                        raise Exception("Erro")

                    _ = await reader.readexactly(1)

                async with asyncio.TaskGroup() as tg:
                    tg.create_task(read(reader))
                    tg.create_task(write(writer))
            except Exception as ex:
                if writer is not None:
                    writer.close()
                while not self._send.empty():
                    _, _, future = self._send.get_nowait()
                    future.set_exception(ex)
            await asyncio.sleep(5)

    async def _request(self, command: int, data: bytes = b"") -> bytes:
        async with self._request_lock:
            queue = asyncio.Queue[tuple[int, bytes]](maxsize=16)
            self._receive.append(queue)
            try:
                future = asyncio.Future[None]()
                self._send.put_nowait(
                    (
                        command,
                        data,
                        future,
                    )
                )
                async with asyncio.timeout(10):
                    await future
                    while True:
                        _command, _data = await queue.get()
                        if _command == command:
                            return _data
            finally:
                self._receive.remove(queue)

    async def arm(self, password: str, *, stay: bool = False) -> None:
        data = await self._request(
            MY_HOME,
            my_home_data(password, MyHomeCommands.ARM[0], MyHomeCommands.ARM[1]()),
        )
        if data == b"\xe1":
            raise WrongPasswordError
        if data == b"\xe4":
            raise OpenZoneError

    async def disarm(self, password: str) -> None:
        data = await self._request(
            MY_HOME,
            my_home_data(
                password, MyHomeCommands.DISARM[0], MyHomeCommands.DISARM[1]()
            ),
        )
        if data == b"\xe1":
            raise WrongPasswordError

    async def panic(self, password: str, *, silent: bool = False) -> None:
        data = await self._request(
            MY_HOME,
            my_home_data(
                password,
                MyHomeCommands.PANIC[0],
                MyHomeCommands.PANIC[1](audible=not silent),
            ),
        )
        if data == b"\xe1":
            raise WrongPasswordError

    async def pgm(self, *, on: bool = True) -> None:
        await self._request(
            MY_HOME,
            my_home_data(self.pin, MyHomeCommands.PGM[0], MyHomeCommands.PGM[1](on=on)),
        )

    async def bypass(self, zones: list[int]) -> None:
        await self._request(
            MY_HOME,
            my_home_data(self.pin, MyHomeCommands.BYPASS[0], null_zone_data(zones)),
        )

    async def sync(self, type: int, indexes: bytes = bytes([0x00])) -> list[str]:
        data = await self._request(
            MY_HOME, my_home_data(self.pin, 0x00, sync_data(type, indexes))
        )
        return parse_sync(data)[1]

    async def status(self) -> Status:
        data = await self._request(
            MY_HOME,
            my_home_data(
                self.pin, MyHomeCommands.STATUS[0], MyHomeCommands.STATUS[1]()
            ),
        )
        return parse_status(data)

    async def get_event_cursor(self) -> tuple[int, int]:
        """Get event log cursor. Returns (pointer, total_count)."""
        payload = bytes([0x00, 0x00, 0xF1, 0x00, 0x03, 0x30, 0x03, 0x00])
        payload = bytes([*payload, checksum(payload)])
        data = await self._request(
            MY_HOME, my_home_data(self.pin, 0x00, payload)
        )
        pointer = data[9]
        total = data[9] * 256 + data[10]
        return pointer, total

    async def fetch_events(self) -> list[EventRecord]:
        """Fetch all events from the ring buffer (newest first)."""
        pointer, total = await self.get_event_cursor()
        count = min(total, 128)
        if count == 0:
            return []

        indices: list[int] = []
        pos = (pointer - 1) % 128
        for _ in range(count):
            indices.append(pos)
            pos = (pos - 1) % 128

        events: list[EventRecord] = []
        for batch_start in range(0, len(indices), 10):
            batch = indices[batch_start : batch_start + 10]
            index_bytes: list[int] = []
            for idx in batch:
                index_bytes.extend([0x00, idx])
            payload = bytes([
                0x00, 0x00, 0xF1, 0x00,
                len(index_bytes) + 2, 0x39, 0x00,
                *index_bytes,
            ])
            payload = bytes([*payload, checksum(payload)])

            data = await self._request(
                MY_HOME, my_home_data(self.pin, 0x00, payload)
            )

            if len(data) > 6 and data[6] == 0xF0:
                continue

            event_data = data[8:]
            for i in range(len(batch)):
                offset = i * 15
                if offset + 15 > len(event_data):
                    break
                events.append(parse_event_record(event_data[offset : offset + 15]))

        return events
