import asyncio

START_COMMAND = 0x94
MAC_COMMAND = 0xC4
VERSION_COMMAND = 0xC0
UNKNOWN_COMMAND = 0x80
PING_COMMAND = 0xF7
PUSH_COMMAND = 0xB4
OK = 0xFE
MY_HOME = 0xE9
ISEC = 0xE7
XOR_COMMAND = 0xFB
CONNECTION_COMMAND = 0xE5


class MyHomeCommands:
    ARM = (0x41, b"\x41")
    DISARM = (0x44, b"")
    PANIC_AUDIBLE = (0x45, b"\x01")
    PANIC_SILENT = (0x45, b"\x00")
    STATUS = (0x5A, b"")
    MESSAGES = (0xF1, b"")


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
        elif (
            command == MyHomeCommands.PANIC_AUDIBLE[0]
            and data == MyHomeCommands.PANIC_AUDIBLE[1]
        ):
            command = "PANIC_AUDIBLE"
        elif (
            command == MyHomeCommands.PANIC_SILENT[0]
            and data == MyHomeCommands.PANIC_SILENT[1]
        ):
            command = "PANIC_SILENT"
        elif command == MyHomeCommands.STATUS[0]:
            command = "STATUS"
        elif command == 0x00 and data[2] == MyHomeCommands.MESSAGES[0]:
            command = "MESSAGES"
            if data[5] == SYNC_NAME:
                command += " NAME"
            elif data[5] == SYNC_USER:
                command += " USER"
            elif data[5] == SYNC_ZONE:
                command += " ZONE"
        else:
            command = f"0x{command:02x}" + (f": {data.hex(':')}" if data else "")
        return f"CMD = {command}, PASSWORD = {password}"
    try:
        type, messages = parse_sync(data)
        if type == SYNC_NAME:
            sync = "NAME"
        elif type == SYNC_USER:
            sync = "USER"
        elif type == SYNC_ZONE:
            sync = "ZONE"
        return f"SYNC = {sync}, MESSAGES = {messages}"
    except:
        pass

    try:
        status = parse_status(data)
        return status
    except:
        pass

    return data.hex(":")


def command_to_str(command: int, data: bytes) -> str:
    if command == START_COMMAND:
        return "START"
    if command == MAC_COMMAND:
        return "MAC" + (f": {data.hex(':')}" if data else "")
    if command == VERSION_COMMAND:
        return "VERSION" + (f": {data.decode('ascii')}" if data else "")
    if command == UNKNOWN_COMMAND:
        return "UNKNOWN" + (f": {data.hex(':')}" if data else "")
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


def parse_status(data: bytes) -> dict:
    open_zones = int.from_bytes(data[:3], byteorder="little")
    violated_zones = int.from_bytes(data[6:9], byteorder="little")
    anulated_zones = int.from_bytes(data[12:15], byteorder="little")
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
                "anulated": bool(anulated_zones & (1 << i)),
                "stay": bool(stay_zones & (1 << i)),
                "enabled": bool(enabled_zones & (1 << i)),
                "low_battery": bool(low_battery & (1 << i)),
            }
            for i in range(24)
        ],
        "pgm": bool(data[37] & (1 << 7)),
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
        raise Exception("Invalid data")

    type = data[6]
    result = []
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


SYNC_NAME = 0x31
SYNC_USER = 0x32
SYNC_ZONE = 0x33


def sync_data(type: int, indexes: bytes = b"\x00") -> bytes:
    data = bytes(
        [
            # 0x00,
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


async def read_command(reader: asyncio.StreamReader):
    [length] = await reader.read(1)

    if length == PING_COMMAND:
        return PING_COMMAND, b""
    if length == OK:
        return OK, b""

    data = await reader.read(length)
    [checksum_] = await reader.read(1)
    if checksum_ != checksum(bytes([length, *data])):
        raise Exception("Invalid checksum")

    return data[0], data[1:]


async def send_command(
    writer: asyncio.StreamWriter, command: int, data: bytes = b"", key=None
):
    if command == PING_COMMAND or command == OK:
        data = bytes([command])
    else:
        data = create_command(command, data)

    if key:
        data = encrypt(data, key)

    writer.write(data)
    await writer.drain()


class ServidorAMT:
    def __init__(self, host, port, mac, pin):
        self.host = host
        self.port = port
        self.mac = bytes.fromhex(mac.replace(":", ""))
        self.pin = pin
        self._connection = None

    async def connect(self):
        self._connection = await asyncio.open_connection(self.host, self.port)

        # await send_command(self._connection[1], XOR_COMMAND)
        # key, _ = await read_command(self._connection[0])
        key = None

        data = connection_data(self.mac)
        await send_command(self._connection[1], CONNECTION_COMMAND, data, key)

        [result] = await self._connection[0].read(1)
        if result in (228, 253):
            raise Exception("Central não conectada")
        if result == 232:
            raise Exception("Outro dispositivo conectado")
        if result != 230:
            raise Exception("Erro")

        [result] = await self._connection[0].read(1)

    async def sync(self, type: int, indexes: bytes = bytes([0x00])) -> list[str]:
        await send_command(
            self._connection[1],
            MY_HOME,
            my_home_data(self.pin, 0x00, sync_data(type, indexes)),
        )
        _, data = await read_command(self._connection[0])
        return parse_sync(data)[1]

    async def status(self) -> dict:
        await send_command(
            self._connection[1],
            MY_HOME,
            my_home_data(self.pin, MyHomeCommands.STATUS[0]),
        )
        _, data = await read_command(self._connection[0])
        return parse_status(data)

    def disconnect(self):
        self._connection[1].close()
        self._connection = None
