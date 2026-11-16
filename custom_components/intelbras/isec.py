"""Debug-log formatting for 0xE7 frames (used only for logging).

Splits the frame into header, length, command code and payload, and checks
the trailing checksum. Command codes are shown as hex.
"""

ACK = 0xF0FE
NACK = 0xF0FD

_NAMES: dict[int, str] = {
    ACK: "ACK",
    NACK: "NACK",
}


def _checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result ^ 0xFF


def isec_to_str(data: bytes) -> str:
    """Format the payload of a 0xE7 frame for logs.

    Layout: [4-byte header][len16 BE = payload+2][cmd16 BE][payload][checksum].
    Falls back to hex for anything that doesn't fit.
    """
    if len(data) < 9:
        return data.hex(":")
    length = (data[4] << 8) | data[5]
    if length < 2 or 6 + length + 1 > len(data):
        return data.hex(":")
    cmd = (data[6] << 8) | data[7]
    payload = data[8 : 6 + length]
    trailer = data[6 + length + 1 :]
    name = _NAMES.get(cmd, "cmd")
    parts = [f"{name}(0x{cmd:04x})"]
    if cmd == NACK and payload:
        parts.append(f"error=0x{payload[0]:02x}")
        payload = payload[1:]
    if payload:
        parts.append(payload.hex(":"))
    if data[0:4] != b"\x00\x00\x00\xf1":
        parts.append(f"hdr={data[0:4].hex(':')}")
    if _checksum(data[: 6 + length]) != data[6 + length]:
        parts.append("BAD-CKSUM")
    if trailer:
        parts.append(f"+{trailer.hex(':')}")
    return " ".join(parts)
