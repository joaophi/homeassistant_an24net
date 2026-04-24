# AMT Protocol - Intelbras AN-24 Net

## Overview

The Intelbras AN-24 Net alarm panel communicates over TCP (default port 9009) using a custom binary protocol. All commands use a simple framing format with XOR checksums.

## Frame Format

```
[length] [command] [payload...] [checksum]
```

- **length**: 1 byte, number of bytes in command + payload (excludes itself and checksum)
- **command**: 1 byte command code
- **payload**: variable length
- **checksum**: 1 byte, XOR of all preceding bytes (length + command + payload) XOR 0xFF

Special single-byte commands (no framing): PING (0xF7), OK (0xFE).

```python
def checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result ^ 0xFF
```

## Connection Handshake

1. Client sends `XOR_COMMAND (0xFB)`
2. Server responds with encryption key (0x00 = no encryption)
3. Client sends `CONNECTION_COMMAND (0xE5)` with MAC address in connection data (encrypted with key if non-zero)
4. Server responds: `0xE6 0x0E` (success), `0xE4` (alarm not found), `0xE8` (other device connected)

## Command Codes

| Code | Name | Description |
|------|------|-------------|
| 0x94 | START | Alarm panel identification |
| 0xC4 | MAC | Query/return MAC address |
| 0xC0 | VERSION | Query/return firmware version |
| 0x80 | TIME | Time sync with timezone |
| 0xF7 | PING | Keep-alive (single byte, no framing) |
| 0xB4 | PUSH | Event push from panel |
| 0xFE | OK | Acknowledgment (single byte) |
| 0xE9 | MY_HOME | Main command for all alarm operations |
| 0xE7 | ISEC | ISEC protocol |
| 0xFB | XOR | Encryption key negotiation |
| 0xE5 | CONNECTION | Client connection with MAC |

## MY_HOME Command (0xE9)

All alarm operations (arm, disarm, status, events, sync) are wrapped in MY_HOME commands.

### Password-framed requests

Sent by clients with authentication:
```
[0x21] [password: 4 ASCII bytes] [inner_command] [inner_data...] [0x21]
```

### Inner commands

| Inner cmd | Name | Data |
|-----------|------|------|
| 0x41 | ARM | `0x41` |
| 0x42 | BYPASS | zone bitmask (3 bytes, little-endian) |
| 0x44 | DISARM | (empty) |
| 0x45 | PANIC | `0x01` (audible) or `0x00` (silent) |
| 0x50 | PGM | `0x4C 0x31` (on) or `0x44 0x31` (off) |
| 0x5A | STATUS | (empty) |
| 0x00 | MESSAGES | sync/event data (see below) |

### Error responses

- `0xE1` = wrong password
- `0xE4` = open zone (cannot arm)

## Status Response

54 bytes of binary data:

| Offset | Size | Description |
|--------|------|-------------|
| 0-2 | 3 | Open zones (24-bit little-endian bitmask) |
| 6-8 | 3 | Violated zones |
| 12-14 | 3 | Annulled zones |
| 19 | 1 | Version |
| 20 | 1 | Partitioned panel (bit 0) |
| 21 | 1 | Partition A armed (bit 0), Partition B armed (bit 1) |
| 28 | 1 | No energy (bit 0) |
| 30 | 1 | Battery: envoltório (bit 0), 1° nível (1), 2° nível (2), 3° nível (3), envoltório pisc (4) |
| 37 | 1 | Siren triggered (bit 2), PGM (bit 6) |
| 38-40 | 3 | Low battery zones |
| 47-49 | 3 | Enabled zones |
| 50-52 | 3 | Stay zones |

Each zone bitmask: bit N = zone N+1 (0-indexed, 24 zones max).

## MESSAGES Command (inner command 0x00)

Used for sync (names, zones) and event log. The payload varies by type.

### Sync format (NAME/ZONE/USER)

Request payload inside `my_home_data(pin, 0x00, ...)`:
```
[0x00, 0x00, 0xF1, 0x00, len(indexes)+2, type, 0xE0, *indexes, checksum]
```

| Type | Constant | Description |
|------|----------|-------------|
| 0x31 | SYNC_NAME | Device name |
| 0x32 | SYNC_USER | User names |
| 0x33 | SYNC_ZONE | Zone names |

- Indexes: 1 byte per item (e.g. `bytes(range(8))` for zones 0-7)
- Response: text strings, 14 chars max each, using custom character map for Portuguese accents

### Character map (Portuguese)

Custom byte → Unicode mapping for accented characters:

| Byte | Char | Byte | Char |
|------|------|------|------|
| 126 | â | 139 | Á |
| 127 | ã | 140 | À |
| 128 | á | 141 | Ã |
| 129 | à | 142 | Â |
| 130 | ê | 143 | É |
| 131 | é | 144 | Ê |
| 132 | í | 145 | Í |
| 133 | ô | 146 | Ó |
| 134 | ó | 147 | Ô |
| 135 | õ | 148 | Õ |
| 136 | ú | 149 | Ú |
| 137 | ü | 150 | Ü |
| 138 | ç | 151 | Ç |

## Event Log Protocol

The alarm stores events in a **128-entry ring buffer**. Events are fetched in two steps.

### Step 1: Get cursor (type 0x30)

Request payload:
```
[0x00, 0x00, 0xF1, 0x00, 0x03, 0x30, 0x03, 0x00, checksum]
```
- byte[6] = **0x03** for events (NOT 0xE0 like NAME/ZONE sync)

Response: `00:f1:00:00:00:LL:30:03:00:HI:LO:...`
- **HI** = ring buffer write pointer (0x00–0x7F)
- Newest event at position `(HI - 1) % 128`, oldest at HI
- `HI * 256 + LO` = total event count

### Step 2: Fetch events (type 0x39)

Request payload:
```
[0x00, 0x00, 0xF1, 0x00, length, 0x39, 0x00, *index_pairs, checksum]
```
- Each index is 2 bytes: `[0x00, ring_position]` (position 0x00–0x7F)
- **10 indices per batch** (length = 10×2 + 2 = 0x16)
- Iterate from `(pointer - 1) % 128` downward, wrapping 0 → 127
- Last batch may have fewer than 10

Response: 15 bytes per event:
```
[0]  = 0x00 (padding)
[1]  = ring buffer index
[2]  = BCD year   (0x26 = 2026)
[3]  = BCD month  (0x01–0x12)
[4]  = BCD day    (0x01–0x31)
[5]  = BCD hour   (0x00–0x23)
[6]  = BCD minute (0x00–0x59)
[7]  = BCD second (0x00–0x59)
[8]  = CID qualifier (high nibble) + event code digit 1 (low nibble)
[9]  = CID event code digits 2-3 (BCD, 0xA = 0)
[10] = 0xAA (constant)
[11] = 0x0A (constant)
[12] = zone number (0x0A = system/no zone)
[13] = zone number (duplicate)
[14] = 0x00 (terminator)
```

### BCD decoding

```python
def bcd(b: int) -> int:
    return (b >> 4) * 10 + (b & 0x0F)
```

### Contact ID decoding

**Qualifier** (byte[8] high nibble):
- `1` = new event / trouble
- `3` = restore / recovery

**Event code** (byte[8] low nibble + byte[9]):
- Hundreds = byte[8] & 0x0F
- Tens = byte[9] >> 4 (0xA = 0)
- Units = byte[9] & 0x0F (0xA = 0)

### Contact ID codes observed

| Code | Event (Q=1) | Restore (Q=3) |
|------|-------------|----------------|
| 130 | Abertura zona / Burglary | Fechamento zona |
| 147 | Falha supervisão RF | Restauração supervisão RF |
| 301 | Falha na rede elétrica | Rede elétrica presente |
| 384 | Bateria baixa (RF sensor) | Bateria recuperada |
| 401 | Desarme / Disarm | Arme / Arm |

## XOR Encryption

Simple XOR cipher applied to frames when key ≠ 0:
```python
def encrypt(data: bytes, key: int) -> bytes:
    return bytes([x ^ key for x in data])
```

## Zone Bitmask

For BYPASS and status zone fields, zones are packed as 3-byte little-endian bitmasks:
```python
def null_zone_data(zones: list[int]) -> bytes:
    data = [0] * 3
    for i in zones:
        x = i - 1
        data[x // 8] |= 1 << (x % 8)
    return bytes(data)
```
