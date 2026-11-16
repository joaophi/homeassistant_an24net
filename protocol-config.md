# Config App Protocol: AMT Remoto Mobile ↔ Intelbras AN-24 Net

Companion to [`protocol.md`](protocol.md), which covers the **user** app (AMT Mobile V3, `0xE9` MY_HOME).
This file covers the **installer/config** app, **AMT Remoto Mobile v3.0.0**. Everything here comes from
the decompiled APK (Xamarin/.NET, `Amt2k.Core.DotnetStandard.dll`), not from captured traffic.
"(inferred)" marks guesses. Source references are decompiled class/method names.

## Overview

| | User app (AMT Mobile V3) | Config app (AMT Remoto Mobile) |
|---|---|---|
| Protocol | Legacy short frames, `0xE9` MY_HOME | **ISECNet v2**: 8-byte header, 16-bit command, XOR checksum |
| Auth | 4-digit user PIN inside each MY_HOME frame | Remote-config password (up to 6 digits), once per session (`0xF0F0`) |
| Cloud | `0xFB` XOR key, then `0xE5` connect | `0xE5` connect (no XOR step), then every frame wrapped as `[len][0xE7][isecnet][ck]` |
| Local | TCP 9009 | TCP 9009 (LAN scan = TCP connect sweep of the /24) |
| Commands | 1-byte inner commands (`0x41` arm, `0x5A` status, …) | 16-bit: read `0x3xxx`, write `0x2xxx`, special `0x4xxx`–`0x6xxx`, control `0xF0xx` |

Generations: **ANM 24 NET (G1)** = model byte `0x02`, **ANM 24 NET - G2** = `0x25` (reply to `0x0060`, byte `[8]`).

Firmware binaries: the public API `https://api-cronos.intelbras.com.br/v1/version/anm/anm24netg2-cloud/prod/latest`
returns JSON whose `file` field is a direct `.bin` URL (G2 1.0.3 = 116,640 B, md5 `c2bd4dbd5e1d04e388ffc689b11515c3`).

---

## Part 1 — Transport layer: AMT Remoto Mobile v3.0.0 with ANM 24 NET / ANM 24 NET - G2

Source: ILSpy decompile of `Amt2k.Core.DotnetStandard` (namespace folders under `apk/src/Amt2k.Core.DotnetStandard/`). Paths below drop the `Amt2k.Core.DotnetStandard.` namespace prefix. Multi-byte integers are big-endian unless marked LE. "(inferred)" marks anything the code doesn't state outright.

**Summary:** both 24 NET generations are ISECNet v2 devices. The app treats them as members of the AMT 8000 family (`Client.IsAmt8000 = true`). Every 24 NET session uses the same three things:

- TCP port **9009**
- the 8-byte-header ISECNet v2 frame
- `0xF0F0` authentication

The model is decided **after login** from command `0x0060`, response byte `[8]`: `0x02` = G1, `0x25` = G2. The app uses no UDP anywhere (grep for `UdpClient`/`Broadcast` finds nothing).

---

### 1. Framing

#### 1.1 ISECNet v2 frame (`Packet(CommandTypesAmt8000 cmd, byte[] data, bool isRemoteConnection)`, `Packet.cs`)

```
off  0  1  2  3   4..5          6..7      8..         last
     00 00 00 F1  len16=n+2     cmd16     data[n]     ck
```
- Byte 3 is `0xF1` when `isRemoteConnection == false` and `0x00` when it is true.
- `ck` = XOR of every preceding byte, then `^ 0xFF` (`Core/Checksum.Calculate`).
- **Remote (cloud / IP receiver) wrapping.** When `isRemoteConnection` is true, the whole inner frame (byte 3 = 00) is wrapped as `[1+innerLen][E7][inner…][ck']`, where `ck'` uses the same XOR^FF over `len, E7, inner`.
- Other constructors:
  - The 2-arg `Packet(CommandTypesAmt8000, data)` always writes byte 3 = `0x00` and never wraps. It is used only for the G2 firmware-status poll (§6.2) and the fence keep-alive.
  - `Packet9000` is the AMT 9000 variant. It always writes byte 3 = `0x00` and doesn't apply to the 24 NET.

Examples, computed with the app's algorithms:
```
0x0060 info, local   : 00 00 00 F1 00 02 00 60 6C
0x3FAA MAC [00]      : 00 00 00 F1 00 03 3F AA 00 98
0x5002 bootloader    : 00 00 00 F1 00 02 50 02 5E
0xF0F0 auth "123456" local : 00 00 00 F1 00 0B F0 F0 01 01 02 03 04 05 06 10 00 13
                     remote: 13 E7 00 00 00 00 00 0B F0 F0 01 01 02 03 04 05 06 10 00 E2 F4
```

#### 1.2 Legacy / "IP communication" frames (used only as a probe for the 24 NET)

- `Packet(CommandTypes cmd, data)` (legacy, with CRC): `[len][cmd][dlen][data…][crc16 LE][ck]`.
  - `len = 1 + (1+dlen) + 2`.
  - The CRC runs over `[dlen][data]` (`Protocol/Crc.ComputeChecksum`): table-driven, init 0, `crc = (crc>>8) ^ T[(crc^b)&0xFF]`. The table is custom (`T[1]=0x0580`, `T[128]=0x0383`, 257 entries). The result is emitted with `BitConverter.GetBytes`, so LE on Android.
  - `ck` = XOR^FF over everything before it.
  - The probe `Packet(CMD_IP_COMMUNICATION=0xE7, [0x10])` = `05 E7 01 10 06 60 6A`.
- `CloudPacket` / `IpReceptorPacket`: `[len=1+n][cmd][data n][ck]`, no CRC. These are the cloud/receiver control frames.

The remote wrapper in §1.1 is the same `[len][E7]…[ck]` "IP communication" envelope that legacy panels use, but with an ISECNet v2 frame inside and no CRC/dlen (inferred from the identical `0xE7` value and layout).

#### 1.3 Receive side (`Infra.Tcp/TcpSocketClient.cs`, `SocketCommunicationService.cs`)

- **Socket:** `TcpClient(AddressFamily.InterNetworkV6)` with `IPv6Only=0` (dual-stack). `ReceiveTimeout`/`SendTimeout` = 10 000 ms. Connect timeout comes from the caller: 5 000 ms for scan, 10 000 ms for login, 30 000 ms for the G1 post-bootloader reconnect.
- **No framing on receive.** `Receive(size=1024, responseTimeout)` polls `DataAvailable` every 50 ms until `responseTimeout`, then does **one** `ReadAsync` into a `size` buffer and returns the full zero-padded `size`-byte array.
  - The app never uses the length field. Replies larger than `size` are truncated, and a reply split across TCP segments is read only partially.
  - `responseTimeout` = `Client.PacketResponseTimeout × 1000`: user setting, default 10 s, allowed 10–120 s (`Domain.Entities/Client` ctor).
  - Timeout or error returns `null`. `SendAndReceive*` then returns `new byte[size]`, all zeros, **never an empty array**, so the callers' `Length == 0` checks never fire.
- **Unwrap.** If `resp[1]==0xE7 && resp[2]==0x00`, the first 2 bytes (`len, E7`) and the last buffer byte are dropped (`SendAndReceive`, `SendAndReceiveNoReconnection`). The inner ISECNet v2 frame then starts at offset 0, so every parser can use `[6..7]=cmd` and `[8..]=data` regardless of transport.
- **Retries.**
  - `SendAndReceive`: up to 3 send+receive tries. After the 2nd empty reply it calls `Reconnect()`, a full re-login with the stored credentials via `LocalIpConnection`, `IpReceiverConnection` or `CloudConnection` depending on `ConnectionMode`.
  - `SendAndReceiveNoReconnection` (used during login): 2 tries.
  - Only one request can be in flight at a time (`_watingResponse` flag). Waits poll every 1 s and give up after 10 s, returning zeros.
- **Pacing:** `Client.TimeBetweenPackets` is stored but never used anywhere.

---

### 2. Discovery and model identification

#### 2.1 LAN scan (`SearchPanels.Presentation/BuscaRedeViewModel.BuscarCentrais`, `Infra.Datasources.SearchPanel/SearchPanelsDataSource.Search`)

- **What gets scanned:** a **TCP connect sweep**, not a broadcast. The app takes the first IPv4 address on `en0`/`wlan*`/`eth*` and assumes a /24. It tries `.1`–`.254`, skipping its own address, in batches of 23 every ~1 s.
- **Per host:** `Open(ip, 9009, 5000 ms)`. If the connect succeeds, it sends two 3-byte legacy short frames `[len=01][cmd][ck]`:

| Request | Meaning | Reply parsing |
|---|---|---|
| `01 C4 3A` | get MAC | MAC = reply bytes `[2..7]`, hex, upper-case (`text += macBytes[i]` for i=2..7). Retried once if the reply is empty. |
| `01 C2 3C` | get model string | `[0]=n`; chars = bytes `[2..n]` as ASCII (`BuildModel`). If `[0]==0` → `"AMT Intelbras"`. Retried once if the reply is all zeros. |

- **`BuildModel` normalisation:**
  - Upper-cases and trims the string, then strips `\x0F`, `\0`, `]`, `.` and `*`.
  - Explicit mapping: **`"ANM24NETG2"` → `"ANM 24 NET"`**, so the scan list does not distinguish G2.
  - Other mappings, which are not 24 NET: `5`/`9` → ELC 6012 NET/IND, `8` → 4G communicator, `XEG 4000 SMART` → AMT 4010.
  - Not in the code: what string a G1 returns. Probably passed through as e.g. `ANM24NET` (inferred).
- **Result:** `ClientDto{Mac, Model, Ip, ConnectionMode = 2}`, where 2 = **cloud**. Tapping a result opens the login screen prefilled for cloud login by MAC, not local IP (`BuscaRedeViewModel.actionClick` → `LoginViewModel.Prepare`).
- `SearchWithPanelAlreadyConnected` sends the same `C4`/`C2` pair over an already-open session. It is used only by `ListElcWifiScanViewModel` (ELC), not the 24 NET.

#### 2.2 Model detection after login (`Infra.Datasources.Online/OnlineAmt8000DataSource.GetAlarmPanelModel`)

Called once by `InitializingViewModel` → `ProgressRepositoryImpl` → `GetAlarmPanelModelUseCase`. `OnlineRepository` picks `OnlineAmt8000DataSource` because `IsAmt8000` is true after `OpenAmt8000`.

1. The app sends `0x0B4A` (full status, AMT 8000) with no data. If the reply echoes cmd `0x0B4A` at `[6..7]`, the panel is an AMT 8000-family device and `ReadPanelModel(resp)` runs on it.
2. Otherwise it calls `Get24NetModel()`: send **`0x0060` CMD_INFO_CENTRAL_ALARME**, no data, then `InterpreterInformationAmt8000.ReadPanelModel(resp)`.

From this the 24 NET is evidently expected **not** to echo `0x0B4A` (inferred).

`ReadPanelModel` (`InterpreterInformationAmt8000.cs`), applied to the `0x0060` reply:

| byte `[8]` | Model string set | Zones / users |
|---|---|---|
| `0x02` | `"ANM 24 NET"` | 24 / 30 |
| `0x25` | `"ANM 24 NET - G2"` | 24 / 30 |
| `0x01`, `0x8A`, `0x8B` | AMT 8000 / PRO / LITE | — |
| `0x35`, `0x39`, `0x38` | ELC 6012 NET / IND, 4G communicator | — |

- **Version** (`ReadPanelModel`, `OnlineInterpreter.Read24NetStatus`):
  - If `[9] > 0`: `"[9].[10].[11]"` in decimal.
  - Else: `"(([10]>>4)).([10]&0x0F).[9]"`, a packed-nibble old format.
  - `Client.Version` = that string with the dots removed, as an int. Example: `6.0.0` → `600`. The 24 NET code branches on `Version >= 600`.
- **Every later model branch compares the model *string*** (`"ANM 24 NET"` / `"ANM 24 NET - G2"`), for example the firmware data-source choice in `OnlineFirmwareRepositoryImpl`. The saved-panel list folds G2 into `"ANM 24 NET"` for display (`ManagePanels/TabFragmentViewModel`, line ~426).

---

### 3. Connection and login

`LoginViewModel.GetLoginUseCase` maps `ConnectionMode` to a use case: `0` = local IP (`LocalIpConnection`), `1` = IP receiver (`IpReceiverConnection`), `2` = cloud (`CloudConnection`). If the "bootloader" checkbox is set **and** mode = 0, it uses `BootModeConnection` instead (§6.3). All of them end in `Infra.Repositories.Login/LoginRepository`.

#### 3.1 Local IP (`LoginRepository.LocalIpLogin`)

1. Set `IsRemoteConnection = false`, then `Open(ip, 9009, 10 s)`. The port is **hard-coded 9009**; `Client.Port` (default 9010) is only used for the IP receiver.
2. Send the legacy probe `05 E7 01 10 06 60 6A` (`Packet(CMD_IP_COMMUNICATION,[0x10])`) and classify the reply:
   - `Converters.Translate(CMD_LOCAL_REFRESH)`: `[1]==E7 && [3]==0x90` → legacy panel. The legacy `SendIdentify` path, or AMT 9000 if `[4]==0x90`. **Not used for the 24 NET.**
   - Otherwise `Converters.TranslateAmt8000(CMD_LOCAL_REFRESH)`: `[3]==0x80` → ISECNet v2 device → **`OpenAmt8000`** (§4).
   - Neither matches → exception → `ErrorAuthenticationLocalIp`.
3. Frames go out with byte 3 = `0xF1`, unwrapped.

The 24 NET must answer the legacy `E7/0x10` probe with byte `[3]==0x80` (inferred). The exact reply layout isn't in the code.

#### 3.2 Cloud (`LoginRepository.CloudLogin`)

1. `Open(CLOUD_DNS, PORT_CLOUD, 10 s)`. If that call succeeds but the socket isn't connected, retry with `IP_CLOUD` after 200 ms. In practice the IP fallback is dead code, because `Open` throws on failure.

| RoutesStrategy | CLOUD_DNS | IP_CLOUD | PORT_CLOUD | AMT_UPDATE | CLOUD_DNS_8000 / IP_CLOUD_8000 |
|---|---|---|---|---|---|
| `OficialRoutesStrategy` (default) | `amt.intelbras.com.br` | `54.207.87.87` | 9009 | `54.207.162.243` | `amt8000.intelbras.com.br` / `52.67.212.35` |
| `OficialRoutesStrategy("es")` | `global.amt.intelbras.com.br` | `75.2.7.18` | 9009 | same as default | `global.amt8000.intelbras.com.br` / `15.197.214.60` |
| `StagingRoutesStrategy` | `amt-stag.intelbras.com.br` | `18.229.98.157` | **9029** | (unset) | `amt8000-stag.intelbras.com.br` / (unset) |

`PORT_CLOUD_2 = 8080` is defined but never used.

2. **Connect request.** `CloudPacket(CMD_CLOUD_CONNECT = 0xE5, data[20])`, sent in clear:
   ```
   15 E5 | 04 | MAC[6] | 00 | 01 | MAC[6] | 00 00 00 00 00 | ck
   e.g.  15 E5 04 AA BB CC DD EE FF 00 01 AA BB CC DD EE FF 00 00 00 00 00 0A
   ```
   - MAC = 12-hex-char string parsed in pairs (`CloudPacket.TranslateMacToByte`).
   - The meaning of the `04` and `01` bytes is unknown.
   - **Unlike the AMT Mobile V3 user app, there is no `0xFB` key request and no XOR.** `CloudPacket.BuilHexNumberRequest()` (→ `01 FB 05`) and `EncryptConnectionCommand(cmd, key)` (byte-wise XOR) exist but have no callers.
3. **Reply:** only **byte `[0]`** is checked.

| `[0]` | Meaning | Action |
|---|---|---|
| `0xFE` | Panel is online on the cloud | Send the legacy probe through the tunnel. If `[3]==0x80`, set `IsRemoteConnection = true` and call `OpenAmt8000` (all later frames E7-wrapped, inner byte 3 = 00). A legacy reply takes the `SendIdentify` path. |
| `0xFD` | Panel not on this cloud | Fall back to `ConnectCloudAmt8000` (below) |
| other | — | Return false → `ErrorAuthenticationCloud` |

   This differs from the user app's `E6 0E` / `E4` / `E8` replies. Whether `FE`/`FD` is a bare byte or a framed reply can't be told from the code.
4. **AMT 8000 cloud fallback** (`ConnectCloudAmt8000`). It runs for any panel after `0xFD`; whether a 24 NET G2 is ever reachable this way is unknown.
   1. `Open(CLOUD_DNS_8000, 9009)`, falling back to `IP_CLOUD_8000:9009`.
   2. Send `0x30F6` CMD_CONECTA_SERVIDOR_RELAY with data `01 00×14 01` (16 bytes) and byte 3 = `0xF1` (`IsFakeConnection` is never set). Expect `[6..7] = F0 FE`. The check is written `[6]!=240 && [7]!=254`, so it is lax.
   3. Send `0xFFF0` CMD_BIND_CENTRAL_SERVIDOR_RELAY with data = **ASCII bytes of the 12-char MAC string** (`GetMacPacket`). Expect `F0 FE`, else `PANEL_NOT_CONNECTED_TO_CLOUD`.
   4. Call `OpenAmt8000` with `IsRemoteConnection = false`: plain frames, byte 3 = F1, no E7 wrapper.
- **Demo shortcut:** MAC `123456123456` + password `7536` skips the network entirely (`CloudConnection.Execute`).

#### 3.3 IP receiver (`IpReceiverLogin`)

Uses `IpReceptorPacket` commands `0xE0`, `0xE3` (`"E"`/`"G"`/`"H"` + account) and `0xE4`, then the same probe → `OpenAmt8000` with `IsRemoteConnection = true`.

It is probably unused for the 24 NET: `RememberConnectedPanelDecorator` blanks the receiver IP, port and account for `"ANM 24 NET"` (inferred).

#### 3.4 Keep-alive and disconnect

- **`Services/KeepAliveService`:**
  - Starts after the menu or password screen opens. A `Timer` ticks every 10 s.
  - It sends a frame only if `now − LastRequestTime ≥ PacketResponseTimeout` (default 10 s).
  - For `IsAmt8000` panels, including the 24 NET, it sends **`0x0B4A`** (no data) and expects the cmd echoed.
  - The 24 NET most likely doesn't echo `0x0B4A` (§2.2), so the check "fails". The return value is ignored, so the frame works purely as traffic (inferred).
  - `0xF0F7` CMD_KEEP_ALIVE is **not** used as the periodic keep-alive. It is sent once, after a date/time write (`GeneralDateSet8000DataSource`). `Converters.TranslateAmt8000(CMD_KEEP_ALIVE)` expects `[7]==0xFE` (or `[9]` if still wrapped).
- **Disconnect** (`Infra.Repositories/DisconnectRepository.Disconnect`): sends `0xF0F1` CMD_DESCONECTAR_DISPOSITIVO_REMOTO with no data. Success = `[7]==0xFE`, or `[6]==0xF0 && [7]==0xF1` (`Converters.TranslateAmt8000`). The socket is closed either way.

---

### 4. Authentication (`LoginRepository.OpenAmt8000`)

```
cmd 0xF0F0  CMD_AUTENTICA_CONEXAO_REMOTA
data (9 B): 01 | p1 p2 p3 p4 p5 p6 | 10 | 00
```
- **Password encoding:**
  1. `Client.Create` first replaces every `'0'` with `'A'`.
  2. `Converters.GetPartsInBytesAmt8000(pw, 6)` then turns each character into **one byte** = its hex-digit value. So `0`→`0x0A`, `1..9`→`0x01..0x09`.
  3. Only 6 positions are read. A shorter password leaves the remaining bytes `0x00`, because `Substring` throws and the partly filled array is returned.

  So for the 24 NET, the remote-access password is up to 6 digits, one digit per byte, with `0` sent as `0x0A`.
- The meaning of the fixed bytes `0x01` (data[0]) and `0x10 0x00` (data[7..8]) is unknown. Possibly a software/connection type (inferred).
- **Reply** (after unwrap): `[6..7] = F0 F0` is not checked. **Result = `[8]`** (or `[10]` if still wrapped, `[1]==E7`).
  - **`0x00` or `0x0C` = success** (`Converters.TranslateAmt8000`).
  - Any other value is a failure with a generic message. The specific code is not decoded at login.
- `[9]` is checked only for `0x90` → `"AMT 9000"` and `0x38` → `"Comunicador WiFi 4G"`. Probably it is the device-type ID (inferred).
- IP-receiver mode only: `[0]==0xFD` → fail.
- On success: `IsAmt8000 = true`, `IsConnected = true`.
- The legacy `SendIdentify` path (`E7` + `0x11` + BCD password + `0x34`, master flag `[3]==0x4D`) is **not** used for the 24 NET.

---

### 5. Generic response handling

| Item | Rule | Source |
|---|---|---|
| Expected-reply check | `VerifyExpectedPacket(resp, cmd)`: `resp[6]==cmd>>8 && resp[7]==cmd&0xFF`. The checksum is **never verified**; neither is the length. | `InterpreterInformationAmt8000.VerifyExpectedPacket` |
| ACK | cmd **`0xF0FE`**. Writes and exec commands expect it. It may carry a status byte at `[8]`; for example, wireless pairing: `00` = in progress, `01`/`8A`/`8B` = done, other = invalid RF. | `WirelessDevicesAddGeneric8000DataSource.AddDevice` |
| NACK | cmd **`0xF0FD`**, error code at **`[8]`** | `OnlineAmt8000DataSource.ActivatePanel` |
| NACK codes (`Get8000Error`) | `00` OK, `19` invalid password, `1B`/`20` partition without enabled zones, `27` open zones, `2A` operation denied, `2E` arm/disarm error, `36` partition without stay zone, `3F` panel without enabled zones, `44` PGM not accessible, `46` device without digital tamper | `InterpreterInformationAmt8000.Get8000Error` |
| Extra 24 NET wireless codes at `[8]` | `D3` (211) position occupied (add), `D4` (212) no device at position (delete) | `WirelessDevicesAddGeneric8000DataSource` |
| Read requests | Data is usually 1 byte: index `00`, or `FF` = all. The reply echoes it at `[8]` and the payload starts at **`[9]`** (inferred from the parsers below). | — |
| MAC (`ReadMac`) | Request `0x3FAA` + `[00]`. Reply MAC = `[9..14]`, formatted `AA:BB:…` | `InterpreterInformationAmt8000.ReadMac` |
| Time (`ReadOnlineAlarmHour`) | `0x34AA` + `[00]` → `[9..11]` = hh mm ss, **BCD** (printed with `BitConverter.ToString`) | same file |
| Date (`ReadOnlineAlarmDate`) | `0x34A1` + `[00]` → `[9..11]` = DD MM YY, BCD | same file |
| Write time | `0x24AA` data `00 hh mm ss`, BCD | `WriteInformationBuilder.WriteAlarmTimeAmt8000` |
| Write date | `0x24A1` data `00 DD MM YY dow`, BCD, `dow` 1 = Sunday | `WriteInformationBuilder.WriteAlarmDateAmt8000` |

- **Command-number pattern:** reads are `0x3xxx` (`0x6xxx` for 24 NET-specific ones), writes are read − `0x1000`, exec commands are `0x40xx`, session commands are `0xF0xx` (inferred from the enum).
- **Error detection on reads is weak.** A timeout yields a zero-filled buffer that fails `VerifyExpectedPacket` and leaves default values.

---

### 6. Online / status commands used for the 24 NET

The online screen for the 24 NET shows only the **Zones** tab (`Presentation.Online/OnlineMainViewModel`). Siren-stop and clear-triggers are blocked in the UI for the 24 NET (`OnlineMainViewModel.ExecuteDisableAlarmCommand`, `OnlineZonesViewModel.ExecuteCleanTriggerCommand`).

#### 6.1 Status poll (`OnlineAmt8000DataSource.GetAlarmPanelStatusOnly`)

1. Send **`0x0060`**, no data → `OnlineInterpreter.Read24NetStatus`:

| Offset | Meaning |
|---|---|
| `[8]` | Model ID: `02` G1, `25` G2 |
| `[9..11]` | Version (§2.2) |
| `[11]` bit 4 (`0x10`) | "Partitioned" flag. It overlaps the version byte whenever `[9] > 0`. |
| `[14]` | Firmware channel: `00` = " dev", `01` = " beta", else release. Only shown for G2 in `Read24NetStatus`; `ReadOnlineWrapper` shows it for both. |

2. Send **`0x0B01`** CMD_READ_STATUS_CENTRAL_ALARME, no data → `OnlineInterpreter.Read8000Status`:

| Offset | Meaning |
|---|---|
| `[8]` bit 1 (`0x02`) | Alarm / siren triggered |
| `[8]` bits 5/6/7 (`0x20`/`0x40`/`0x80`) | Armed = `0x20 && 0x40 && !0x80`. "Stay/partial" entity = `0x80`. For Version < 600 the code computes `0x20 && !0x40` but never uses it. |
| `[25..27]` | 24-zone bitmap, bit *j* of byte *i* = zone 8·(i−25)+j+1. **G2: open; G1: triggered.** |
| `[33..35]` | 24-zone bitmap. **G2: triggered; G1: open.** |
| `[41..43]` | 24-zone bitmap: bypassed ("cancelled") |
| `[51..53]` | Date DD MM YY, BCD |
| `[54..56]` | Time hh mm ss, BCD |

   The 0x0B4A full-status request that AMT 8000 panels also get is skipped for the 24 NET.
   - The dead-code parser `InterpreterInformationAmt8000.ReadAlarmStatus` (no callers) gives a different reading: `[25]`=open and `[33]`=alarm for both generations; for v ≥ 600 stay = `0x20 && 0x40 && 0x80`; for v < 600 complete = `0x20 && 0x40` and partial = `0x20 && !0x40`.
3. **Zones tab** (`Online.Zones/OnlineZone8000DataSource.ZonesStatus`): status as above, then **`0x33A0`** CMD_READ_ZONAS_TIPO with data `[FF]` → `Read24NetZoneType`. Payload from `[9]`, **2 bytes per zone × 24**; bit 0 of the first byte = zone has a sensor.
4. **MAC:** `0x3FAA` `[00]` (`GetAlarmPanelMac`). **Battery:** not queried; shown as "unavailable" for the 24 NET (`GetBatteryStatus`).
5. **Bypass** (`BypassZone`): `0x401F` with data `(zoneIndex0, isBypassed)` pairs for zones that have a sensor; expects ACK.
6. **Arm/disarm** (`ActivatePanel`, `0x401E`): the code has a 24 NET branch, but the Partitions tab isn't shown for the 24 NET, so it is unreachable from the UI.
   - G2, or G1 with Version ≥ 600: data `[partition][mode]`, mode `00` disarm / `01` arm / `02` stay.
   - Older G1: partition `0` → `FF`.
   - A NACK reply is decoded with `Get8000Error`.

---

### 7. Firmware update

The data source is chosen by model string in `Infra.Repositories.Online.Firmware/OnlineFirmwareRepositoryImpl`: `"ANM 24 NET"` → `OnlineFirmware24NetDataSource`, `"ANM 24 NET - G2"` → `OnlineFirmware24NetG2DataSource`. `Update()` stops the keep-alive first, and disconnects afterwards if the session is still marked connected.

**`ReadFirmware`** (both generations): `0x0060` → `ReadOnlineWrapper`. Both IDs `02` and `25` display as "ANM 24 NET" plus "1st/2nd generation", plus a channel item. Then:
- G1: `0x3FAA [00]`.
- G2: `0x34AA [00]`, `0x34A1 [00]`, `0x3FAA [00]`.

#### 7.1 G1: app-relayed download (`OnlineFirmware24NetDataSource`)

**Version check (`GetAvailableFirmwareVersion`).** New TCP connection to **`IP_CLOUD:9009`** (`54.207.87.87`, or `75.2.7.18` for "es"; IP, not DNS). Raw short frame:
```
03 F8 24 00 20        [len][0xF8][uID=0x24][00][ck]   (uID 0x35 = test server, flag never set)
reply: [?][F8][?][?][major][minor][mandatory] → version "major.minor" (+".0")
```

**`UpdateFirmware`:**

1. **Download the image (`GetFragmentAnm24Net`).** New connection to `IP_CLOUD:9009`, 20 s connect timeout.
   - Send `04 F9 24 00 00 26`. Reply `[?][F9][?][?][size: int32 **LE** at 4..7]`.
   - Send `04 F9 24 00 01 27`, then wait 5 s (`delayBetweenRequestAndResponse=5000`) and do one read of `size+2` bytes. Expected layout: `[F9][image × size][ck]`, with **no length byte** and `ck` = XOR^FF of all preceding bytes (`CheckSumPacketCheckRemoteUpdate`).
   - The image is `bytes[1..size]`. The whole image must arrive within that single read (see §1.3).
2. **Enter the bootloader (`StartBootloaderAnm24Net`).** Send `0x5002` CMD_START_BOOTLOADER, no data, over the current session (local or cloud-wrapped per `IsRemoteConnection`). Expect ACK `F0FE`.
3. **Reconnect.** Wait 15 s, then `ConnectUpdateAnm24Net` closes the socket and reopens **`ConnectedAlarmPanel.IpAddress:9009`** (30 s timeout). There is no re-authentication, and the IP is only known in local-IP mode (inferred).
4. **Send the image.** Split it into **240-byte** fragments; the last one is shorter. For each fragment *i* of *N*:
   ```
   cmd 0x5003 CMD_SEND_BIN_FILE, isRemoteConnection forced false (byte3 = F1):
   data = idx16 BE | N16 BE | fragment[≤240] | xorFF(fragment)
   ```
   Each fragment expects ACK `F0FE`. The app does not retry; the first failure aborts the update.
5. **Finish.** Wait 10 s and close.

#### 7.2 G2: panel downloads its own image (`OnlineFirmware24NetG2DataSource`)

- **Available version:** HTTPS GET `https://api-cronos.intelbras.com.br/v1/version/anm/anm24netg2-cloud/prod/latest`, JSON → `FirmwareModel` with `version`, `release`, `md5`, `file`, … (`SystemConstants.HTTP_ENDPOINTS.CRONOS_24_NET_G2`; `/beta/` and `/dev/` variants are defined but unused here).
- **`UpdateFirmware`:**
  1. `0x5002` START_BOOTLOADER over the current session (local or cloud). Expect ACK.
  2. Close the session, then `Open(AMT_UPDATE = 54.207.162.243, **9031**, 10 s)`. The address is the same for every language.
  3. Poll `RequestFirmwareStatus`: `0x4CB4` CMD_FW_UPDATE_GET_STATUS, data = **6 raw MAC bytes** parsed from `ConnectedAlarmPanel.MacAddress` (12 hex chars). It is built with the 2-arg `Packet`, so byte 3 = `00` and there is no wrapper:
     ```
     00 00 00 00 00 08 4C B4 AA BB CC DD EE FF 1E
     ```
     Reply byte `[8]`:

| `[8]` | Mapped to | Meaning |
|---|---|---|
| `0xF0` | `-1` | Not ready / preparing. Re-polled immediately, with no delay. |
| `0x39` | `-2` | Error (inferred) |
| `0..100` | percent | Progress. Polled every 5 s until ≥ 100. |
| timeout (zero buffer) | `0` | — |

  - **Bug:** the loop's error exit tests `status == 57 || status == 240`, but those values have already been mapped to −2/−1. An error reply therefore loops forever.
  - With a local-IP login and no MAC typed in, `MacAddress` may be empty → MAC bytes `00×6` (inferred).
- `ConnectUpdateAnm24Net` (`IP_CLOUD:9009`, 30 ms timeout) has no caller.

#### 7.3 Boot mode (recovery) (`LoginViewModel.BootloaderFlag`, `Application.UseCases/BootModeConnection`, `LoginRepository.BootModeLogin`, `Infra.Repositories.Online.Firmware/BootModeRepositoryImpl`)

- **Conditions:** "bootloader" checkbox set + local-IP mode. The UI notes the feature is 24 NET-only (`RecursoDisponivelApenas24Net`).
- **Login:** `BootModeLogin` just opens `ip:9009` with a 10 s timeout. No probe, no authentication.
- **Update:** `UpdateFirmwareBootModeUseCase` → `BootModeRepositoryImpl.Update()` → **`new OnlineFirmware24NetDataSource().UpdateFirmware()`**, which is always the **G1 flow** (§7.1), including the `0x5002` → ACK step and the reconnect to `IpAddress:9009`.

---

### 8. `CommandTypesAmt8000` values on 24 NET code paths

The "Path" column notes how certain each entry is:
- **T** = transport/session.
- **O** = online / firmware.
- **24** = a 24 NET-specific data source (`*24Net*DataSource`) or 24 NET-only command.
- **S** = a shared 8000 data source with an explicit 24 NET branch (UI reach not fully verified).
- **x** = in the code path but skipped or not echoed for the 24 NET.

| Hex | Dec | Name | Meaning / use for 24 NET | Path |
|---|---|---|---|---|
| `0xF0F0` | 61680 | CMD_AUTENTICA_CONEXAO_REMOTA | Login, §4 | T |
| `0xF0F1` | 61681 | CMD_DESCONECTAR_DISPOSITIVO_REMOTO | Logout | T |
| `0xF0F7` | 61687 | CMD_KEEP_ALIVE | Ping after date/time write only | T |
| `0xF0FD` | 61693 | CMD_NACK | Error reply, code at `[8]` | T |
| `0xF0FE` | 61694 | CMD_ACK | OK reply, optional status at `[8]` | T |
| `0x0010` | 16 | CMD_LOCAL_REFRESH | Not sent as ISECNet v2; selects the "reply `[3]==0x80`" check on the legacy probe | T |
| `0x0080` | 128 | CMD_LOCAL_REFRESH_ANSWER_AMT_8000 | The `0x80` value above (enum only) | T |
| `0x30F6` | 12534 | CMD_CONECTA_SERVIDOR_RELAY | AMT 8000-cloud fallback: bind app | T (fallback) |
| `0xFFF0` | 65520 | CMD_BIND_CENTRAL_SERVIDOR_RELAY | AMT 8000-cloud fallback: bind MAC (ASCII) | T (fallback) |
| `0x0060` | 96 | CMD_INFO_CENTRAL_ALARME | Model ID, version, channel | O |
| `0x0B4A` | 2890 | CMD_READ_STATUS_…_COMPLETO_AMT8000 | Model probe + keep-alive; 24 NET not expected to echo | O / x |
| `0x0B7A` | 2938 | CMD_READ_STATUS_…_COMPLETO_AMT8000_G2 | AMT 8000 PRO/LITE ≥ 3.2.6 only | x |
| `0x0B01` | 2817 | CMD_READ_STATUS_CENTRAL_ALARME | Arm state, zones, clock (§6.1) | O |
| `0x3FAA` | 16298 | CMD_READ_ENDERECO_MAC | MAC at `[9..14]` | O |
| `0x33A0` | 13216 | CMD_READ_ZONAS_TIPO | `[FF]` online "has sensor"; `[00]` zone list | O / 24 |
| `0x23A0` | 9120 | CMD_WRITE_ZONAS_TIPO | Zone types (`ZonesList24NetDataSource`) | 24 |
| `0x401F` | 16415 | CMD_EXEC_BYPASS_ZONA | Bypass zones | O |
| `0x401E` | 16414 | CMD_EXEC_ARMA_DESARMA_CENTRAL_ALARME | Arm/disarm (24 NET branch, UI not exposed) | O / x |
| `0x4013` | 16403 | CMD_EXEC_CLEAN_TRIGGER_CENTRAL | Blocked in UI for 24 NET | x |
| `0x4019` | 16409 | CMD_EXEC_STOP_SIREN | Blocked in UI for 24 NET | x |
| `0x0B73` / `0x0B74` | 2931 / 2932 | CMD_DEVICE_SIGNAL_LEVEL / CMD_SENSOR_TYPE | Skipped for 24 NET (`ZonesStatus` returns earlier) | x |
| `0x34AA` / `0x24AA` | 13482 / 9386 | CMD_READ / WRITE_HORA_CENTRAL_ALARME | Clock hh mm ss, BCD | O / S |
| `0x34A1` / `0x24A1` | 13473 / 9377 | CMD_READ / WRITE_DATA_CENTRAL_ALARME | Date DD MM YY (dow), BCD | O / S |
| `0x34A3` / `0x24A3` | 13475 / 9379 | CMD_READ / WRITE_TEMPO_SINCRO_DATA_HORA | Meant to be skipped for 24 NET, but the guard compares the `Client` object to a string (always "not equal"), so it **is sent** | S (bug) |
| `0x5002` | 20482 | CMD_START_BOOTLOADER | Enter bootloader → ACK | O |
| `0x5003` | 20483 | CMD_SEND_BIN_FILE | G1 firmware fragment | O |
| `0x4CB4` | 19636 | CMD_FW_UPDATE_GET_STATUS | G2 progress poll on `AMT_UPDATE:9031` | O |
| `0x00F8` / `0x00F9` | 248 / 249 | CMD_REQUEST_FIRMWARE_VERSION_CLOUD / _BIN_FILE | Enum names for the raw cloud `[len][F8\|F9]…` frames (§7.1); never put in an ISECNet v2 header | O |
| `0x6001` / `0x5001` | 24577 / 20481 | CMD_READ / WRITE_GENERAL_24_NET_CONFIG | 24 NET general options | 24 |
| `0x6002` | 24578 | CMD_WIRELESS_DEVICE_CONTROL | Pair/erase remote: `[idx][type][0]` | 24 |
| `0x6003` | 24579 | CMD_WIRELESS_DEVICE_SENSOR | Pair/erase sensor: `[idx][0]` | 24 |
| `0x6004` | 24580 | CMD_WIRELESS_DEVICE_SENSOR_SIGNAL_LEVEL | Request `[idx]` → level at `[9]` | 24 |
| `0x6005` | 24581 | CMD_WIRELESS_DEVICE_CONTROL_SIGNAL_LEVEL | Request `[idx][type]` → level at `[10]` | 24 |
| `0x351A` / `0x251A` | 13594 / 9498 | CMD_READ / WRITE_OPCOES_GERAIS | General options | 24 |
| `0x3530` / `0x2530` | 13616 / 9520 | CMD_READ / WRITE_ZONAS_NUMERO_DISPARO_AUTO_BYPASS | Zones | 24 |
| `0x3490` / `0x2490` | 13456 / 9360 | CMD_READ / WRITE_ZONAS_INTELIGENTES_TEMPO | Zones | 24 |
| `0x3471` / `0x2471` | 13425 / 9329 | CMD_READ / WRITE_MONIT_TESTE_PERIODICO_INTERVALO | Periodic test | 24 |
| `0x34A2` / `0x24A2` | 13474 / 9378 | CMD_READ / WRITE_TIMEZONE | Timezone (read with no data) | 24 |
| `0x3812`–`0x3815` / `0x2812`–`0x2815` | 14354–14357 / 10258–10261 | CMD_READ / WRITE_ETH_{ENDERECO_IP_LOCAL, MASCARA_SUBREDE_LOCAL, GATEWAY_LOCAL, SERVIDOR_DNS_PARA_ETHERNET} | Ethernet IP / mask / gateway / DNS (DNS read uses `[FF]`) | 24 |
| `0x3831` / `0x2831` | 14385 / 10289 | CMD_READ / WRITE_ETH_OPCOES_ETHERNET_LOCAL | Ethernet options | 24 |
| `0x3003` | 12291 | CMD_READ_BUFFER_EVENTOS_PONTEIRO_ESCRITA | Event log write pointer | 24 |
| `0x3900` | 14592 | CMD_READ_BUFFER_EVENTOS | Event log | 24 |
| `0x32A0` / `0x22A0` | 12960 / 8864 | CMD_READ / WRITE_USUARIO_SENHA | User and default passwords | 24 |
| `0x346A` / `0x246A` | 13418 / 9322 | CMD_READ / WRITE_AUTO_ARME_TEMPO | Auto-arm | 24 |
| `0x3410` / `0x2410` | 13328 / 9232 | CMD_READ / WRITE_TEMPO_SIRENE | Timing (24 NET-specific write length) | S |
| `0x3420` / `0x2420`, `0x3440` / `0x2440` | 13344 / 9248, 13376 / 9280 | CMD_READ / WRITE_TEMPO_ENTRADA, _SAIDA | Timing. Reads use index `[00]` for 24 NET (`[FF]` for the others); writes use a 24 NET-specific length | S |
| `0x3511` / `0x2511` | 13585 / 9489 | CMD_READ / WRITE_OPCOES_PANICO | Panic; `FUNCAO_TECLA_PANICO` is skipped for 24 NET | S |
| `0x3512` / `0x2512` | 13586 / 9490 | CMD_READ / WRITE_BLOQUEIO_FUNCOES | Blocks; `PROBLEMAS_GERAM_DISPARO` is skipped for 24 NET | S |
| `0x35A0` / `0x25A0` | 13728 / 9632 | CMD_READ / WRITE_PGM_MODO_OPERACAO | Single PGM | S |
| `0x33E0` / `0x23E0`, `0x32E0` / `0x22E0` | 13280 / 9184, 13024 / 8928 | CMD_READ / WRITE_MENSAGENS_ZONAS, _USUARIOS | Names (24 NET branch; the Messages tab is not in the 24 NET config tabs) | S |

The config-command payload layouts are out of scope here. Sources: `WriteInformationBuilder.cs`, `InterpreterInformationAmt8000.cs`.

---

### 9. Differences from the AMT Mobile V3 (user app) transport

- **No `0xFB` / XOR handshake.** The config app sends `0xE5` in clear with the payload `04|MAC|00|01|MAC|00×5`, and checks only reply byte `[0]`: `FE` = online, `FD` = offline, which triggers the 8000-cloud fallback. The user app's `E6 0E` / `E4` / `E8` replies aren't checked. The helpers for `FB`/XOR exist in `CloudPacket` but are dead code.
- **No `0xF7` / `0xFE` / `0xE9` cloud keep-alive frames.** The keep-alive is an ISECNet v2 `0x0B4A` sent through the tunnel.
- **Local port is always 9009**, with the same TCP framing as the cloud minus the `E7` wrapper (byte 3 = `F1` instead of `00`).

---

## Part 2 — ANM 24 NET / ANM 24 NET - G2 — configuration commands (AMT Remoto Mobile 3.0.0)

Source: `Amt2k.Core.DotnetStandard/` (ILSpy). Paths below are relative to it; `IIA8000` = `Amt2k.Core.DotnetStandard/InterpreterInformationAmt8000.cs`, `WIB` = `Amt2k.Core.DotnetStandard/WriteInformationBuilder.cs`.

### Conventions

- `d[n]` = payload byte *n* (the byte after `cmd16`). In a response, `d[n]` = packet offset `8+n`. The app parses most single-value replies at packet offset 9, so `d[1]`.
- Read/write pairs follow a pattern: **read = `0x3xxx`, write = `0x2xxx`** (the same code with bit `0x1000` cleared). The new 24 NET commands `0x6001..0x6005` and `0x5001` don't follow it.
- The first request byte is usually an **index/selector**. `00` means index 0 or a single item, and `FF` means "all". The reply echoes it in `d[0]` and the values start at `d[1]` (inferred from the parse offsets).
- Write success means the reply cmd is `CMD_ACK` = `0xF0FE`. `CMD_NACK` = `0xF0FD` carries an error code in `d[0]` (`ErrorsTypeAmt8000.cs`, e.g. `0x19` wrong password, `0x2A` operation not permitted, `0xD3` RF position occupied, `0xD4` no RF device at position).
- The panel is treated as an AMT 8000-family device (`IsAmt8000 = true`, set in `Infra.Repositories.Login/LoginRepository.cs`). Shared `*8000DataSource` classes therefore serve 24 NET wherever a repository routes on `IsAmt8000`. Classes that route on `Model.Contains("8000")` don't.
- Version gates: `Client.Version` = the version string with the dots removed, as an int (`"6.5.0"` → 650).
- Out of scope (not config): live status, arm/disarm, online zones/bypass, firmware update (`OnlineFirmware24Net*DataSource`).

### Model detection

| Step | Cmd | Req | Response |
|---|---|---|---|
| 1 | `0x0B4A` CMD_READ_STATUS_CENTRAL_ALARME_COMPLETO_AMT8000 | — | if the reply cmd is `0x0B4A`, it is parsed as below |
| 2 (fallback if step 1 isn't echoed) | `0x0060` CMD_INFO_CENTRAL_ALARME | — | `d[0]` model: `0x02` = ANM 24 NET, `0x25` = ANM 24 NET - G2. Version: if `d[1]>0` → `d[1].d[2].d[3]`, else `(d[2]>>4).(d[2]&0x0F).d[1]` |

Both models get 24 zones and 30 users. Source: `Infra.Datasources.Online/OnlineAmt8000DataSource.cs` `GetAlarmPanelModel`/`Get24NetModel`; `IIA8000.ReadPanelModel`.

Menus shown for both models (`ConfigurationViewModel.cs`, `ViewModels/GeneralViewModel.cs`, `Zones/ZonesViewModel.cs`, `Communication/CommunicationViewModel.cs`, `Presentation.General.GeneralTiming/TimingConfigViewModel.cs`, `ViewModels/DevicesViewModel.cs`):
- **General:** panel name, general options, blocks
- **Passwords:** master, user names, users
- **Zones:** zone config, zone names, type/mode
- **Communication:** periodic test, Ethernet
- **Timing:** times, auto-arm; timezone on G2, or on 24 NET with `Version >= 650`
- **Devices:** PGM, add RF, remove RF, RF signal level

The app shows no event-codes, partition, keypad, siren, GPRS/Wi-Fi or IP-monitoring screens for these models.

---

### Text encoding (all names)

- **Plain ISO-8859-1.** The app does **not** use the custom Portuguese char map at bytes 126–151.
- Each name field is 14 bytes, padded with spaces (`0x20`) on write. On read, NULs are stripped.
- Before saving, the view models fold lowercase accents to ASCII (`à..å→a, ç→c, é..ë→e, ì..ï→i, ñ→n, ò..õ→o, ù..ü→u, ý ÿ→y`). Uppercase accented letters are sent as Latin-1 unchanged. Source: `Presentation.Messages.MessagesZones/MessagesZonesNameViewModel.cs` `Validate`, with the same arrays in the Users and General name view models.

### Panel name

| | Cmd | Request | Response |
|---|---|---|---|
| Read | `0x31E0` CMD_READ_MENSAGENS_NOME_CENTRAL_ALARME | `00` | `d[1..14]` name |
| Write | `0x21E0` CMD_WRITE_MENSAGENS_NOME_CENTRAL_ALARME | `00` + 14 B name | ACK |

Source: `Infra.Datasources.Messages.MessagesGeneral/MessagesGeneral8000DataSource.cs` (chosen via `IsAmt8000`); `IIA8000.ReadPanelNameAmt8000`; `WIB.WriteAlarmNameAmt8000`.

### Zone names (24) and user names (30)

| | Cmd | Request | Response / payload |
|---|---|---|---|
| Read zones | `0x33E0` CMD_READ_MENSAGENS_ZONAS | list of indices: `00..0F`, then `10..17` | `count ×` 15-byte records `[idx][name 14]`, starting at `d[0]` |
| Write zones | `0x23E0` CMD_WRITE_MENSAGENS_ZONAS | records `[idx][name 14]`, at most 16 records (240 B) per packet: `00..0F` (240 B), then `10..17` (120 B) | ACK per packet |
| Read users | `0x32E0` CMD_READ_MENSAGENS_USUARIOS | `00..0F`, then `10..1D` | as for zones |
| Write users | `0x22E0` CMD_WRITE_MENSAGENS_USUARIOS | `00..0F` (240 B), then `10..1D` (210 B) | ACK per packet |

- Zone `idx` = zone number − 1.
- User `idx` 0..29 is the same numbering as the password table, so 0 is presumably master (inferred).

Source: `Infra.Datasources.Messages.MessagesZones/MessagesZones8000DataSource.cs` (it has a 24 NET branch; both its G2 sub-branches send the same indices); `…MessagesUsers/MessagesUsers8000DataSource.cs`; `IIA8000.ReadZonesNamesAmt8000`/`ReadUsersNamesAmt8000`; `WIB.WriteZonesNameAmt8000`/`WriteUsersNameAmt8000`.

---

### Passwords and user permissions

Read (master and users together):

| | Cmd | Request | Response |
|---|---|---|---|
| Read | `0x32A0` CMD_READ_USUARIO_SENHA | 30 bytes `00 01 … 1D` | 30 × 4-byte records starting at `d[0]` (no echo byte) |

Record `[idx][P1][P2][perm]`:

| Byte | Meaning |
|---|---|
| idx | `00` = master; `01..1D` = users 1–29. The code also maps `0x61`/`0x62`/`0x63` to duress, remote-config and installer, but those indices are never requested for 24 NET |
| P1 P2 | 4-digit password, one BCD nibble per digit, **digit 0 sent as `A`**. Unused nibbles are `0` or `F` (the decoder strips `0` and `F`, then maps `A→0`) |
| perm | bit0 total arm, bit1 partial arm (stay), bit2 PGM, bit3 audible panic, bit4 silent panic, bit5 medical panic |

Writes:

| Write | Cmd | Payload |
|---|---|---|
| Master | `0x22A0` CMD_WRITE_USUARIO_SENHA | `00 P1 P2 00` (success = reply is not NACK) |
| User *n* (1–29) | `0x22A0` | `n P1 P2 perm` (ACK). An empty password gives `n 00 00 perm`, which presumably erases the user (inferred) |

Example: password `1203` → `12 A3`.

- The 24 NET master screen exposes **only the master password**. Duress, installer and remote passwords are skipped for 24 NET in `WriteUsersDefaultPasswordsAmt8000`.
- On **ANM 24 NET** the UI requires total or partial arm to be set.
- On **G2** the total/partial bits are hidden and **always written as 1** (`perm |= 0x03`).

Source: `Infra.Datasources.Passwords.DefaultPasswords/PasswordsDefaults24NetDataSource.cs`; `…UserPasswords/PasswordsUsers24NetDataSource.cs`; `IIA8000.ReadPasswordsAnm24Net`; `WIB.WriteUsersPasswordsAnm24Net`, `WIB.WriteUsersDefaultPasswordsAmt8000`; `Passwords/PasswordGenericUserViewModel.cs` `Validate`.

---

### General options

| | Cmd | Request | Response / payload |
|---|---|---|---|
| Read | `0x351A` CMD_READ_OPCOES_GERAIS | `00` | `d[1]`: bit1 one-key arm, bit2 siren beep on arm/disarm |
| Write | `0x251A` CMD_WRITE_OPCOES_GERAIS | `00 flags` | ACK |
| Read (24 NET only, fw ≥ 1.0.2, **not G2**) | `0x6001` CMD_READ_GENERAL_24_NET_CONFIG | `00` | `d[1]`: bit0 enable smart supervision, bit1 enable "learn" key. `d[2]`: RF modulation, `0` = OOK, `1` = FSK (read but not shown) |
| Write (same gate) | `0x5001` CMD_WRITE_GENERAL_24_NET_CONFIG | `00 flags 00` | ACK |

- The write builds `flags` from scratch, so every bit other than 1–2 (or 0–1 for `0x5001`) is written as 0.
- On `0x5001`, `d[2]` (modulation) is always written as `00`, which would force OOK (inferred side effect).
- Partitioning, six-digit passwords and the other `0x351A` bits are hidden for 24 NET.

Source: `Infra.Datasources.General.GeneralConfig/GeneralConfig24NetDataSource.cs`; `IIA8000.ReadGeneral`, `ReadConfig24Net`; `WIB.WriteGeneralConfig24Net`; `Models/RadioOption.cs` `ModulationOptionsAnm24Net`.

### Blocks

| | Cmd | Request | Response / payload |
|---|---|---|---|
| Read | `0x3512` CMD_READ_BLOQUEIO_FUNCOES | `00` | `d[1]` bit1 = block remote controls (only bit used for 24 NET) |
| Write | `0x2512` CMD_WRITE_BLOQUEIO_FUNCOES | `00 flags` (bit1 only; other bits 0) | ACK |

`CMD_*_PROBLEMAS_GERAM_DISPARO` is skipped for both 24 NET models. Source: `Infra.Datasources.General.Blocks/GeneralBlocks8000DataSource.cs` (chosen via `IsAmt8000`); `IIA8000.ReadBlockade`.

---

### Zones — type and mode (24 zones)

| | Cmd | Request | Response / payload |
|---|---|---|---|
| Read | `0x33A0` CMD_READ_ZONAS_TIPO | `FF` | `d[0]` echo (inferred); `d[1..48]` = 24 × `[status][type]` |
| Write | `0x23A0` CMD_WRITE_ZONAS_TIPO | `FF` + 24 × `[status][type]` (49 B) | ACK |

- `status` byte: bit0 = zone enabled. Written as `00`/`01`.
- `type` byte bits:

| Bit | ANM 24 NET | G2 |
|---|---|---|
| 0 | Partial (stay) | "Stay" (same bit, different label) |
| 1 | Timed (entry/exit delay) | = |
| 2 | 24 h | = |
| 3 | Smart (only zones 1–4; written only when zone id ≤ 4) | = |
| 4 | Silent | = |
| 5 | Electric-fence trigger | = |
| 6 | Doorbell ("porteiro") | = |
| 7 | Arming input ("entrada liga") | = |

The UI rejects some combinations: timed with 24 h, doorbell, arming input or fence; silent with doorbell or arming input; 24 h with partial, doorbell, arming input or fence; partial with doorbell, arming input or fence; doorbell with arming input or fence.

Source: `Infra.Datasources.Zones.ZonesList/ZonesList24NetDataSource.cs`; `IIA8000.ReadZonesTypes24Net`; `WIB.WriteZonesTypes24Net`; `Presentation.Zones.ZonesList/ZonesGenericZoneViewModel.cs`.

### Zones — global config

| | Cmd | Request | Response | Range |
|---|---|---|---|---|
| Read triggers before auto-bypass | `0x3530` CMD_READ_ZONAS_NUMERO_DISPARO_AUTO_BYPASS | `00` | `d[1]` | 0–9 |
| Write | `0x2530` | `00 n` | ACK | |
| Read smart-zone time | `0x3490` CMD_READ_ZONAS_INTELIGENTES_TEMPO | `00` | `d[1]` seconds | 0–255 |
| Write | `0x2490` | `00 s` | ACK | |

Source: `Infra.Datasources.Zones.ZonesConfig/Zones24NetDataSource.cs`; `Presentation.Zones.ZonesConfig/ZonesConfigViewModel.cs` `Validate`.

---

### Timings

All three use 1-byte values for 24 NET. AMT 8000 uses 16 partitions with an `FF` selector instead.

| | Cmd | Request | Response | Unit / range |
|---|---|---|---|---|
| Read siren time | `0x3410` CMD_READ_TEMPO_SIRENE | `00` | `d[1]` | minutes, 1–99 |
| Write | `0x2410` | `00 v` | ACK | |
| Read entry delay | `0x3420` CMD_READ_TEMPO_ENTRADA | `00` | `d[1]` | seconds, 0–255 |
| Write | `0x2420` | `00 v` | ACK | |
| Read exit delay | `0x3440` CMD_READ_TEMPO_SAIDA | `00` | `d[1]` | seconds, 0–255 |
| Write | `0x2440` | `00 v` | ACK | |

The app writes in the order entry → siren → exit. Source: `GeneralTiming8000DataSource.cs` (chosen via `IsAmt8000`, with 24 NET branches); `IIA8000.ReadSirenTimeout`/`ReadEntryTime`/`ReadExitTime`; `WIB.WriteEntryTimeAmt8000`/`WriteExitTimeAmt8000`/`WriteSirenTimeAmt8000`; `General.GeneralTiming.Presentation/GeneralTimingViewModel.cs`.

### Auto-arm by inactivity

| | Cmd | Request | Response | Unit / range |
|---|---|---|---|---|
| Read | `0x346A` CMD_READ_AUTO_ARME_TEMPO | `00` | `d[1]` | minutes, 0–99 (0 = off, inferred) |
| Write | `0x246A` CMD_WRITE_AUTO_ARME_TEMPO | `00 v` | ACK | |

Source: `Infra.Datasources.General.GeneralAutoActivate24Net/GeneralAutoActivate24NetDataSource.cs`; `IIA8000.ReadInativityTime`; `Presentation.General.GeneralAutoActivate24Net/GeneralAutoActivate24NetViewModel.cs`.

### Timezone (G2 always; ANM 24 NET only with fw ≥ 6.5.0)

| | Cmd | Request | Response |
|---|---|---|---|
| Read | `0x34A2` CMD_READ_TIMEZONE | *(empty)* | `d[0]` (no echo byte) |
| Write | `0x24A2` CMD_WRITE_TIMEZONE | `tz` (1 B) | ACK |

`tz` = 0..7 means GMT−0 … GMT−7 (3 = Brasília). For 24 NET, 0 is GMT−0, not "disabled". Source: `GeneralTimezone24NetDataSource.cs`; `IIA8000.ReadTimezone`; `Models/RadioOption.cs` `Timezone24NetOptions`.

---

### Communication — periodic test

| | Cmd | Request | Response | Unit / range |
|---|---|---|---|---|
| Read | `0x3471` CMD_READ_MONIT_TESTE_PERIODICO_INTERVALO | `00` | `d[1]` | hours, 0–255 (0 = off, inferred) |
| Write | `0x2471` | `00 v` | ACK | |

The test time-of-day (`0x347A`) is not used for 24 NET. `CommunicationGeneral24NetDataSource.cs` sends the identical pair. Source: `PeriodicTest24NetDataSource.cs`; `Communication.CommunicationPeriodicTest.Presentation/CommunicationPeriodicTestViewModel.cs`.

### Communication — Ethernet

| Field | Read cmd / req | Read resp | Write cmd / payload |
|---|---|---|---|
| Local IP | `0x3812` / `00` | `d[1..4]` | `0x2812` / `00 a b c d` |
| Subnet mask | `0x3813` / `00` | `d[1..4]` | `0x2813` / `00 a b c d` |
| Gateway | `0x3814` / `00` | `d[1..4]` | `0x2814` / `00 a b c d` |
| DNS 1+2 | `0x3815` / `FF` | DNS1 `d[1..4]`, DNS2 `d[5..8]` (as the app parses it) | `0x2815` / `00 dns1(4) 01 dns2(4)` (10 B, index-prefixed) |
| Options | `0x3831` / `00` | `d[1]` bit0 = DHCP | `0x2831` / `00 flags` (bit0 only for 24 NET) |

- Command names: `CMD_*_ETH_ENDERECO_IP_LOCAL`, `_MASCARA_SUBREDE_LOCAL`, `_GATEWAY_LOCAL`, `_SERVIDOR_DNS_PARA_ETHERNET`, `_OPCOES_ETHERNET_LOCAL`.
- The app writes the five commands in table order and stops at the first non-ACK.
- Keep-alive (`0x3816`), Wi-Fi and GPRS are not used for 24 NET.

Source: `EthernetIpConfig24NetDataSource.cs`; `IIA8000.ReadLocalIpAddressAmt8000`…`ReadEthernetOptionsAmt8000`; `WIB.WriteEthernet*Amt8000`.

---

### PGM (1 output)

| | Cmd | Request | Response / payload |
|---|---|---|---|
| Read mode + event | `0x35A0` CMD_READ_PGM_MODO_OPERACAO | `FF` | `d[1]` = mode, `d[2]` = event (the app reads only PGM 1) |
| Write | `0x25A0` CMD_WRITE_PGM_MODO_OPERACAO | `00 mode event` (selector `00` because the PGM list length is 1) | ACK |
| Read on-time | `0x356A` CMD_READ_PGM_TEMPO_LIGADA | `FF` | `d[1..16]` (the app reads 16 values and uses `d[1]`) |
| Write on-time | `0x256A` CMD_WRITE_PGM_TEMPO_LIGADA | `FF t1..t16` (the app sends back all 16 values it read) | ACK |

PGM mode values:

| Value | Mode |
|---|---|
| 0 | On/off (latching) |
| 1–7 | Pulse of 1–7 s |
| 8 | Timed |
| 9 | Siren mirror |

PGM event values:

| Value | Event |
|---|---|
| 0 | Arm |
| 1 | Disarm |
| 2 | Audible alarm |
| 3 | Silent alarm |
| 4 | Audible panic |
| 5 | Silent panic |
| 6 | Zone open |
| 7 | Remote control |
| 8 | Siren mirror |

UI rules:
- Mode 0 is not allowed with events 2–5.
- Mode 9 and event 8 must go together.
- On **ANM 24 NET (not G2)**, a remote control can be enrolled as type "PGM" only when the PGM event is 7.

On-time: the UI rejects 0 and shows "1–99". The unit is not stated in the app (inferred seconds or minutes).

Source: `Infra.Datasources.Pgm.PgmEvent/PgmEvents8000DataSource.cs`, `…PgmMode/PgmMode8000DataSource.cs`, `…PgmTime/PgmTime8000DataSource.cs`, `…PgmList/PgmsList8000DataSource.cs` (1 PGM for 24 NET); `IIA8000.ReadPgmOperationMode`/`ReadPgmTime`; `WIB.WritePgmOperationModeAmt8000`/`WritePgmTimeAmt8000`; `Presentation.Pgms.PgmEvent/Pgm24NetViewModel.cs`; `Models/RadioOption.cs` `PgmModeAnm24Net`, `PgmEventANM24Net`; `Presentation.WirelessDevices.WirelessDevicesAdd/WirelessDevicesAddGenericViewModel.cs` `UpdateData`.

PGM live control has a 24 NET code path, but the 24 NET online screen shows only Zones, so it may be unreachable:
- Status: `0x0B70` CMD_READ_STATUS_PGM, request `01`; reply `d[1]` bit0 = PGM 1 on.
- Switch: `0x45AF` CMD_EXEC_LIGA_DESLIGA_PGM, request `00 01|00` (PGM index − 1, then on/off).

Source: `Infra.Datasources.Online.Pgm/OnlinePgm8000DataSource.cs`, `PgmInterpreter.Read24NetPgmData`.

---

### Wireless devices (24 NET-specific commands)

Remote-control **type** byte (from the app's `deviceId`):

| Type | Function |
|---|---|
| `00` | Total arm |
| `01` | Partial arm |
| `02` | PGM |
| `03` | Audible panic |
| `04` | Silent panic |
| `05` | Medical emergency |

Slots:
- Remote controls: `slot` = 0–29.
- Sensors: `zone` = zone number **5–24**, 1-based (zones 1–4 are not offered for RF; presumably wired).

Enroll and remove:

| Operation | Cmd | Request |
|---|---|---|
| Enroll remote | `0x6002` CMD_WIRELESS_DEVICE_CONTROL | `slot type 00` |
| Remove remote | `0x6002` | `slot type 01` |
| Enroll sensor | `0x6003` CMD_WIRELESS_DEVICE_SENSOR | `zone 00` |
| Remove sensor | `0x6003` | `zone 01` |

Enroll/remove reply:

| Reply | Meaning |
|---|---|
| ACK with `d[0]` = `00` | In progress (waiting for an RF transmission) |
| ACK with `d[0]` = `01` | Done. The app also accepts `0x8A`/`0x8B`, copied from the AMT 8000 code |
| ACK with any other `d[0]` | Invalid RF |
| NACK `d[0]` = `0xD3` | Position occupied (enroll) |
| NACK `d[0]` = `0xD4` | No device at position (remove) |

- **Enroll:** the app re-sends the same request in a loop while it gets "in progress", for up to 10 s, while the user triggers the device.
- **Remove:** sent once. "In progress" is shown as a failure, and any other NACK is treated as success (app quirk).

Signal level:

| Operation | Cmd | Request | Response |
|---|---|---|---|
| Sensor | `0x6004` CMD_WIRELESS_DEVICE_SENSOR_SIGNAL_LEVEL | `zone` | `d[1]` = level |
| Remote | `0x6005` CMD_WIRELESS_DEVICE_CONTROL_SIGNAL_LEVEL | `slot type` | `d[2]` = level (`d[0..1]` presumably echo slot/type) |

- `0xFF` means no reading yet. The app polls for up to 10 s and then shows the raw value; the scale is not stated.
- The registered-device list (`0x0B50`) and the AMT 8000 RF commands (`0x46xx`/`0x47xx`/`0x56xx`) are **not** used for 24 NET.

Source: `Infra.Datasources.WirelessDevices/WirelessDevicesAddGeneric8000DataSource.cs` (`AddDevice`, `DeleteDevice`, `CheckSignal` — 24 NET branches; chosen via `IsAmt8000` in `Infra.Repositories.WirelessDevices/WirelessDevicesRepositoryImpl.cs`); slot ranges in `Presentation.WirelessDevices.WirelessDevicesAdd/WirelessDevicesAdd24NetViewModel.cs`, `WirelessDevicesAddRemoteControl24NetViewModel.cs`, `…Remove/WirelessDevicesDelete24NetViewModel.cs`, `DeleteRemoteControl24NetViewModel.cs`, `…SignalLevel/WirelessDevicesSignalLevelViewModel.cs`, `RemoteControlSignalLevel24NetViewModel.cs`.

---

### Event log (read-only; 128-entry ring)

| Step | Cmd | Request | Response |
|---|---|---|---|
| 1. Write pointer | `0x3003` CMD_READ_BUFFER_EVENTOS_PONTEIRO_ESCRITA | `00` | **24 NET: 1 byte `d[1]`**. AMT 8000 uses 2 bytes `d[1..2]` |
| 2. Records | `0x3900` CMD_READ_BUFFER_EVENTOS | 16 × idx16 BE (always 32 B; unused slots are `00 00`) | 16 × 15-byte records from `d[0]` |

The app reads backwards from pointer − 1, wrapping 0 → 127, until it reaches the pointer again.

Record layout:

| Off | Size | Field |
|---|---|---|
| 0 | 2 | Index (BE) |
| 2..7 | 6 | yy mm dd hh mm ss (BCD). `FF…` = empty |
| 8 | 2 | Event code, 16-bit BE (Contact-ID-like, digit 0 sent as `A`, e.g. `0x113A`; enum `EventsKeysAmt8000`) |
| 10 | 1 | Unused by the app |
| 11 | 1 | Low nibble = source class: 0/1 zone, 2 keypad, 3 siren, 4 repeater, 5 PGM, 6 user |
| 12 | 1 | Zone or user number (BCD, `A`→0; `00` = master) |
| 13 | 1 | "Partition" byte. For 24 NET user-partition and PGM events it is shown as the **user** number |
| 14 | 1 | Photo-associated count/flag |

Source: `GeneralEvents24NetDataSource.cs`; `IIA8000.ReadEventBuffer` (24 NET branches at the user-partition and PGM events).

---

### ANM 24 NET vs G2 — differences in this app

| Area | ANM 24 NET | G2 |
|---|---|---|
| Model id (`d[0]` of `0x0060`) | `0x02` | `0x25` |
| `0x6001`/`0x5001` smart supervision / learn key | fw ≥ 1.0.2 | never sent |
| Timezone screen | fw ≥ 6.5.0 | always |
| User perm bits 0–1 | editable; UI requires at least one | forced to 1, hidden |
| Zone type bit0 label | "Parcial" | "Stay" |
| PGM-type remote enroll | requires PGM event = 7 | no check |
| Firmware update | `OnlineFirmware24NetDataSource` | `OnlineFirmware24NetG2DataSource` (not covered) |

All other commands and layouts above are identical for both.

---

## Part 3 — Verified against the panel firmware (Ghidra)

Source: static analysis of `ANM24NETG2-CLOUD-1.0.3.bin` (G2 firmware, md5
`c2bd4dbd5e1d04e388ffc689b11515c3`), decompiled with Ghidra. The command
dispatcher is one function, `FUN_08013174` (app loaded at base `0x0800D000`).
These are the commands the **panel itself** implements — the ground truth that
the app enum is matched against.

### Commands the ANM 24 NET G2 actually handles

| Code | Command | Dir |
|---|---|---|
| `0x0010` | LOCAL_REFRESH | read |
| `0x0060` | INFO_CENTRAL_ALARME | read |
| `0x0b01` | READ_STATUS_CENTRAL_ALARME | read |
| `0x0b11` | READ_ZONAS_ABERTAS | read |
| `0x0b12` | READ_ZONAS_DISPARO | read |
| `0x0b13` | READ_ZONAS_BYPASS | read |
| `0x0b70` | READ_STATUS_PGM | read |
| `0x0b73` | DEVICE_SIGNAL_LEVEL | read |
| `0x21e0` | WRITE_MENSAGENS_NOME_CENTRAL_ALARME | write |
| `0x22a0` | WRITE_USUARIO_SENHA | write |
| `0x22e0` | WRITE_MENSAGENS_USUARIOS | write |
| `0x23a0` | WRITE_ZONAS_TIPO | write |
| `0x23e0` | WRITE_MENSAGENS_ZONAS | write |
| `0x2410` | WRITE_TEMPO_SIRENE | write |
| `0x2420` | WRITE_TEMPO_ENTRADA | write |
| `0x2440` | WRITE_TEMPO_SAIDA | write |
| `0x246a` | WRITE_AUTO_ARME_TEMPO | write |
| `0x2471` | WRITE_MONIT_TESTE_PERIODICO_INTERVALO | write |
| `0x2481` | WRITE_MONIT_ATRASO_ENVIO_FALHA_AC | write |
| `0x2490` | WRITE_ZONAS_INTELIGENTES_TEMPO | write |
| `0x24a1` | WRITE_DATA_CENTRAL_ALARME | write |
| `0x24a2` | WRITE_TIMEZONE | write |
| `0x24aa` | WRITE_HORA_CENTRAL_ALARME | write |
| `0x2512` | WRITE_BLOQUEIO_FUNCOES | write |
| `0x251a` | WRITE_OPCOES_GERAIS | write |
| `0x2530` | WRITE_ZONAS_NUMERO_DISPARO_AUTO_BYPASS | write |
| `0x256a` | WRITE_PGM_TEMPO_LIGADA | write |
| `0x25a0` | WRITE_PGM_MODO_OPERACAO | write |
| `0x2812` | WRITE_ETH_ENDERECO_IP_LOCAL | write |
| `0x2813` | WRITE_ETH_MASCARA_SUBREDE_LOCAL | write |
| `0x2814` | WRITE_ETH_GATEWAY_LOCAL | write |
| `0x2815` | WRITE_ETH_SERVIDOR_DNS_PARA_ETHERNET | write |
| `0x2816` | WRITE_ETH_TEMPO_KEEPALIVE | write |
| `0x2831` | WRITE_ETH_OPCOES_ETHERNET_LOCAL | write |
| `0x28a1` | WRITE_MONIT_IP_ENDERECO_IP_DESTINO | write |
| `0x2faa` | WRITE_ENDERECO_MAC (RW MAC; app never sends) | write |
| `0x3003` | READ_BUFFER_EVENTOS_PONTEIRO_ESCRITA | read |
| `0x31e0` | READ_MENSAGENS_NOME_CENTRAL_ALARME | read |
| `0x32a0` | READ_USUARIO_SENHA | read |
| `0x32e0` | READ_MENSAGENS_USUARIOS | read |
| `0x33a0` | READ_ZONAS_TIPO | read |
| `0x33e0` | READ_MENSAGENS_ZONAS | read |
| `0x3410` | READ_TEMPO_SIRENE | read |
| `0x3420` | READ_TEMPO_ENTRADA | read |
| `0x3440` | READ_TEMPO_SAIDA | read |
| `0x346a` | READ_AUTO_ARME_TEMPO | read |
| `0x3471` | READ_MONIT_TESTE_PERIODICO_INTERVALO | read |
| `0x3481` | READ_MONIT_ATRASO_ENVIO_FALHA_AC | read |
| `0x3490` | READ_ZONAS_INTELIGENTES_TEMPO | read |
| `0x34a1` | READ_DATA_CENTRAL_ALARME | read |
| `0x34a2` | READ_TIMEZONE | read |
| `0x34aa` | READ_HORA_CENTRAL_ALARME | read |
| `0x3512` | READ_BLOQUEIO_FUNCOES | read |
| `0x351a` | READ_OPCOES_GERAIS | read |
| `0x3530` | READ_ZONAS_NUMERO_DISPARO_AUTO_BYPASS | read |
| `0x356a` | READ_PGM_TEMPO_LIGADA | read |
| `0x35a0` | READ_PGM_MODO_OPERACAO | read |
| `0x3812` | READ_ETH_ENDERECO_IP_LOCAL | read |
| `0x3813` | READ_ETH_MASCARA_SUBREDE_LOCAL | read |
| `0x3814` | READ_ETH_GATEWAY_LOCAL | read |
| `0x3815` | READ_ETH_SERVIDOR_DNS_PARA_ETHERNET | read |
| `0x3816` | READ_ETH_TEMPO_KEEPALIVE | read |
| `0x3831` | READ_ETH_OPCOES_ETHERNET_LOCAL | read |
| `0x38a1` | READ_MONIT_IP_ENDERECO_IP_DESTINO | read |
| `0x3900` | READ_BUFFER_EVENTOS | read |
| `0x3faa` | READ_ENDERECO_MAC | read |
| `0x401e` | EXEC_ARMA_DESARMA_CENTRAL_ALARME | exec |
| `0x401f` | EXEC_BYPASS_ZONA | exec |
| `0x45af` | EXEC_LIGA_DESLIGA_PGM | exec |
| `0x5001` | WRITE_GENERAL_24_NET_CONFIG | write |
| `0x5002` | START_BOOTLOADER | write |
| `0x6001` | READ_GENERAL_24_NET_CONFIG | read |
| `0x6002` | WIRELESS_DEVICE_CONTROL | read |
| `0x6003` | WIRELESS_DEVICE_SENSOR | read |
| `0x6004` | WIRELESS_DEVICE_SENSOR_SIGNAL_LEVEL | read |
| `0x6005` | WIRELESS_DEVICE_CONTROL_SIGNAL_LEVEL | read |

*76 command codes, extracted from the panel's dispatcher `FUN_08013174` (Ghidra).*

- All but one map to the app's `CommandTypesAmt8000` names. The exception is
  **`0x2faa` WRITE MAC** (`RX CMD RW MAC` in the firmware) — a factory/service
  command the app never sends.
- The other ~270 enum values are for other panels (AMT 8000 / 2018 / 9000,
  PSTN dialer, multi-partition, keypad/siren partitioning). The 24 NET is a
  24-zone, single-partition subset.
- Read = `0x3xxx` / `0x6xxx`, write = read − `0x1000` (or `0x5xxx`), exec =
  `0x40xx`/`0x45xx`, live reads = `0x0bxx`, info/refresh = `0x0060`/`0x0010`.

### Reply layouts seen in the dispatcher

- **`0x0060` INFO**: reply `00 00 F1 .. .. .. 09 00 60 | 25 vMaj vMin vBuild 04 .. flags | ck`.
  Byte `[9] = 0x25` is the **hard-coded G2 model id**; `[10..12]` = version;
  the app reads the model here to tell G1 (`0x02`) from G2 (`0x25`).
- **`0x401e` ARM/DISARM (exec)**: ACK `.. 04 40 1e FF ..`; the handler then
  sets the partition-arm flag and can NACK `0x2e` (arm/disarm error).
- **`0x401f` BYPASS (exec)**: loops over the 24 zones (`!= 0x18`), setting or
  clearing each zone's bypass byte.
- **`0x45af` PGM (exec)**: writes `'D'`/`0x44` to turn the PGM off (and the
  on-path sets the opposite), one PGM only.
- **`0x0b01`/`0x0b11`/`0x0b12`/`0x0b13`**: live reads — full status, open
  zones, triggered zones, bypassed zones.

### Status packet — `0x0b01` READ_STATUS_CENTRAL_ALARME

Built at the tail of `FUN_08013174` (the `0x0b01`/`0x0b11` fall-through),
sent with length `0x3a` (58 B). Header `.. 00 F1 .. .. 34 0b 01`, then the
**payload starts at offset `[9]`** (same framing as every other reply).
Byte offsets below are into the ISEC payload (`[9]` = payload byte 0).

| Payload off | Panel index | Size | Field |
|---|---|---|---|
| 0 | `[9]` | 1 | **Status flags** (bitfield, see below) |
| 1–3 | `[10..12]` | 3 | **Open zones** — enabled & open, 24-bit LE (bit N = zone N+1) |
| 4–8 | `[13..17]` | 5 | reserved (zeroed) |
| 9–11 | `[18..20]` | 3 | **Violated / triggered zones**, 24-bit LE |
| 12–16 | `[21..25]` | 5 | reserved (zeroed) |
| 17–19 | `[26..28]` | 3 | **Bypassed zones**, 24-bit LE (same `+0x3d` table the `0x401f` bypass exec writes) |
| 20–24 | `[29..33]` | 5 | reserved (zeroed) |
| 25 | `[34]` | 1 | boolean flag (inferred: siren active — `FUN_0801a8b4`) |
| 26 | `[35]` | 1 | zero |
| 27–32 | `[36..41]` | 6 | **Date/time** from RTC `DAT_08013864`: sequence is `[3] [5] [6] [2] [1] [0]` of the RTC struct (BCD) (inferred field order; needs a capture to pin which is Y/M/D/h/m/s) |
| … | … | | remainder zeroed up to the checksum |

**Status flags byte `[9]`** (each an independent bit):

| Bit | Mask | Meaning (inferred from the setter calls) |
|---|---|---|
| 0 | `0x01` | armed / central active (`FUN_0800f75c`) |
| 1 | `0x02` | `FUN_0801a8b4` true (siren / triggered) |
| 2 | `0x04` | set when `DAT_08013480[2] == 0` |
| 3 | `0x08` | set when `DAT_08013480[0] != 0` |
| 4 | `0x10` | set when `DAT_08013480[0x0f]` true |
| 5–7 | `0xe0` / `0x60` | mains/battery state: `0xe0` and `0x60` are the two combinations written from the two AC-presence flags at `DAT_08013484 + 0x790/0x791` |

Notes:
- This is the config app's compact status. It carries the **same semantic data**
  as the user-app 54-byte status in `protocol.md` (open / violated / bypassed
  zones + armed + AC + time), but a **different layout** — don't reuse offsets
  across the two.
- `0x0b11` (partial status) and the live reads `0x0b12` (triggered) / `0x0b13`
  (bypassed) / `0x0b70` (PGM) return the individual bitmaps on their own.
- Flag-bit and date-field meanings are inferred from the firmware; a single
  real capture settles them.

### Confirmed facts
- Plaintext, no crypto. Integrity is a CRC-32 over the app in NVM (not a signature).
- One socket serves both apps: `FALHA IDENTIFICADOR E9 OU E7`.
- Cloud hosts are hard-coded DNS; no command repoints the cloud (DNAT stays the way in).

## Open questions (need real traffic to settle)

- **Cloud `0xE5` reply**: is it a bare `FE`/`FD` byte or a framed reply? What do the `04` and `01` bytes in the request mean?
- **Login payload**: what do the fixed bytes `01 … 10 00` mean? Reply byte `[9]` is probably the device type.
- **Status parser**: the live parser swaps the meaning of bytes `[25..27]`/`[33..35]` (open vs triggered) between G1 and G2. A dead-code parser doesn't.
- **Keep-alive `0x0B4A`**: the panel seems not to echo it. Does it NACK or stay silent?
- **Echo byte**: does `d[0]` really echo the selector in single-value replies? (inferred from the app parsing at `d[1]`)
- **DNS read/write layouts don't match**: the app reads DNS2 at `d[5..8]` but writes `00 dns1 01 dns2`.
- **PGM on-time**: the app sends 16 values with selector `FF` for a 1-PGM panel. Unit unknown.
- **Writes that clear other bits**: `0x251A`, `0x2512` and `0x5001` rebuild their flags byte from 0. `0x5001` always sends modulation `00` (may force OOK).
- **RF enroll replies**: done = `01/8A/8B` (the latter look copied from AMT 8000 code). Remove treats any NACK except `0xD4` as success.
- **App bugs**:
  - The G2 firmware status loop never exits on error: it tests 57/240 after mapping them to −2/−1.
  - The date/time-sync guard compares an object to a string, so `0x34A3`/`0x24A3` is still sent to the 24 NET.

Capture idea: the phone talks to `amt.intelbras.com.br` directly, but the cloud relays to the panel
over the panel's own 9009 connection, which goes through the proxy. A cloud session from AMT Remoto
Mobile should therefore show the panel side of the `0xE7`-wrapped frames there (inferred). That only
works if the proxy forwards `0xE7` frames from upstream to the panel.
