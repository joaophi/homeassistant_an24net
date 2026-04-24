# Alarme Intelbras

Home Assistant custom integration for **Intelbras AN-24 Net** alarm systems.

Communicates with the alarm panel over the AMT protocol via TCP — either through Intelbras cloud or locally via the optional proxy server.

## Features

- Arm / disarm / arm stay / panic
- Per-zone binary sensors (open, violated, stay, low battery)
- Energy (AC power) sensor
- PGM output switch
- Per-zone bypass/annulment switches
- Real-time push events for instant status updates
- Repair issues for RF supervision failures and low battery
- Diagnostics support

## Installation

### HACS (recommended)

1. Open HACS in Home Assistant
2. Go to **Integrations** > **Custom repositories**
3. Add this repository URL and select **Integration**
4. Install **Alarme Intelbras**
5. Restart Home Assistant

### Manual

Copy `custom_components/intelbras` to your Home Assistant `custom_components` directory and restart.

## Configuration

Go to **Settings** > **Devices & Services** > **Add Integration** > **Alarme Intelbras**.

You will need:

| Field | Description |
|-------|-------------|
| Host  | Hostname or IP of the proxy server (default: `amt.intelbras.com.br`) |
| Port  | TCP port (default: 9009) |
| MAC   | Alarm panel MAC address |
| PIN   | Alarm panel PIN code |

### Options

After setup, you can configure additional options via **Settings** > **Devices & Services** > **Alarme Intelbras** > **Configure**:

| Option      | Description |
|-------------|-------------|
| Require PIN | When enabled, the PIN must be entered in the UI to arm/disarm. When disabled, the stored PIN is used automatically (default: enabled) |

## Proxy Server (optional)

The integration works out of the box via Intelbras cloud (`amt.intelbras.com.br:9009`). The proxy server is optional — it intercepts the alarm's outbound connection so Home Assistant can communicate with the panel locally, reducing latency. It also maintains the upstream connection to Intelbras cloud, so the original app keeps working.

### Running the proxy

From the `proxy/` directory:

```bash
docker compose up -d
```

This builds and starts the proxy server listening on port `9009`.

### Network setup

The alarm panel must be redirected to the proxy server instead of the Intelbras cloud. Configure a port forwarding / DNAT rule on your router to redirect the alarm's outbound traffic on port `9009` to the machine running the proxy.

Example OpenWrt firewall rule (`/etc/config/firewall`):

```
config redirect
    option dest '<DEST_ZONE>'
    option target 'DNAT'
    option name 'Redirect-Alarme-Server'
    option src '<SRC_ZONE>'
    option src_dport '9009'
    option dest_ip '<PROXY_SERVER_IP>'
    list proto 'tcp'
    option family 'ipv4'
    list src_mac '<ALARM_PANEL_MAC>'
    option dest_port '9009'
```

Replace the placeholders:

- `<SRC_ZONE>` — the firewall zone where the alarm panel is connected (e.g. `lan`, `iot`)
- `<DEST_ZONE>` — the firewall zone where the proxy server is running (e.g. `lan`, `server`)
- `<PROXY_SERVER_IP>` — IP of the machine running the proxy
- `<ALARM_PANEL_MAC>` — your alarm panel's MAC address

## Requirements

- Home Assistant 2024.1+
- Intelbras AN-24 Net alarm panel
- Proxy server running on the local network (see above)
- Router with DNAT/port forwarding capability to redirect alarm traffic
