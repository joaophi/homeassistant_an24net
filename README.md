# Alarme Intelbras

Home Assistant custom integration for **Intelbras AN-24 Net** alarm systems.

Communicates with the alarm panel over the AMT protocol on the local network via TCP. No cloud dependencies.

## Features

- Arm / disarm / arm stay / panic
- Per-zone binary sensors (open, violated, stay, low battery)
- Energy (AC power) sensor
- PGM output switch
- Per-zone bypass/annulment switches
- Real-time push events for instant status updates
- Repair issues for RF supervision failures and low battery

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
| Host  | Hostname or IP of the proxy server |
| Port  | TCP port (default: 9009) |
| MAC   | Alarm panel MAC address |
| PIN   | Alarm panel PIN code |

## Requirements

- Home Assistant 2024.1+
- Intelbras AN-24 Net alarm panel
- Network connectivity to the panel (via proxy server on port 9009)
