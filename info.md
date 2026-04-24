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

## Configuration

Go to **Settings** > **Devices & Services** > **Add Integration** > **Alarme Intelbras**.

You will need:

| Field | Description |
|-------|-------------|
| Host  | Hostname or IP of the proxy server |
| Port  | TCP port (default: 9009) |
| MAC   | Alarm panel MAC address |
| PIN   | Alarm panel PIN code |
