# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Assistant custom integration for **Intelbras AN-24 Net** alarm systems. Communicates with the alarm panel over a custom TCP protocol (AMT protocol) on the local network. Zero external runtime dependencies — uses only Home Assistant core.

- Domain: `intelbras`
- IoT class: `cloud_polling` (TCP via proxy server)
- Config flow only (no YAML configuration)
- HACS-compatible

## Development Commands

```bash
uv sync                                    # Install dependencies
uv run pyright custom_components/intelbras  # Type check (strict mode)
uv run ruff check custom_components/intelbras  # Lint
```

No test suite exists.

## Architecture

### Data Flow

```
ConfigFlow → ClientAMT(host, port, mac, pin) → background TCP task
                                                       ↓
AMTCoordinator (polls every 5s via client.status())
         ↓
    Entity platforms read from coordinator.data
```

### Key Layers

**`protocol.py`** — AMT protocol implementation. Handles TCP framing, XOR encryption, checksum validation, and command serialization. Defines `ClientAMT` which manages the async TCP connection with queue-based send/receive. All alarm operations (arm, disarm, panic, PGM, bypass, status) go through this class. Error types: `ChecksumError`, `OpenZoneError`, `WrongPasswordError`.

**`coordinator.py`** — Standard HA `DataUpdateCoordinator`. Fetches device names/zone labels on first refresh, then polls `client.status()` every 5 seconds.

**`config_flow.py`** — Collects host, port, MAC, and PIN. Validates by attempting a `client.sync()` call.

### Entity Platforms

- **`alarm_control_panel.py`** — Single alarm entity. Maps partition state to HA alarm states (disarmed/armed_away/armed_home/triggered). Stay-zone detection enables armed_home mode.
- **`binary_sensor.py`** — Energy sensor (power status) + per-zone sensors (open, violated, stay, low_battery). Dynamically creates entities only for enabled zones.
- **`switch.py`** — PGM output control + per-zone annulment/bypass switches. Dynamically created for enabled zones.

## Protocol Reference

See [`protocol.md`](protocol.md) for the full AMT protocol documentation including frame format, command codes, status parsing, sync/names, event log ring buffer, and Contact ID decoding.

## Publishing a Release

1. Bump the version in `manifest.json`
2. Commit with the version number as the message (e.g. `0.1.16`)
3. Push, tag, and create a GitHub release:

```bash
git push
git tag <version>
git push origin <version>
gh release create <version> --title "<version>" --generate-notes
```

## Conventions

- Python 3.14.2+, strict Pyright type checking
- Follows Home Assistant integration patterns (config flow, coordinator, entity platforms)
- Translations in `translations/` (en, pt-BR); master keys in `strings.json`
- Version tracked in `manifest.json`
