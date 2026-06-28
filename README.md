# u-device-emulator

A Python library and YAML-driven daemon focused exclusively on emulating Ub\*qu\*t\* Un\*F\* devices in lab environments for security investigations and deeper technical understanding.

The project can emulate switch, access point, and gateway profiles, emit discovery traffic, run inform cycles, and publish topology and statistics payloads.

## Quick Start

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
cp config.example.yaml config.yaml
.venv/bin/python device_emulator_daemon.py --config config.yaml --dry-run
```

## Main Components

- `device_emulator_daemon.py`: YAML-driven daemon entry point (primary interface).
- `device_emulator/`: reusable package (protocol, devices, services, state, stats).
- `config.example.yaml`: annotated local example configuration.
- `test/config.test.yaml`: local test-oriented configuration.
- `test/sim_cli.py`: flag-driven simulation harness for ad-hoc testing.
- `test/`: home for all test-only configs, notes, and scripts.

## Package Layout

- `device_emulator/protocol/`: packet framing, crypto, discovery, STUN.
- `device_emulator/devices/`: base, switch, access point, gateway, registry.
- `device_emulator/services/`: discovery, inform, runner, ssh, stun, health.
- `device_emulator/state.py`: persistence helpers.
- `device_emulator/stats.py`: counters and synthetic runtime stats.

The daemon builds device objects from YAML, optionally applies a declared
topology map, starts the service loops from a shared runner, and persists state
snapshots when configured.

## Data Directory Policy

- `data/` is runtime output.
- Generated state/capture files are intentionally ignored.
- Keep only placeholder files in versioned content.

## Documentation

- `doc/DEVICE_PROTOCOL.md`: protocol and payload reference for this implementation.

## Validation

- Importing the package succeeds.
- Daemon `--dry-run` resolves all configured devices.
- CLI simulation starts with expected defaults.
- State file write/read works with the configured path.

## Intended Use

Use only in controlled lab or test environments where you have explicit authorization.
