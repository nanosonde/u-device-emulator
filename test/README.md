# Test Guide

This folder contains local testing assets.

## Files

- `config.test.yaml`: test-oriented daemon configuration.
- `sim_cli.py`: flag-driven simulation harness for ad-hoc/manual testing (drives
  the `device_emulator` package directly; the daemon is the primary interface).

## Quick Validation

Run these commands from the repository root.

1. Daemon dry-run:

```bash
.venv/bin/python device_emulator_daemon.py --config test/config.test.yaml --dry-run
```

2. CLI help smoke test:

```bash
.venv/bin/python test/sim_cli.py --help
```

3. Installed entrypoint smoke test (after `pip install -e .`):

```bash
.venv/bin/device-emulator-daemon --config test/config.test.yaml --dry-run
```

## Manual simulation harness (`sim_cli.py`)

For quick, flag-driven runs without writing YAML (e.g. N identical devices, reset
simulation, or controller-DB cleanup via MAC-pool rotation):

```bash
.venv/bin/python test/sim_cli.py \
  --controller-url http://192.168.56.1:8080/inform \
  --device-ip 192.168.56.3 --discovery-mode both \
  --profile adoptable-handshake --count 3 --model US24
```

Run from the repository root. The script bootstraps the repo root onto
`sys.path`, so it works with or without an editable install.

## Notes

- Runtime state files are written under `data/` and should remain untracked.
- If pytest is installed, you can run `pytest -q`, but there are currently no formal test cases in this repository.
