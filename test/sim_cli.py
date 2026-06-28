from __future__ import annotations

import argparse
import sys
import urllib.parse
from pathlib import Path

# This simulation CLI lives under test/ but drives the top-level
# `device_emulator` package. Ensure the repo root is importable when the script
# is run directly by path (e.g. `python test/sim_cli.py`) without an editable
# install on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from device_emulator import (
    DEFAULT_AUTH_KEY,
    create_device,
    find_firmware_manifest,
    resolve_latest_firmware,
    infer_bootstrap_model_from_mac,
    infer_local_ip,
    is_loopback_ip,
    normalize_mac,
    bump_mac,
)
from device_emulator.services.runner import EmulationRunner
from device_emulator.state import rotate_base_mac, truncate_file_if_present, StateStore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Test harness: simulate multiple network devices by posting binary "
            "encrypted /inform packets. For declarative lab setups use "
            "device_emulator_daemon.py with a YAML config instead."
        )
    )
    parser.add_argument("--controller-url", default="http://127.0.0.1:8080/inform")
    parser.add_argument(
        "--device-ip",
        default=None,
        help="Advertised device IPv4 address (defaults to auto-detected non-loopback local IP)",
    )
    parser.add_argument(
        "--allow-loopback-ip",
        action="store_true",
        help="Allow advertising 127.x.x.x device IPs (disabled by default)",
    )
    parser.add_argument(
        "--profile",
        choices=["managed", "adoptable-reset", "adoptable-handshake"],
        default="managed",
        help="Simulation profile preset",
    )
    parser.add_argument("--count", type=int, default=3, help="Number of virtual devices")
    parser.add_argument("--base-mac", default="02:15:6d:00:00:10", help="First device MAC")
    parser.add_argument("--model", default="US24", help="network device model string")
    parser.add_argument(
        "--firmware",
        default="6.6.61.14919",
        help="Reported firmware version, or 'auto' to use the controller's latest "
        "for the model (avoids the 'update available' flag)",
    )
    parser.add_argument(
        "--firmware-manifest",
        default=None,
        help="Path to the controller's firmware.json (auto-detected if omitted; "
        "used when --firmware auto)",
    )
    parser.add_argument(
        "--firmware-channel",
        default="release",
        help="Firmware channel to match when --firmware auto (default: release)",
    )
    parser.add_argument("--auth-key", default=DEFAULT_AUTH_KEY, help="32-hex auth key")
    parser.add_argument("--aes-mode", choices=["cbc", "gcm"], default="cbc")
    parser.add_argument("--interval", type=int, default=30, help="Initial inform interval in seconds")
    parser.add_argument(
        "--disable-inform",
        action="store_true",
        help="Disable /inform traffic and only simulate discovery",
    )
    parser.add_argument("--capture-response", action="store_true", help="Print decoded controller commands")
    parser.add_argument(
        "--capture-file",
        default=None,
        help="Optional NDJSON file path for decoded controller responses",
    )
    parser.add_argument(
        "--discovery-mode",
        choices=["off", "listen", "announce", "both"],
        default="off",
        help="Enable UDP discovery on port 10001",
    )
    parser.add_argument("--discovery-port", type=int, default=10001)
    parser.add_argument("--discovery-target", default="255.255.255.255")
    parser.add_argument(
        "--discovery-bind-ip",
        default=None,
        help="Source IP to bind discovery announcements to (defaults to the device IP)",
    )
    parser.add_argument("--discovery-interval", type=int, default=10)
    parser.add_argument(
        "--discovery-packet-type",
        type=lambda x: int(x, 0),
        default=0x06,
        help="Discovery packet type to emit (e.g. 0x02 for reset-style, 0x06 managed-style)",
    )
    parser.add_argument(
        "--simulate-reset",
        action="store_true",
        help="Preset reset-like discovery behavior (packet type 0x02, disables inform)",
    )
    parser.add_argument(
        "--discovery-sniff",
        action="store_true",
        help="Log raw UDP discovery packets as hex (rx/tx)",
    )
    parser.add_argument(
        "--discovery-sniff-file",
        default=None,
        help="Optional NDJSON file path for discovery packet records",
    )
    parser.add_argument(
        "--status-summary",
        action="store_true",
        help="Print compact per-cycle handshake status (cmd/authkey/cfgversion/adopted)",
    )
    parser.add_argument(
        "--cleanup-mode",
        action="store_true",
        help="Rotate MAC base across a bounded pool for predictable test runs",
    )
    parser.add_argument(
        "--cleanup-mac-pool-size",
        type=int,
        default=64,
        help="Total MAC slots used by cleanup rotation",
    )
    parser.add_argument(
        "--cleanup-state-file",
        default="data/simulator_cleanup_state.json",
        help="State file used to remember next cleanup MAC offset",
    )
    parser.add_argument(
        "--cleanup-truncate-capture",
        action="store_true",
        help="Clear capture/sniff output files at startup when cleanup mode is enabled",
    )
    parser.add_argument(
        "--state-file",
        default="data/device_state.json",
        help="JSON file used to persist adopted device state (auth key, GCM mode, "
        "cfgversion, uptime, etc.) so a device can be reused across restarts",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Disable persisting/restoring device state across simulator restarts",
    )
    parser.add_argument(
        "--post-adopt-keepalive",
        action="store_true",
        help="After adoption, inform more frequently to reduce Adopting/Offline flaps",
    )
    parser.add_argument(
        "--post-adopt-interval",
        type=int,
        default=10,
        help="Inform interval in seconds when post-adopt keepalive is enabled",
    )
    parser.add_argument(
        "--emulate-ssh",
        action="store_true",
        help="Run a minimal SSH server for controller post-adopt reachability checks",
    )
    parser.add_argument(
        "--ssh-bind-ip",
        default="0.0.0.0",
        help="Bind IP for SSH emulation server",
    )
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-user", default="device")
    parser.add_argument("--ssh-password", default="device")
    parser.add_argument(
        "--emulate-health-probes",
        action="store_true",
        help="Expose simple TCP/HTTP probe endpoints for post-adopt controller checks",
    )
    parser.add_argument(
        "--health-bind-ip",
        default="0.0.0.0",
        help="Bind IP for health probe listeners",
    )
    parser.add_argument(
        "--health-ports",
        default="80,8080,443",
        help="Comma-separated TCP ports for health probe listeners",
    )
    parser.add_argument(
        "--emulate-stun",
        action="store_true",
        help="Send periodic STUN binding requests to controller stun_url after adoption",
    )
    parser.add_argument(
        "--stun-interval",
        type=int,
        default=10,
        help="Seconds between STUN binding requests",
    )
    parser.add_argument(
        "--emulate-stun-server",
        action="store_true",
        help="Run a minimal STUN binding responder on the configured STUN port",
    )
    parser.add_argument(
        "--stun-server-bind-ip",
        default="127.0.0.1",
        help="Bind IP for STUN responder",
    )
    parser.add_argument(
        "--stun-server-port",
        type=int,
        default=3478,
        help="UDP port for STUN responder",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if len(args.auth_key) != 32:
        raise SystemExit("--auth-key must be 32 hex chars")

    if args.simulate_reset:
        args.discovery_packet_type = 0x02
        args.disable_inform = True

    if args.profile == "adoptable-reset":
        args.discovery_packet_type = 0x02
        args.disable_inform = True
    elif args.profile == "adoptable-handshake":
        args.discovery_packet_type = 0x02
        args.disable_inform = False
        args.status_summary = True
        args.post_adopt_keepalive = True
        args.emulate_stun = True
        args.emulate_stun_server = True
        if args.discovery_mode == "off":
            args.discovery_mode = "both"

    if args.cleanup_mode:
        if args.cleanup_mac_pool_size < args.count:
            raise SystemExit("--cleanup-mac-pool-size must be >= --count")
        rotated_base, offset, next_offset = rotate_base_mac(
            args.base_mac,
            args.count,
            args.cleanup_mac_pool_size,
            args.cleanup_state_file,
        )
        print(
            f"[cleanup] rotated base-mac {args.base_mac} -> {rotated_base} "
            f"(offset={offset}, next_offset={next_offset}, pool={args.cleanup_mac_pool_size})"
        )
        args.base_mac = rotated_base
        if args.cleanup_truncate_capture:
            truncate_file_if_present(args.capture_file)
            truncate_file_if_present(args.discovery_sniff_file)

    controller_host = urllib.parse.urlparse(args.controller_url).hostname or "127.0.0.1"
    local_ip = args.device_ip or infer_local_ip(controller_host)
    if is_loopback_ip(local_ip) and not args.allow_loopback_ip:
        raise SystemExit(
            "Refusing loopback device IP. Use --device-ip <LAN IP> or --allow-loopback-ip for test-only loopback mode."
        )

    if args.firmware == "auto":
        manifest = args.firmware_manifest or find_firmware_manifest()
        resolved = None
        if manifest:
            try:
                resolved = resolve_latest_firmware(manifest, args.model, args.firmware_channel)
            except Exception as exc:
                print(f"[firmware] failed to read manifest {manifest}: {exc}")
        else:
            print("[firmware] no firmware.json manifest found; use --firmware-manifest <path>")
        if resolved:
            print(f"[firmware] reporting latest {args.model} firmware {resolved} (from {manifest})")
            args.firmware = resolved
        else:
            fallback = "6.6.61.14919"
            print(f"[firmware] could not resolve latest for {args.model}; falling back to {fallback}")
            args.firmware = fallback

    state_store = StateStore(None if args.no_persist else args.state_file)
    if state_store.enabled:
        print(f"[state] persisting device state to {args.state_file}")

    devices = []
    for i in range(args.count):
        mac = bump_mac(args.base_mac, i)
        normalized_mac = normalize_mac(mac)
        bootstrap_model = infer_bootstrap_model_from_mac(normalized_mac)
        dev = create_device(
            index=i + 1,
            mac=normalized_mac,
            model=args.model,
            firmware=args.firmware,
            controller_url=args.controller_url,
            auth_key=args.auth_key.lower(),
            aes_mode=args.aes_mode,
            interval_seconds=max(1, args.interval),
            local_ip=local_ip,
            handshake_mode=(args.profile == "adoptable-handshake"),
            post_adopt_keepalive=args.post_adopt_keepalive,
            post_adopt_interval=max(1, args.post_adopt_interval),
            inform_enabled=(not args.disable_inform),
            bootstrap_model=bootstrap_model,
        )
        saved = state_store.get(normalized_mac)
        if saved:
            dev.restore_state(saved)
            print(
                f"[state] restored {dev.hostname} mac={dev.mac} "
                f"adopted={dev.adopted} aes={dev.aes_mode} "
                f"cfgversion={dev.cfgversion or '-'} uptime={dev.uptime()}s"
            )
        devices.append(dev)

    print(f"Starting {len(devices)} fake network device(s) -> {args.controller_url}")
    for dev in devices:
        print(f"  - {dev.hostname} mac={dev.mac} model={dev.model} ip={dev.local_ip}")

    runner = EmulationRunner(
        devices=devices,
        state_store=state_store,
        verbose=args.verbose,
        status_summary=args.status_summary,
        capture_response=args.capture_response,
        capture_file=args.capture_file,
        discovery_mode=args.discovery_mode,
        discovery_port=args.discovery_port,
        discovery_target=args.discovery_target,
        discovery_bind_ip=args.discovery_bind_ip or (local_ip if not is_loopback_ip(local_ip) else None),
        discovery_interval=args.discovery_interval,
        discovery_packet_type=args.discovery_packet_type,
        discovery_sniff=args.discovery_sniff,
        discovery_sniff_file=args.discovery_sniff_file,
        ssh_enabled=args.emulate_ssh,
        ssh_bind_ip=args.ssh_bind_ip,
        ssh_port=args.ssh_port,
        ssh_user=args.ssh_user,
        ssh_password=args.ssh_password,
        stun_enabled=args.emulate_stun,
        stun_interval=args.stun_interval,
        stun_server_enabled=args.emulate_stun_server,
        stun_server_bind_ip=args.stun_server_bind_ip,
        stun_server_port=args.stun_server_port,
        health_enabled=args.emulate_health_probes,
        health_bind_ip=args.health_bind_ip,
        health_ports=args.health_ports,
    )
    runner.start()
    runner.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
