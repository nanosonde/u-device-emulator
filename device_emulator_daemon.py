from __future__ import annotations

import argparse
import signal
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required for the daemon. Install it with: pip install pyyaml")

from device_emulator import (
    DEFAULT_AUTH_KEY,
    EmulationRunner,
    StateStore,
    bump_mac,
    create_device,
    find_firmware_manifest,
    infer_bootstrap_model_from_mac,
    infer_local_ip,
    normalize_mac,
    resolve_latest_firmware,
)
from device_emulator.net import is_loopback_ip


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_devices(config: dict) -> tuple[list, StateStore]:
    controller_url = config.get("controller_url", "http://127.0.0.1:8080/inform")
    defaults = config.get("defaults", {})
    device_ip = defaults.get("device_ip", "auto")
    default_interval = defaults.get("interval", 30)
    default_aes_mode = defaults.get("aes_mode", "cbc")
    default_firmware = defaults.get("firmware", "6.6.61.14919")
    post_adopt_keepalive = defaults.get("post_adopt_keepalive", True)
    post_adopt_interval = defaults.get("post_adopt_interval", 10)

    state_file = config.get("state_file", "data/device_state.json")
    persist = config.get("persist", True)
    state_store = StateStore(state_file if persist else None)

    if state_store.enabled:
        print(f"[state] persisting device state to {state_file}")

    devices = []
    raw_devices = config.get("devices", [])
    host = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(controller_url).hostname or "127.0.0.1"
    resolved_local_ip = None

    for i, entry in enumerate(raw_devices):
        mac = normalize_mac(entry.get("mac") or bump_mac("02:15:6d:00:00:10", i))
        model = entry.get("model", "US24")
        device_name = entry.get("name")

        firmware = entry.get("firmware") or default_firmware
        if firmware == "auto":
            manifest = find_firmware_manifest()
            resolved = None
            if manifest:
                try:
                    resolved = resolve_latest_firmware(manifest, model)
                except Exception:
                    pass
            firmware = resolved or "6.6.61.14919"

        if device_ip == "auto":
            if resolved_local_ip is None:
                resolved_local_ip = infer_local_ip(host)
            local_ip = resolved_local_ip
        else:
            local_ip = device_ip

        if is_loopback_ip(local_ip) and not entry.get("allow_loopback_ip"):
            print(f"[warn] device {device_name or mac}: loopback IP {local_ip}")

        interval = entry.get("interval") or default_interval
        aes_mode = entry.get("aes_mode") or default_aes_mode

        dev = create_device(
            index=i + 1,
            mac=mac,
            model=model,
            firmware=firmware,
            controller_url=controller_url,
            auth_key=entry.get("auth_key", DEFAULT_AUTH_KEY).lower(),
            aes_mode=aes_mode,
            interval_seconds=max(1, int(interval)),
            local_ip=local_ip,
            device_type=entry.get("type", "auto"),
            handshake_mode=entry.get("handshake_mode", False),
            post_adopt_keepalive=entry.get("post_adopt_keepalive", post_adopt_keepalive),
            post_adopt_interval=max(1, int(entry.get("post_adopt_interval", post_adopt_interval))),
            inform_enabled=entry.get("inform_enabled", True),
            bootstrap_model=infer_bootstrap_model_from_mac(mac),
        )
        saved = state_store.get(mac)
        if saved:
            dev.restore_state(saved)
            print(
                f"[state] restored {dev.hostname} mac={dev.mac} "
                f"adopted={dev.adopted} aes={dev.aes_mode} "
                f"cfgversion={dev.cfgversion or '-'} uptime={dev.uptime()}s"
            )
        if device_name:
            dev.device_name = device_name
        devices.append(dev)

    return devices, state_store


def apply_topology(config: dict, devices: list) -> None:
    """Resolve the `topology` config section and call apply_topology() on devices.

    Each entry in `topology` declares that a device is connected *upward*
    to another device on a specific port:

      topology:
        - device: lab-switch-01
          uplink_device: lab-gw-01
          uplink_port: 1        # port index on the parent (LAN port on GW)
          local_port: 1         # our own port that faces the parent (optional)
        - device: lab-ap-01
          uplink_device: lab-switch-01
          uplink_port: 5        # port on the switch where the AP connects

    For each child this produces the three signals the controller correlates
    into a topology link (see doc/DEVICE_PROTOCOL.md §5.7 — the controller
    trusts the device's self-reported data, no on-the-wire LLDP):

      * an `lldp_table` neighbor entry pointing at the parent (on the child's
        local port), and the reverse entry on the parent,
      * the child's top-level `uplink` port-name string + a matching `if_table`
        entry carrying `uplink_mac` (built in `devices/base.py`), and
      * a `downlink_table` on each parent (inverting the uplink relationships).
    """
    topo_entries = config.get("topology", [])
    if not topo_entries:
        return

    # Build a name→device and mac→device lookup
    by_name: dict[str, object] = {}
    by_mac: dict[str, object] = {}
    for dev in devices:
        by_mac[dev.mac] = dev
        name = getattr(dev, "device_name", "") or ""
        if name:
            by_name[name] = dev

    def _resolve(ref: str):
        """Resolve a device name or MAC string to a device object."""
        if ref in by_name:
            return by_name[ref]
        try:
            from device_emulator import normalize_mac
            norm = normalize_mac(ref)
            return by_mac.get(norm)
        except Exception:
            return by_mac.get(ref)

    # Accumulate, per device, everything we need to apply once at the end:
    #   uplink:   {uplink_mac, uplink_remote_port, uplink_local_port}
    #   downlinks: [{mac, port_idx}, ...]
    #   lldp:     [{chassis_id, local_port_idx, port_id, is_wired}, ...]
    # The controller's wiredLldpProcessor reads lldp_table[*].chassis_id (the
    # neighbor MAC) and local_port_idx (our port) and builds the tree.
    uplinks: dict[str, dict] = {}
    downlinks: dict[str, list[dict]] = {}
    lldp: dict[str, list[dict]] = {}

    def _port_ifname(dev, port_idx: int) -> str:
        """Best-effort interface name for a port on a device (for port_id)."""
        dtype = getattr(dev, "device_type", "")
        if dtype == "access_point":
            return "eth0"
        return f"eth{port_idx}" if port_idx else "eth0"

    for entry in topo_entries:
        child_ref = entry.get("device", "")
        parent_ref = entry.get("uplink_device", "")
        if not child_ref or not parent_ref:
            print(f"[topology] skipping incomplete entry: {entry}")
            continue

        child = _resolve(child_ref)
        parent = _resolve(parent_ref)
        if child is None:
            print(f"[topology] device not found: {child_ref!r}")
            continue
        if parent is None:
            print(f"[topology] uplink_device not found: {parent_ref!r}")
            continue

        uplink_port = int(entry.get("uplink_port", 0))   # port on the PARENT
        local_port = int(entry.get("local_port", 0))     # port on the CHILD

        # Child's uplink → parent
        uplinks[child.mac] = {
            "uplink_mac": parent.mac,
            "uplink_remote_port": uplink_port,
            "uplink_local_port": local_port,
        }
        # Parent's downlink_table gets the child (on the parent's port)
        downlinks.setdefault(parent.mac, []).append({
            "mac": child.mac,
            "port_idx": uplink_port,
        })

        # LLDP neighbor entries (both directions):
        #  - child sees parent on the child's local_port
        lldp.setdefault(child.mac, []).append({
            "chassis_id":     parent.mac,
            "local_port_idx": local_port,
            "port_id":        _port_ifname(parent, uplink_port),
            "chassis_descr":  parent.device_name or parent.mac,
            "is_wired":       True,
        })
        #  - parent sees child on the parent's uplink_port
        lldp.setdefault(parent.mac, []).append({
            "chassis_id":     child.mac,
            "local_port_idx": uplink_port,
            "port_id":        _port_ifname(child, local_port),
            "chassis_descr":  child.device_name or child.mac,
            "is_wired":       True,
        })

        print(
            f"[topology] {child.device_name or child.mac} "
            f"→ {parent.device_name or parent.mac} "
            f"port {uplink_port}"
            + (f" (local port {local_port})" if local_port else "")
        )

    # Apply once per device with the complete picture
    all_macs = set(uplinks) | set(downlinks) | set(lldp)
    for mac in all_macs:
        dev = by_mac.get(mac)
        if dev is None:
            continue
        up = uplinks.get(mac, {})
        dl = list({e["mac"]: e for e in downlinks.get(mac, [])}.values())
        nb = lldp.get(mac, [])
        dev.apply_topology(
            uplink_mac=up.get("uplink_mac", ""),
            uplink_remote_port=up.get("uplink_remote_port", 0),
            uplink_local_port=up.get("uplink_local_port", 0),
            downlink_table=dl,
            lldp_neighbors=nb,
            uplink_type=up.get("uplink_type", "wire"),
        )
        neigh = ", ".join(f"{n['chassis_id']}@p{n['local_port_idx']}" for n in nb)
        print(f"[topology] {dev.device_name or dev.mac} lldp_table: [{neigh}]")


def build_runner(config: dict, devices: list, state_store: StateStore) -> EmulationRunner:
    svc = config.get("services", {})
    # Default the discovery source to the device's own IP so broadcast announces
    # leave via the interface that faces the controller, not the host's default
    # broadcast NIC.
    default_bind_ip = None
    for dev in devices:
        if dev.local_ip and not is_loopback_ip(dev.local_ip):
            default_bind_ip = dev.local_ip
            break
    return EmulationRunner(
        devices=devices,
        state_store=state_store,
        verbose=config.get("verbose", False),
        discovery_mode=svc.get("discovery", "off"),
        discovery_port=svc.get("discovery_port", 10001),
        discovery_target=svc.get("discovery_target", "255.255.255.255"),
        discovery_bind_ip=svc.get("discovery_bind_ip", default_bind_ip),
        discovery_interval=svc.get("discovery_interval", 10),
        discovery_packet_type=svc.get("discovery_packet_type", 0x06),
        discovery_sniff=svc.get("discovery_sniff", False),
        discovery_sniff_file=svc.get("discovery_sniff_file"),
        ssh_enabled=svc.get("ssh", False),
        ssh_bind_ip=svc.get("ssh_bind_ip", "0.0.0.0"),
        ssh_port=svc.get("ssh_port", 22),
        ssh_user=svc.get("ssh_user", "device"),
        ssh_password=svc.get("ssh_password", "device"),
        stun_enabled=svc.get("stun", False),
        stun_interval=svc.get("stun_interval", 10),
        stun_server_enabled=svc.get("stun_server", False),
        stun_server_bind_ip=svc.get("stun_server_bind_ip", "127.0.0.1"),
        stun_server_port=svc.get("stun_server_port", 3478),
        health_enabled=svc.get("health", False),
        health_bind_ip=svc.get("health_bind_ip", "0.0.0.0"),
        health_ports=svc.get("health_ports", "80,8080,443"),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="YAML-driven network device emulation daemon")
    parser.add_argument("--config", "-c", required=True, help="Path to YAML config file")
    parser.add_argument("--dry-run", action="store_true", help="Parse config and print resolved devices, then exit")
    args = parser.parse_args()

    config = load_config(args.config)
    devices, state_store = build_devices(config)
    apply_topology(config, devices)

    print(f"Resolved {len(devices)} device(s) -> {config.get('controller_url', 'http://127.0.0.1:8080/inform')}")
    for dev in devices:
        print(f"  - {dev.hostname} mac={dev.mac} model={dev.model} type={dev.device_type} ip={dev.local_ip}")

    if args.dry_run:
        return 0

    runner = build_runner(config, devices, state_store)
    runner.start()

    stop = runner.stop_event

    def _signal_handler(sig, frame):
        stop.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    while not stop.is_set():
        stop.wait(1)

    runner.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
