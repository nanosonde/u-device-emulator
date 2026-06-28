from __future__ import annotations

import datetime as dt
import json
import threading
import urllib.error
from pathlib import Path
from typing import Any

from ..devices.base import BaseDevice
from ..state import StateStore


def write_json_line(prefix: str, output_file: str | None, record: dict[str, Any]) -> None:
    line = json.dumps(record, separators=(",", ":"), sort_keys=True)
    print(f"[{prefix}] {line}")
    if output_file:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def device_loop(
    device: BaseDevice,
    stop_event: threading.Event,
    verbose: bool,
    status_summary: bool,
    capture_response: bool,
    capture_file: str | None,
    capture_lock: threading.Lock,
    state_store: StateStore | None = None,
) -> None:
    wait_s = 1
    while not stop_event.is_set():
        if not device.inform_enabled:
            stop_event.wait(1)
            continue
        try:
            wait_s, response_obj = device.inform_once()
            if state_store is not None:
                state_store.update(device.mac, device.state_snapshot())
            if capture_response and response_obj is not None:
                record = {
                    "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "device": device.hostname,
                    "mac": device.mac,
                    "controller": device.controller_url,
                    "response": response_obj,
                }
                with capture_lock:
                    write_json_line("capture", capture_file, record)
            if verbose:
                print(
                    f"[{device.hostname}] informed controller={device.controller_url} "
                    f"adopted={device.adopted} next={wait_s}s"
                )
            if status_summary and device.last_response_summary is not None:
                s = device.last_response_summary
                print(
                    f"[{device.hostname}] status cmd={s['cmd']} "
                    f"authkey_updated={s['authkey_updated']} "
                    f"cfgversion_updated={s['cfgversion_updated']} "
                    f"cfgversion={s.get('cfgversion')} "
                    f"resp_keys={s.get('resp_keys')} "
                    f"mgmt_cfg_applied={s['mgmt_cfg_applied']} "
                    f"locating={s.get('locating')} reboots={s.get('reboot_count')} "
                    f"led={'on' if s.get('led_enabled') else 'off'} "
                    f"name={s.get('device_name') or '-'} "
                    f"jumbo={s.get('jumbo_frames')} flowctrl={s.get('flow_control')} "
                    f"ip={s.get('ip_mode')} "
                    f"ports_cfg={s.get('port_overrides')} "
                    f"mgmt_vlan={s.get('management_vlan')} vlans={s.get('vlans')} "
                    f"inform_url_updated={s['inform_url_updated']} adopted={s['adopted']}"
                )
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and device.aes_mode == "gcm":
                device.gcm_disabled = True
                device.aes_mode = "cbc"
                if state_store is not None:
                    state_store.update(device.mac, device.state_snapshot())
                print(f"[{device.hostname}] controller rejected GCM; falling back to CBC")
                wait_s = 1
                stop_event.wait(wait_s)
                continue
            wait_s = 5 if not device.adopted else max(5, device.interval_seconds)
            print(f"[{device.hostname}] HTTP error: {exc.code}; retry in {wait_s}s")
        except Exception as exc:
            wait_s = 5 if not device.adopted else max(5, device.interval_seconds)
            print(f"[{device.hostname}] inform failed: {exc}; retry in {wait_s}s")

        stop_event.wait(wait_s)
