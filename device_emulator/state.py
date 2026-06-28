from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .utils import bump_mac


def rotate_base_mac(base_mac: str, count: int, pool_size: int, state_file: str) -> tuple[str, int, int]:
    state_path = Path(state_file)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    state: dict[str, Any] = {"next_offset": 0}
    if state_path.exists():
        try:
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                state = loaded
        except Exception:
            pass

    offset = int(state.get("next_offset", 0)) % pool_size
    rotated = bump_mac(base_mac, offset)
    next_offset = (offset + count) % pool_size
    state_path.write_text(json.dumps({"next_offset": next_offset}, indent=2), encoding="utf-8")
    return rotated, offset, next_offset


def truncate_file_if_present(path: str | None) -> None:
    if not path:
        return
    out = Path(path)
    if out.exists():
        out.write_text("", encoding="utf-8")


def parse_mgmt_cfg_lines(mgmt_cfg: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in mgmt_cfg.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


class StateStore:
    def __init__(self, path: str | None) -> None:
        self.path = Path(path) if path else None
        self.lock = threading.Lock()
        self.data: dict[str, Any] = {}
        if self.path and self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
            except (OSError, ValueError) as exc:
                print(f"[state] failed to read {self.path}: {exc}; starting fresh")
                self.data = {}

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def get(self, mac: str) -> dict[str, Any] | None:
        entry = self.data.get(mac)
        return entry if isinstance(entry, dict) else None

    def update(self, mac: str, snapshot: dict[str, Any]) -> None:
        if not self.path:
            return
        with self.lock:
            self.data[mac] = snapshot
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(self.path.suffix + ".tmp")
                tmp.write_text(
                    json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8"
                )
                tmp.replace(self.path)
            except OSError as exc:
                print(f"[state] failed to write {self.path}: {exc}")
