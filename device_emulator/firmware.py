from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .utils import _version_tuple


def find_firmware_manifest() -> str | None:
    candidates = [
        Path.home() / "network" / "data" / "firmware.json",
        Path("/usr/lib/network-controller/data/firmware.json"),
        Path("/var/lib/network-controller/data/firmware.json"),
        Path("/var/lib/network-controller/firmware.json"),
        Path("/usr/lib/network-controller/firmware.json"),
        Path("/opt/network/data/firmware.json"),
    ]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return None


def resolve_latest_firmware(manifest_path: str, model: str, channel: str = "release") -> str | None:
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None

    model_keys = [model.strip(), model.strip().upper()]
    best: tuple[tuple[int, ...], str] | None = None

    def consider(channel_node: Any) -> None:
        nonlocal best
        if not isinstance(channel_node, dict):
            return
        entry = None
        for key in model_keys:
            if key in channel_node:
                entry = channel_node[key]
                break
        if isinstance(entry, dict) and isinstance(entry.get("version"), str):
            version = entry["version"]
            vt = _version_tuple(version)
            if best is None or vt > best[0]:
                best = (vt, version)

    for ctrl_version, node in data.items():
        if not isinstance(node, dict):
            continue
        if channel in node:
            consider(node[channel])
        else:
            for channel_node in node.values():
                consider(channel_node)

    return best[1] if best else None
