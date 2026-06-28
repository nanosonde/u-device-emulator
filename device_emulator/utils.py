from __future__ import annotations

import re

from .constants import DEFAULT_AUTHKEY_MODEL_RING


def mac_to_bytes(mac: str) -> bytes:
    cleaned = mac.replace(":", "").replace("-", "").lower()
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC: {mac}")
    return bytes.fromhex(cleaned)


def normalize_mac(mac: str) -> str:
    raw = mac_to_bytes(mac)
    return ":".join(f"{b:02x}" for b in raw)


def bump_mac(base_mac: str, offset: int) -> str:
    value = int(mac_to_bytes(base_mac).hex(), 16)
    next_value = (value + offset) & ((1 << 48) - 1)
    raw = next_value.to_bytes(6, "big")
    return ":".join(f"{b:02x}" for b in raw)


def infer_bootstrap_model_from_mac(mac: str) -> str:
    raw = mac_to_bytes(mac)
    return DEFAULT_AUTHKEY_MODEL_RING[raw[-1] % len(DEFAULT_AUTHKEY_MODEL_RING)]


def infer_device_type_from_model(model: str) -> str:
    m = model.upper()
    if m.startswith(("UGW", "UXG", "UDM", "UDR", "UCG", "UDW")):
        return "gateway"
    if m.startswith("US"):
        return "switch"
    if m.startswith(("U", "BZ")):
        return "access_point"
    return "unknown"


def _version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in re.split(r"[.\-+_]", version.strip()):
        match = re.match(r"\d+", token)
        parts.append(int(match.group()) if match else 0)
    return tuple(parts)
