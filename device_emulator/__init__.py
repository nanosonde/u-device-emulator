from __future__ import annotations

from .constants import (
    DEFAULT_AUTH_KEY,
    DEFAULT_AUTHKEY_MODEL_RING,
    FLAG_AES_GCM,
    FLAG_ENCRYPTED,
    HEADER_SIZE,
    PACKET_MAGIC,
)
from .devices.access_point import AccessPointDevice
from .devices.base import BaseDevice
from .devices.gateway import GatewayDevice
from .devices.registry import create_device
from .devices.switch import SwitchDevice
from .firmware import find_firmware_manifest, resolve_latest_firmware
from .net import infer_local_ip, is_loopback_ip
from .services.runner import EmulationRunner
from .state import StateStore
from .stats import SystemStats, TrafficCounter
from .utils import (
    bump_mac,
    infer_bootstrap_model_from_mac,
    infer_device_type_from_model,
    mac_to_bytes,
    normalize_mac,
)

__version__ = "0.1.0"

__all__ = [
    "AccessPointDevice",
    "BaseDevice",
    "DEFAULT_AUTH_KEY",
    "DEFAULT_AUTHKEY_MODEL_RING",
    "EmulationRunner",
    "FLAG_AES_GCM",
    "FLAG_ENCRYPTED",
    "GatewayDevice",
    "HEADER_SIZE",
    "PACKET_MAGIC",
    "StateStore",
    "SwitchDevice",
    "SystemStats",
    "TrafficCounter",
    "bump_mac",
    "create_device",
    "find_firmware_manifest",
    "infer_bootstrap_model_from_mac",
    "infer_device_type_from_model",
    "infer_local_ip",
    "is_loopback_ip",
    "mac_to_bytes",
    "normalize_mac",
    "resolve_latest_firmware",
]
