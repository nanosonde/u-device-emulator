from __future__ import annotations

from typing import Any

from ..utils import infer_device_type_from_model
from .access_point import AccessPointDevice
from .base import BaseDevice
from .gateway import GatewayDevice
from .switch import SwitchDevice


_TYPE_MAP = {
    "switch": SwitchDevice,
    "access_point": AccessPointDevice,
    "gateway": GatewayDevice,
    "switch": SwitchDevice,
    "access_point": AccessPointDevice,
    "gateway": GatewayDevice,
}


def _device_class_for_type(device_type: str) -> type[BaseDevice]:
    cls = _TYPE_MAP.get(device_type)
    if cls is None:
        raise ValueError(f"Unknown device type: {device_type!r}")
    return cls


def create_device(
    *,
    index: int,
    mac: str,
    model: str,
    firmware: str,
    controller_url: str,
    auth_key: str,
    aes_mode: str = "cbc",
    interval_seconds: int = 30,
    local_ip: str,
    device_type: str | None = None,
    handshake_mode: bool = False,
    post_adopt_keepalive: bool = False,
    post_adopt_interval: int = 10,
    inform_enabled: bool = True,
    bootstrap_model: str | None = None,
) -> BaseDevice:
    if device_type and device_type != "auto":
        cls = _device_class_for_type(device_type)
    else:
        inferred = infer_device_type_from_model(model)
        cls = _TYPE_MAP.get(inferred, BaseDevice)

    return cls(
        index=index,
        mac=mac,
        model=model,
        firmware=firmware,
        controller_url=controller_url,
        auth_key=auth_key,
        aes_mode=aes_mode,
        interval_seconds=interval_seconds,
        local_ip=local_ip,
        handshake_mode=handshake_mode,
        post_adopt_keepalive=post_adopt_keepalive,
        post_adopt_interval=post_adopt_interval,
        inform_enabled=inform_enabled,
        bootstrap_model=bootstrap_model,
    )
