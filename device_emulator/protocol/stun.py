from __future__ import annotations

import random
import socket
import struct
import urllib.parse

from ..constants import STUN_MAGIC_COOKIE


def parse_stun_target(stun_url: str) -> tuple[str, int] | None:
    parsed = urllib.parse.urlparse(stun_url)
    if parsed.scheme != "stun":
        return None
    if not parsed.hostname:
        return None
    return parsed.hostname, parsed.port or 3478


def build_stun_binding_request(device_mac: str | None = None) -> bytes:
    tx_id = random.randbytes(12) if hasattr(random, "randbytes") else random.getrandbits(96).to_bytes(12, "big")
    attrs = b""
    if device_mac:
        sw = f"network/{device_mac}".encode("utf-8")
        pad = (4 - len(sw) % 4) % 4
        attrs += struct.pack(">HH", 0x8022, len(sw)) + sw + b"\x00" * pad
    attrs += struct.pack(">HHBBBB", 0x0003, 4, 0, 0, 0, 0)
    msg_len = len(attrs)
    return struct.pack(">HHI12s", 0x0001, msg_len, STUN_MAGIC_COOKIE, tx_id) + attrs


def build_stun_binding_response(request: bytes, source_ip: str, source_port: int) -> bytes | None:
    if len(request) < 20:
        return None
    msg_type, _msg_len, cookie, tx_id = struct.unpack(">HHI12s", request[:20])
    if msg_type != 0x0001 or cookie != STUN_MAGIC_COOKIE:
        return None

    try:
        family = 0x01
        port_xor = source_port ^ (STUN_MAGIC_COOKIE >> 16)
        ip_bytes = socket.inet_aton(source_ip)
        cookie_bytes = struct.pack(">I", STUN_MAGIC_COOKIE)
        addr_xor = bytes(a ^ b for a, b in zip(ip_bytes, cookie_bytes))
        attr_value = struct.pack(">BBH4s", 0, family, port_xor, addr_xor)
    except OSError:
        return None

    attr = struct.pack(">HH", 0x0020, len(attr_value)) + attr_value
    header = struct.pack(">HHI12s", 0x0101, len(attr), STUN_MAGIC_COOKIE, tx_id)
    return header + attr
