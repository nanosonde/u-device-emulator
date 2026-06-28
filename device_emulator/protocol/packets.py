from __future__ import annotations

import json
import random
import struct
from typing import Any

from Crypto.Cipher import AES

from ..constants import (
    DATA_VERSION,
    FLAG_AES_GCM,
    FLAG_ENCRYPTED,
    HEADER_SIZE,
    HEADER_VERSION,
    PACKET_MAGIC,
)
from ..utils import mac_to_bytes
from .crypto import decrypt_payload, pad_pkcs7


def build_packet(payload_obj: dict[str, Any], mac: str, key_hex: str, aes_mode: str = "cbc") -> bytes:
    mac_bytes = mac_to_bytes(mac)
    iv = random.getrandbits(128).to_bytes(16, "big")
    plain = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")

    flags = FLAG_ENCRYPTED
    if aes_mode == "gcm":
        flags |= FLAG_AES_GCM
        data_len = len(plain) + 16
        header = struct.pack(
            ">II6sH16sII",
            PACKET_MAGIC,
            HEADER_VERSION,
            mac_bytes,
            flags,
            iv,
            DATA_VERSION,
            data_len,
        )
        cipher = AES.new(bytes.fromhex(key_hex), AES.MODE_GCM, nonce=iv)
        cipher.update(header)
        encrypted, tag = cipher.encrypt_and_digest(plain)
        return header + encrypted + tag
    else:
        cipher = AES.new(bytes.fromhex(key_hex), AES.MODE_CBC, iv)
        data = cipher.encrypt(pad_pkcs7(plain))

    header = struct.pack(
        ">II6sH16sII",
        PACKET_MAGIC,
        HEADER_VERSION,
        mac_bytes,
        flags,
        iv,
        DATA_VERSION,
        len(data),
    )
    return header + data


def parse_packet(raw: bytes, key_hex: str) -> dict[str, Any]:
    if len(raw) < HEADER_SIZE:
        raise ValueError("Response too short")

    magic, _header_version, mac_bytes, flags, iv, data_version, data_len = struct.unpack(
        ">II6sH16sII", raw[:HEADER_SIZE]
    )
    if magic != PACKET_MAGIC:
        raise ValueError(f"Bad magic: 0x{magic:08x}")
    if data_version != DATA_VERSION:
        raise ValueError(f"Unsupported data version: {data_version}")
    if len(raw) < HEADER_SIZE + data_len:
        raise ValueError("Truncated response payload")

    payload = raw[HEADER_SIZE : HEADER_SIZE + data_len]
    plain = decrypt_payload(flags, mac_bytes, iv, key_hex, payload, aad=raw[:HEADER_SIZE])
    return json.loads(plain.decode("utf-8"))
