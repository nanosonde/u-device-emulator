from __future__ import annotations

import socket
import struct
from typing import Any

from ..utils import mac_to_bytes


def build_discovery_tlv_field(field_type: int, value: bytes) -> bytes:
    return struct.pack(">BH", field_type & 0xFF, len(value)) + value


def build_discovery_payload(device: Any, packet_type: int) -> bytes:
    tlvs = b"".join(
        [
            build_discovery_tlv_field(0x01, mac_to_bytes(device.mac)),
            build_discovery_tlv_field(0x02, socket.inet_aton(device.local_ip)),
            build_discovery_tlv_field(0x03, device.firmware.encode("utf-8")),
            build_discovery_tlv_field(0x0A, device.hostname.encode("utf-8")),
            build_discovery_tlv_field(0x0B, device.model.encode("utf-8")),
            build_discovery_tlv_field(0x0C, device.serial.encode("utf-8")),
        ]
    )
    return struct.pack(">BBH", packet_type & 0xFF, 0x00, len(tlvs)) + tlvs


def decode_discovery_tlvs(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "packet_type": None,
        "flags": None,
        "tlv_len": None,
        "fields": {},
        "raw_fields": [],
        "parse_error": None,
    }
    if len(data) < 4:
        result["parse_error"] = "packet too short"
        return result

    packet_type, flags, total_len = struct.unpack(">BBH", data[:4])
    result["packet_type"] = packet_type
    result["flags"] = flags
    result["tlv_len"] = total_len

    pos = 4
    end = min(len(data), 4 + total_len)
    fields: dict[str, Any] = {}

    while pos + 3 <= end:
        field_type = data[pos]
        field_len = struct.unpack(">H", data[pos + 1 : pos + 3])[0]
        pos += 3
        if pos + field_len > end:
            result["parse_error"] = "truncated tlv field"
            break

        value = data[pos : pos + field_len]
        pos += field_len

        decoded: Any
        if field_type == 0x01 and field_len == 6:
            decoded = ":".join(f"{b:02x}" for b in value)
            fields["mac"] = decoded
        elif field_type == 0x02 and field_len == 4:
            decoded = socket.inet_ntoa(value)
            fields["ip"] = decoded
        elif field_type == 0x03:
            decoded = value.decode("utf-8", errors="replace")
            fields["firmware"] = decoded
        elif field_type == 0x0A:
            decoded = value.decode("utf-8", errors="replace")
            fields["hostname"] = decoded
        elif field_type == 0x0B:
            decoded = value.decode("utf-8", errors="replace")
            fields["model"] = decoded
        elif field_type == 0x0C:
            decoded = value.decode("utf-8", errors="replace")
            fields["serial"] = decoded
        else:
            decoded = value.hex()

        result["raw_fields"].append(
            {
                "type": field_type,
                "len": field_len,
                "value": decoded,
            }
        )

    result["fields"] = fields
    return result


def looks_like_discovery_probe(data: bytes) -> bool:
    if len(data) < 4:
        return False
    packet_type = data[0]
    return packet_type in {0x01, 0x02, 0x04, 0x08}
