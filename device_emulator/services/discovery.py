from __future__ import annotations

import datetime as dt
import socket
import threading
from typing import Any

from ..devices.base import BaseDevice
from ..protocol.discovery import (
    build_discovery_payload,
    decode_discovery_tlvs,
    looks_like_discovery_probe,
)
from .inform import write_json_line


def discovery_listener_loop(
    devices: list[BaseDevice],
    stop_event: threading.Event,
    port: int,
    verbose: bool,
    sniff: bool,
    sniff_file: str | None,
    io_lock: threading.Lock,
    packet_type: int,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    print(f"[discovery-listener] listening on udp/{port}")
    try:
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break

            if verbose:
                print(f"[discovery-listener] probe from {addr[0]}:{addr[1]} len={len(data)}")

            if sniff:
                decoded = decode_discovery_tlvs(data)
                record = {
                    "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "direction": "rx",
                    "src": f"{addr[0]}:{addr[1]}",
                    "dst": f"0.0.0.0:{port}",
                    "len": len(data),
                    "hex": data.hex(),
                    "decoded": decoded,
                }
                with io_lock:
                    write_json_line("discovery-sniff", sniff_file, record)

            if not looks_like_discovery_probe(data):
                continue

            for dev in devices:
                payload = build_discovery_payload(dev, packet_type=packet_type)
                try:
                    sock.sendto(payload, addr)
                except OSError:
                    pass
    finally:
        sock.close()


def discovery_announce_loop(
    devices: list[BaseDevice],
    stop_event: threading.Event,
    target_ip: str,
    port: int,
    interval: int,
    verbose: bool,
    sniff: bool,
    sniff_file: str | None,
    io_lock: threading.Lock,
    packet_type: int,
    bind_ip: str | None = None,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if target_ip.endswith("255"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Bind to the source IP that faces the controller so broadcasts egress the
    # correct interface. Without this, the limited broadcast 255.255.255.255 may
    # follow the host's default broadcast route out the wrong NIC (e.g. a NAT
    # adapter) and never reach the controller's subnet.
    if bind_ip:
        try:
            sock.bind((bind_ip, 0))
        except OSError as exc:
            print(f"[discovery-announce] could not bind to {bind_ip}: {exc}")

    target = (target_ip, port)
    src = bind_ip or "auto"
    print(f"[discovery-announce] sending to {target_ip}:{port} from {src} every {interval}s")
    try:
        while not stop_event.is_set():
            for dev in devices:
                payload = build_discovery_payload(dev, packet_type=packet_type)
                try:
                    sock.sendto(payload, target)
                    if sniff:
                        decoded = decode_discovery_tlvs(payload)
                        record = {
                            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
                            "direction": "tx",
                            "src": "0.0.0.0:0",
                            "dst": f"{target_ip}:{port}",
                            "device": dev.hostname,
                            "mac": dev.mac,
                            "len": len(payload),
                            "hex": payload.hex(),
                            "decoded": decoded,
                        }
                        with io_lock:
                            write_json_line("discovery-sniff", sniff_file, record)
                    if verbose:
                        print(f"[discovery-announce] sent {dev.hostname} ({dev.mac})")
                except OSError as exc:
                    print(f"[discovery-announce] send failed: {exc}")
            stop_event.wait(max(1, interval))
    finally:
        sock.close()
