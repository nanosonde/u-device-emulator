from __future__ import annotations

import socket
import struct
import threading

from ..devices.base import BaseDevice
from ..net import is_loopback_ip
from ..protocol.stun import build_stun_binding_request, build_stun_binding_response, parse_stun_target


def stun_client_loop(
    device: BaseDevice,
    stop_event: threading.Event,
    verbose: bool,
    interval: int,
) -> None:
    sock: socket.socket | None = None
    current_bind_ip: str | None = None
    try:
        last_target: tuple[str, int] | None = None
        while not stop_event.is_set():
            if not device.stun_url:
                stop_event.wait(1)
                continue
            target = parse_stun_target(device.stun_url)
            if target is None:
                stop_event.wait(max(1, interval))
                continue
            bind_ip = "127.0.0.1" if is_loopback_ip(target[0]) else device.local_ip
            if sock is None or bind_ip != current_bind_ip:
                if sock is not None:
                    sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.bind((bind_ip, 0))
                except OSError:
                    sock.bind(("0.0.0.0", 0))
                sock.settimeout(1.0)
                current_bind_ip = bind_ip
            if target != last_target:
                print(f"[stun] {device.hostname} -> {target[0]}:{target[1]}")
                last_target = target
            packet = build_stun_binding_request(device.mac)
            try:
                sock.sendto(packet, target)
                try:
                    data, addr = sock.recvfrom(1024)
                    if len(data) >= 4:
                        rtype = struct.unpack(">H", data[:2])[0]
                        rtype_str = {
                            0x0101: "BindingSuccess",
                            0x0111: "BindingError",
                            0x0001: "BindingRequest",
                        }.get(rtype, f"0x{rtype:04x}")
                    else:
                        rtype_str = "short"
                    print(f"[stun] {device.hostname} rx {rtype_str} ({len(data)}B) from {addr[0]}:{addr[1]}")
                    if len(data) >= 20:
                        rt2 = struct.unpack(">H", data[:2])[0]
                        if rt2 == 0x0001:
                            resp = build_stun_binding_response(data, addr[0], addr[1])
                            if resp:
                                try:
                                    sock.sendto(resp, addr)
                                    print(f"[stun] {device.hostname} replied BindingSuccess to {addr[0]}:{addr[1]}")
                                except OSError:
                                    pass
                except socket.timeout:
                    pass
            except OSError as exc:
                if verbose:
                    print(f"[stun] {device.hostname} send failed: {exc}")
            stop_event.wait(max(1, interval))
    finally:
        if sock is not None:
            sock.close()


def stun_server_loop(
    stop_event: threading.Event,
    bind_ip: str,
    port: int,
    verbose: bool,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((bind_ip, port))
        sock.settimeout(1.0)
        print(f"[stun-server] listening on {bind_ip}:{port}")
    except OSError as exc:
        print(f"[stun-server] failed to bind {bind_ip}:{port}: {exc}")
        sock.close()
        return

    try:
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if verbose:
                print(f"[stun-server] rx {len(data)} bytes from {addr[0]}:{addr[1]}")
            response = build_stun_binding_response(data, addr[0], addr[1])
            if response is None:
                continue
            try:
                sock.sendto(response, addr)
            except OSError:
                pass
    finally:
        sock.close()
