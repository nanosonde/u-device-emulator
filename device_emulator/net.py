from __future__ import annotations

import ipaddress
import socket


def _probe_route_ip(target_host: str, target_port: int = 53) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target_host, target_port))
        ip = sock.getsockname()[0]
        return ip
    except OSError:
        return None
    finally:
        sock.close()


def infer_local_ip(controller_host: str) -> str:
    ip = _probe_route_ip(controller_host)
    if ip and not ip.startswith("127."):
        return ip

    for probe in ("1.1.1.1", "8.8.8.8", "192.168.1.1"):
        ip = _probe_route_ip(probe)
        if ip and not ip.startswith("127."):
            return ip

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM):
            candidate = info[4][0]
            if candidate and not candidate.startswith("127."):
                return candidate
    except OSError:
        pass

    return "127.0.0.1"


def is_loopback_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False
