from __future__ import annotations

import socket
import threading


def parse_health_ports(port_list: str) -> list[int]:
    ports: list[int] = []
    for part in port_list.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    seen: set[int] = set()
    result: list[int] = []
    for p in ports:
        if p not in seen:
            result.append(p)
            seen.add(p)
    return result


def health_probe_server_loop(
    stop_event: threading.Event,
    bind_ip: str,
    port: int,
    verbose: bool,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_ip, port))
        sock.listen(20)
        sock.settimeout(1.0)
        print(f"[health] listening on {bind_ip}:{port}")
    except OSError as exc:
        print(f"[health] failed to bind {bind_ip}:{port}: {exc}")
        sock.close()
        return

    try:
        while not stop_event.is_set():
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                client.settimeout(1.0)
                data = b""
                try:
                    data = client.recv(512)
                except OSError:
                    data = b""
                if verbose:
                    print(f"[health:{port}] probe from {addr[0]}:{addr[1]} len={len(data)}")

                if port in {80, 8080}:
                    body = b"ok\n"
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Connection: close\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                        + body
                    )
                    try:
                        client.sendall(resp)
                    except OSError:
                        pass
            finally:
                try:
                    client.close()
                except OSError:
                    pass
    finally:
        sock.close()
