from __future__ import annotations

import re
import socket
import threading
from typing import Any

import paramiko

logging_mod = __import__("logging")
logging_mod.getLogger("paramiko").setLevel(logging_mod.CRITICAL)
logging_mod.getLogger("paramiko").propagate = False

from ..devices.base import BaseDevice


class MocknetworkSSHServer(paramiko.ServerInterface):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.exec_event = threading.Event()
        self.exec_command = ""
        self.shell_requested = False

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        try:
            self.exec_command = command.decode("utf-8", errors="replace").strip()
        except Exception:
            self.exec_command = ""
        self.exec_event.set()
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: str,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_requested = True
        self.exec_event.set()
        return True


def _mock_ssh_command_output(command: str) -> str:
    cmd = command.lower()
    normalized = " ".join(cmd.split())
    if not normalized:
        return ""
    if "mca-cli-op" in cmd and "info" in cmd:
        return (
            "Model:       US24\n"
            "Version:     6.6.61.14919\n"
            "MAC Address: 24:5a:4c:30:10:2d\n"
            "IP Address:  192.168.56.1\n"
            "Status:      Connected\n"
            "Uptime:      300\n"
        )
    if normalized in {"info", "mca-status", "mca-status -a"}:
        return "status=connected\nmac=24:5a:4c:30:10:2d\nip=192.168.56.1\n"
    if "cat /etc/version" in cmd:
        return "6.6.61.14919\n"
    if "cat /proc/uptime" in cmd:
        return "300.00 250.00\n"
    if "uname -a" in cmd:
        return "Linux device 4.14.54 #1 SMP Tue Jun 13 00:00:00 UTC 2026 mips GNU/Linux\n"
    if "ls /tmp" in cmd:
        return "dhcpc.info\nrun\nsystem.cfg\n"
    if "cat /tmp/system.cfg" in cmd or "showcfg" in cmd:
        return (
            "mgmt.cfgversion=connected\n"
            "mgmt.ip=192.168.56.1\n"
            "mgmt.model=US24\n"
            "mgmt.mac=24:5a:4c:30:10:2d\n"
        )
    if "syswrapper.sh" in cmd and "upgrade" in cmd:
        return "upgrade scheduled\n"
    if "syswrapper.sh" in cmd and "set-inform" in cmd:
        return "Adoption request sent to controller\n"
    if "set-inform" in cmd:
        return "Inform URL set\n"
    if "reboot" in cmd or "restart" in cmd:
        return "rebooting\n"
    if "stun" in cmd:
        return "stun enabled\n"
    return "ok\n"


def _extract_set_inform_url(command: str) -> str | None:
    m = re.search(r"set-inform\s+['\"]?(https?://[^\s'\"]+)", command, re.IGNORECASE)
    if not m:
        return None
    return m.group(1)


def _handle_ssh_shell(channel: paramiko.Channel, verbose: bool) -> None:
    prompt = b"DEV# "
    try:
        channel.send(prompt)
        buffer = b""
        while True:
            chunk = channel.recv(512)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer or b"\r" in buffer:
                split_at = min([idx for idx in [buffer.find(b"\n"), buffer.find(b"\r")] if idx != -1])
                line = buffer[:split_at].decode("utf-8", errors="replace").strip()
                buffer = buffer[split_at + 1 :]
                if not line:
                    channel.send(prompt)
                    continue
                if verbose:
                    print(f"[ssh] shell='{line}'")
                if line.lower() in {"exit", "quit", "logout"}:
                    channel.send(b"logout\n")
                    channel.send_exit_status(0)
                    return
                output = _mock_ssh_command_output(line)
                channel.send(output.encode("utf-8"))
                channel.send(prompt)
    except Exception as exc:
        if verbose:
            print(f"[ssh] shell handling error: {exc}")
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _handle_ssh_client(
    client_sock: socket.socket,
    host_key: paramiko.PKey,
    username: str,
    password: str,
    verbose: bool,
    devices: list[BaseDevice] | None = None,
) -> None:
    transport: paramiko.Transport | None = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)
        server = MocknetworkSSHServer(username=username, password=password)
        transport.start_server(server=server)
        chan = transport.accept(8)
        if chan is None:
            return
        server.exec_event.wait(5)
        if server.shell_requested:
            print(f"[ssh] shell session from {client_sock.getpeername()[0]}")
            _handle_ssh_shell(chan, verbose)
            return
        command = server.exec_command or ""
        print(f"[ssh] exec from {client_sock.getpeername()[0]}: '{command}'")
        inform_url = _extract_set_inform_url(command)
        if inform_url and devices:
            for dev in devices:
                dev.controller_url = inform_url
                dev.inform_enabled = True
            print(f"[ssh] set-inform received; enabled inform for {len(devices)} device(s) -> {inform_url}")
        output = _mock_ssh_command_output(command)
        chan.send(output.encode("utf-8"))
        chan.send_exit_status(0)
        chan.close()
    except Exception as exc:
        if verbose:
            print(f"[ssh] client handling error: {exc}")
    finally:
        try:
            client_sock.close()
        except OSError:
            pass
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass


def ssh_server_loop(
    stop_event: threading.Event,
    bind_ip: str,
    port: int,
    username: str,
    password: str,
    verbose: bool,
    devices: list[BaseDevice] | None = None,
) -> None:
    host_key = paramiko.RSAKey.generate(2048)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_ip, port))
        sock.listen(20)
        sock.settimeout(1.0)
        print(f"[ssh] emulation listening on {bind_ip}:{port} user={username}")
    except OSError as exc:
        print(f"[ssh] failed to start on {bind_ip}:{port}: {exc}")
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
            if verbose:
                print(f"[ssh] connection from {addr[0]}:{addr[1]}")
            th = threading.Thread(
                target=_handle_ssh_client,
                args=(client, host_key, username, password, verbose, devices),
                daemon=True,
            )
            th.start()
    finally:
        sock.close()
