from __future__ import annotations

import threading
import time
from typing import Any

from ..devices.base import BaseDevice
from ..state import StateStore
from .discovery import discovery_announce_loop, discovery_listener_loop
from .health import health_probe_server_loop, parse_health_ports
from .inform import device_loop
from .ssh import ssh_server_loop
from .stun import stun_client_loop, stun_server_loop


class EmulationRunner:
    def __init__(
        self,
        *,
        devices: list[BaseDevice],
        state_store: StateStore | None = None,
        stop_event: threading.Event | None = None,
        verbose: bool = False,
        status_summary: bool = False,
        capture_response: bool = False,
        capture_file: str | None = None,
        capture_lock: threading.Lock | None = None,
        discovery_mode: str = "off",
        discovery_port: int = 10001,
        discovery_target: str = "255.255.255.255",
        discovery_bind_ip: str | None = None,
        discovery_interval: int = 10,
        discovery_packet_type: int = 0x06,
        discovery_sniff: bool = False,
        discovery_sniff_file: str | None = None,
        ssh_enabled: bool = False,
        ssh_bind_ip: str = "0.0.0.0",
        ssh_port: int = 22,
        ssh_user: str = "device",
        ssh_password: str = "device",
        stun_enabled: bool = False,
        stun_interval: int = 10,
        stun_server_enabled: bool = False,
        stun_server_bind_ip: str = "127.0.0.1",
        stun_server_port: int = 3478,
        health_enabled: bool = False,
        health_bind_ip: str = "0.0.0.0",
        health_ports: str = "80,8080,443",
    ) -> None:
        self.devices = devices
        self.state_store = state_store
        self.stop_event = stop_event or threading.Event()
        self.verbose = verbose
        self.status_summary = status_summary
        self.capture_response = capture_response
        self.capture_file = capture_file
        self.capture_lock = capture_lock or threading.Lock()

        self.discovery_mode = discovery_mode
        self.discovery_port = discovery_port
        self.discovery_target = discovery_target
        self.discovery_bind_ip = discovery_bind_ip
        self.discovery_interval = discovery_interval
        self.discovery_packet_type = discovery_packet_type
        self.discovery_sniff = discovery_sniff
        self.discovery_sniff_file = discovery_sniff_file

        self.ssh_enabled = ssh_enabled
        self.ssh_bind_ip = ssh_bind_ip
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password

        self.stun_enabled = stun_enabled
        self.stun_interval = stun_interval
        self.stun_server_enabled = stun_server_enabled
        self.stun_server_bind_ip = stun_server_bind_ip
        self.stun_server_port = stun_server_port

        self.health_enabled = health_enabled
        self.health_bind_ip = health_bind_ip
        self.health_ports = health_ports

        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for dev in self.devices:
            th = threading.Thread(
                target=device_loop,
                args=(
                    dev,
                    self.stop_event,
                    self.verbose,
                    self.status_summary,
                    self.capture_response,
                    self.capture_file,
                    self.capture_lock,
                    self.state_store,
                ),
                daemon=True,
            )
            th.start()
            self._threads.append(th)

        if self.discovery_mode in {"listen", "both"}:
            th = threading.Thread(
                target=discovery_listener_loop,
                args=(
                    self.devices,
                    self.stop_event,
                    self.discovery_port,
                    self.verbose,
                    self.discovery_sniff,
                    self.discovery_sniff_file,
                    self.capture_lock,
                    self.discovery_packet_type,
                ),
                daemon=True,
            )
            th.start()
            self._threads.append(th)

        if self.discovery_mode in {"announce", "both"}:
            th = threading.Thread(
                target=discovery_announce_loop,
                args=(
                    self.devices,
                    self.stop_event,
                    self.discovery_target,
                    self.discovery_port,
                    max(1, self.discovery_interval),
                    self.verbose,
                    self.discovery_sniff,
                    self.discovery_sniff_file,
                    self.capture_lock,
                    self.discovery_packet_type,
                    self.discovery_bind_ip,
                ),
                daemon=True,
            )
            th.start()
            self._threads.append(th)

        if self.ssh_enabled:
            th = threading.Thread(
                target=ssh_server_loop,
                args=(
                    self.stop_event,
                    self.ssh_bind_ip,
                    self.ssh_port,
                    self.ssh_user,
                    self.ssh_password,
                    self.verbose,
                    self.devices,
                ),
                daemon=True,
            )
            th.start()
            self._threads.append(th)

        if self.stun_enabled:
            for dev in self.devices:
                th = threading.Thread(
                    target=stun_client_loop,
                    args=(dev, self.stop_event, self.verbose, max(1, self.stun_interval)),
                    daemon=True,
                )
                th.start()
                self._threads.append(th)

        if self.stun_server_enabled:
            th = threading.Thread(
                target=stun_server_loop,
                args=(
                    self.stop_event,
                    self.stun_server_bind_ip,
                    self.stun_server_port,
                    self.verbose,
                ),
                daemon=True,
            )
            th.start()
            self._threads.append(th)

        if self.health_enabled:
            for port in parse_health_ports(self.health_ports):
                th = threading.Thread(
                    target=health_probe_server_loop,
                    args=(
                        self.stop_event,
                        self.health_bind_ip,
                        port,
                        self.verbose,
                    ),
                    daemon=True,
                )
                th.start()
                self._threads.append(th)

    def stop(self, timeout: float = 2) -> None:
        self.stop_event.set()
        for th in self._threads:
            th.join(timeout=timeout)
        self._threads.clear()

    def join(self) -> None:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
