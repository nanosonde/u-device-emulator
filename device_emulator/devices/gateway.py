from __future__ import annotations

import re
from typing import Any

from ..stats import TrafficCounter, _mac_seed
from .base import BaseDevice


# UGW3 interface layout: eth0=WAN, eth1=LAN, eth2=LAN2
# UGW8: eth0=WAN, eth1-eth8=LAN ports
# UXG/UDM: treated generically like UGW3
_MODEL_IFACES: dict[str, list[dict[str, Any]]] = {
    "UGW3": [
        {"ifname": "eth0", "networkgroup": "WAN",  "num_port": 1},
        {"ifname": "eth1", "networkgroup": "LAN",  "num_port": 1},
        {"ifname": "eth2", "networkgroup": "LAN2", "num_port": 1},
    ],
    "UGW8": [
        {"ifname": "eth0", "networkgroup": "WAN",  "num_port": 1},
        *[
            {"ifname": f"eth{i}", "networkgroup": "LAN", "num_port": 1}
            for i in range(1, 9)
        ],
    ],
}
_DEFAULT_IFACES = [
    {"ifname": "eth0", "networkgroup": "WAN", "num_port": 1},
    {"ifname": "eth1", "networkgroup": "LAN", "num_port": 1},
]


class GatewayDevice(BaseDevice):
    _GW_PERSIST_FIELDS = (
        "wan_ip",
        "wan_netmask",
        "wan_gateway",
        "wan_dns1",
        "wan_dns2",
        "wan_speed",
        "wan_duplex",
        "wan_type",
        "lan_ip",
        "lan_netmask",
        "internet",
        "gw_caps",
        "usg_caps",
        "network_overrides",
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # WAN interface state
        self.wan_ip: str = ""
        self.wan_netmask: str = "255.255.255.0"
        self.wan_gateway: str = ""
        self.wan_dns1: str = "8.8.8.8"
        self.wan_dns2: str = "8.8.4.4"
        self.wan_speed: int = 1000
        self.wan_duplex: bool = True
        self.wan_type: str = "dhcp"          # dhcp | pppoe | static
        # LAN interface state
        self.lan_ip: str = ""
        self.lan_netmask: str = "255.255.255.0"
        # Connectivity
        self.internet: bool = False
        # Capabilities
        self.gw_caps: int = 0
        self.usg_caps: int = 0
        # Per-network overrides pushed via system_cfg
        self.network_overrides: dict[str, dict[str, Any]] = {}
        # Per-WAN traffic counters (keyed by interface name, e.g. "eth0")
        self._wan_counters: dict[str, TrafficCounter] = {}

    @property
    def device_type(self) -> str:
        return "gateway"

    @property
    def serial(self) -> str:
        suffix = self.mac.replace(":", "").upper()
        return f"FKGW{suffix}"

    @property
    def hostname(self) -> str:
        return f"fake-gateway-{self.index:02d}"

    @property
    def _all_persist_fields(self) -> tuple[str, ...]:
        return self._BASE_PERSIST_FIELDS + self._GW_PERSIST_FIELDS

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    def _wan_counter(self, ifname: str) -> TrafficCounter:
        """Return (and lazily create) a WAN TrafficCounter."""
        if ifname not in self._wan_counters:
            seed = _mac_seed(self.mac) ^ hash(ifname)
            # WAN traffic: typical home/small-office ISP speed simulation
            self._wan_counters[ifname] = TrafficCounter(
                seed=seed,
                base_rate_bps=(20_000, 200_000),  # 20–200 KB/s
            )
        return self._wan_counters[ifname]

    def _tick_stats(self, interval: float) -> None:
        """Tick device-level + all per-WAN counters."""
        super()._tick_stats(interval)
        for iface in self._iface_layout():
            if iface["networkgroup"].startswith("WAN"):
                self._wan_counter(iface["ifname"]).tick(interval)

    def _stat_type(self) -> str:
        return "gw"

    def _stat_counters(self) -> dict[str, Any]:
        """Gateway stat rollup: wan-<counter> / wan2-<counter> per WAN iface."""
        result: dict[str, Any] = {}
        wan_ifaces = [i for i in self._iface_layout() if i["networkgroup"].startswith("WAN")]
        for i, iface in enumerate(wan_ifaces):
            prefix = "wan" if i == 0 else f"wan{i + 1}"
            ctr = self._wan_counter(iface["ifname"])
            for field in ("tx_bytes", "rx_bytes", "tx_packets", "rx_packets",
                          "tx_broadcast", "rx_broadcast", "tx_multicast", "rx_multicast",
                          "tx_errors", "rx_errors", "tx_dropped", "rx_dropped"):
                result[f"{prefix}-{field}"] = getattr(ctr, field)
        return result

    def _stats_extra_snapshot(self) -> dict[str, Any]:
        return {"_wan_counters": {k: c.to_dict() for k, c in self._wan_counters.items()}}

    def _restore_stats_extra(self, snapshot: dict[str, Any]) -> None:
        for k, v in snapshot.get("_wan_counters", {}).items():
            ctr = self._wan_counter(k)
            ctr.from_dict(v)

    # ------------------------------------------------------------------
    # Interface / network tables
    # ------------------------------------------------------------------

    def _iface_layout(self) -> list[dict[str, Any]]:
        return _MODEL_IFACES.get(self.model.upper(), _DEFAULT_IFACES)

    def _build_if_table(self) -> list[dict[str, Any]]:
        """Return per-interface status rows for the inform payload."""
        table: list[dict[str, Any]] = []
        for iface in self._iface_layout():
            ifname = iface["ifname"]
            ng = iface["networkgroup"]
            is_wan = ng.startswith("WAN")
            entry: dict[str, Any] = {
                "ifname": ifname,
                "networkgroup": ng,
                "num_port": iface.get("num_port", 1),
                "up": True,
                "speed": self.wan_speed if is_wan else 1000,
                "duplex": self.wan_duplex if is_wan else True,
                "l1up": True,
                "l3up": is_wan and bool(self.wan_ip),
                "gateways": [],
                "dns": [],
                "ip": "",
                "mask": 0,
                "mac": self.mac,
            }
            if is_wan:
                if self.wan_ip:
                    entry["ip"] = self.wan_ip
                    try:
                        entry["mask"] = sum(bin(int(o)).count("1") for o in self.wan_netmask.split("."))
                    except Exception:
                        entry["mask"] = 24
                if self.wan_gateway:
                    entry["gateways"] = [self.wan_gateway]
                dns: list[str] = []
                if self.wan_dns1:
                    dns.append(self.wan_dns1)
                if self.wan_dns2:
                    dns.append(self.wan_dns2)
                entry["dns"] = dns
            else:
                if self.lan_ip:
                    entry["ip"] = self.lan_ip
                    try:
                        entry["mask"] = sum(bin(int(o)).count("1") for o in self.lan_netmask.split("."))
                    except Exception:
                        entry["mask"] = 24
            table.append(entry)
        return table

    def _build_network_table(self) -> list[dict[str, Any]]:
        """Empty network_table; controller populates from its own config."""
        return []

    def _build_uplink_table(self) -> list[dict[str, Any]]:
        """WAN uplink entries (one per WAN interface) with traffic counters."""
        wan_ifaces = [i for i in self._iface_layout() if i["networkgroup"].startswith("WAN")]
        table: list[dict[str, Any]] = []
        for iface in wan_ifaces:
            ctr = self._wan_counter(iface["ifname"])
            rx_r, tx_r = ctr.rx_rate(), ctr.tx_rate()
            entry: dict[str, Any] = {
                "ifname":     iface["ifname"],
                "type":       self.wan_type,
                "up":         True,
                "speed":      self.wan_speed,
                "duplex":     self.wan_duplex,
                "ip":         self.wan_ip or "",
                "max_speed":  self.wan_speed,
                "name":       "WAN",
                "rx_bytes":   ctr.rx_bytes,
                "tx_bytes":   ctr.tx_bytes,
                "rx_packets": ctr.rx_packets,
                "tx_packets": ctr.tx_packets,
                "rx_bytes-r": round(rx_r, 2),
                "tx_bytes-r": round(tx_r, 2),
            }
            if self.wan_gateway:
                entry["gateway"] = self.wan_gateway
            table.append(entry)
        return table

    def _build_wan_objects(self) -> dict[str, Any]:
        """
        Emit wan1 / wan2 counter objects consumed by the gateway WAN activity panel.
        The controller reads these as top-level payload fields.
        """
        wan_ifaces = [i for i in self._iface_layout() if i["networkgroup"].startswith("WAN")]
        result: dict[str, Any] = {}
        for i, iface in enumerate(wan_ifaces):
            key = "wan1" if i == 0 else f"wan{i + 1}"
            ctr = self._wan_counter(iface["ifname"])
            rx_r, tx_r = ctr.rx_rate(), ctr.tx_rate()
            result[key] = {
                "ifname":       iface["ifname"],
                "ip":           self.wan_ip if i == 0 else "",
                "up":           True,
                "full_duplex":  self.wan_duplex,
                "speed":        self.wan_speed,
                "rx_bytes":     ctr.rx_bytes,
                "tx_bytes":     ctr.tx_bytes,
                "rx_packets":   ctr.rx_packets,
                "tx_packets":   ctr.tx_packets,
                "rx_multicast": ctr.rx_multicast,
                "tx_multicast": ctr.tx_multicast,
                "rx_broadcast": ctr.rx_broadcast,
                "tx_broadcast": ctr.tx_broadcast,
                "rx_errors":    ctr.rx_errors,
                "tx_errors":    ctr.tx_errors,
                "rx_dropped":   ctr.rx_dropped,
                "tx_dropped":   ctr.tx_dropped,
                "rx_bytes-r":   round(rx_r, 2),
                "tx_bytes-r":   round(tx_r, 2),
            }
        return result

    def _build_uplink_singular(self) -> dict[str, Any]:
        """Singular `uplink` object for topology / link-activity rendering."""
        wan_ifaces = [i for i in self._iface_layout() if i["networkgroup"].startswith("WAN")]
        if not wan_ifaces:
            return {}
        iface = wan_ifaces[0]
        ctr = self._wan_counter(iface["ifname"])
        rx_r, tx_r = ctr.rx_rate(), ctr.tx_rate()
        return {
            "type":               self.wan_type,
            "networkgroup":       "WAN",
            "up":                 True,
            "speed":              self.wan_speed,
            "full_duplex":        self.wan_duplex,
            "ifname":             iface["ifname"],
            "ip":                 self.wan_ip or "",
            "rx_bytes":           ctr.rx_bytes,
            "tx_bytes":           ctr.tx_bytes,
            "rx_packets":         ctr.rx_packets,
            "tx_packets":         ctr.tx_packets,
            "rx_bytes-r":         round(rx_r, 2),
            "tx_bytes-r":         round(tx_r, 2),
        }

    # ------------------------------------------------------------------
    # payload_extras override
    # ------------------------------------------------------------------

    def payload_extras(self) -> dict[str, Any]:
        extras: dict[str, Any] = {
            "internet":          self.internet,
            "usg_caps":          self.usg_caps,
            "gw_caps":           self.gw_caps,
            "if_table":          self._build_if_table(),
            "network_table":     self._build_network_table(),
            "uplink_table":      self._build_uplink_table(),
            "uplink":            self._build_uplink_singular(),
            "ipv4_active_leases": [],
            "dns": {
                "servers": [s for s in [self.wan_dns1, self.wan_dns2] if s]
            },
        }
        # Add wan1/wan2/... top-level counter objects
        extras.update(self._build_wan_objects())
        return extras

    # ------------------------------------------------------------------
    # system_cfg parsing  (gateway-specific keys)
    # ------------------------------------------------------------------

    def _apply_system_cfg_hook(self, cfg_map: dict[str, str]) -> None:
        truthy = {"enabled", "true", "1", "yes", "on"}

        # WAN interface config  (system_cfg uses "wan" prefix)
        wan_ip = cfg_map.get("netconf.1.ip") or cfg_map.get("wan.ip")
        if wan_ip and wan_ip not in {"", "0.0.0.0"}:
            self.wan_ip = wan_ip

        wan_gw = cfg_map.get("netconf.1.gateway") or cfg_map.get("wan.gateway")
        if wan_gw and wan_gw not in {"", "0.0.0.0"}:
            self.wan_gateway = wan_gw

        wan_nm = cfg_map.get("netconf.1.netmask") or cfg_map.get("wan.netmask")
        if wan_nm:
            self.wan_netmask = wan_nm

        wan_type = cfg_map.get("netconf.1.type") or cfg_map.get("wan.type")
        if wan_type in {"dhcp", "pppoe", "static"}:
            self.wan_type = wan_type

        dns1 = cfg_map.get("resolv.nameserver.1.server") or cfg_map.get("wan.dns1")
        if dns1:
            self.wan_dns1 = dns1

        dns2 = cfg_map.get("resolv.nameserver.2.server") or cfg_map.get("wan.dns2")
        if dns2:
            self.wan_dns2 = dns2

        # LAN  (netconf.2 / netconf.3)
        lan_ip = cfg_map.get("netconf.2.ip") or cfg_map.get("lan.ip")
        if lan_ip and lan_ip not in {"", "0.0.0.0"}:
            self.lan_ip = lan_ip

        lan_nm = cfg_map.get("netconf.2.netmask") or cfg_map.get("lan.netmask")
        if lan_nm:
            self.lan_netmask = lan_nm

        # internet flag from mgmt_cfg
        inet = cfg_map.get("internet")
        if inet is not None:
            self.internet = inet.strip().lower() in truthy

        # WAN speed/duplex from system_cfg
        speed = cfg_map.get("netconf.1.speed") or cfg_map.get("wan.speed")
        if speed and speed.strip().isdigit():
            self.wan_speed = int(speed.strip())

        duplex = cfg_map.get("netconf.1.duplex") or cfg_map.get("wan.duplex")
        if duplex is not None:
            self.wan_duplex = duplex.strip().lower() in truthy

    def process_response(self, response_obj: dict[str, Any]) -> int:
        result = super().process_response(response_obj)
        # `gw_caps` may be pushed back by controller inside include_blocks
        if isinstance(response_obj.get("gw_caps"), int):
            self.gw_caps = response_obj["gw_caps"]
        if self.last_response_summary is not None:
            self.last_response_summary["wan_ip"] = self.wan_ip
            self.last_response_summary["wan_type"] = self.wan_type
            self.last_response_summary["internet"] = self.internet
        return result
