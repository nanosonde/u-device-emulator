from __future__ import annotations

import re
from typing import Any

from ..stats import TrafficCounter, _mac_seed
from .base import BaseDevice


class SwitchDevice(BaseDevice):
    _SWITCH_PERSIST_FIELDS = (
        "jumbo_frames",
        "flow_control",
        "mtu",
        "ip_mode",
        "static_ip",
        "port_overrides",
        "management_vlan",
        "vlan_enabled",
        "vlan_table",
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.jumbo_frames: bool = False
        self.flow_control: bool = False
        self.mtu: int = 0
        self.ip_mode: str = "dhcp"
        self.static_ip: str = ""
        self.port_overrides: dict[str, dict[str, Any]] = {}
        self.management_vlan: int = 1
        self.vlan_enabled: bool = False
        self.vlan_table: dict[str, dict[str, Any]] = {}
        # Per-port traffic counters (keyed by port index as int)
        self._port_counters: dict[int, TrafficCounter] = {}

    @property
    def device_type(self) -> str:
        return "switch"

    @property
    def serial(self) -> str:
        suffix = self.mac.replace(":", "").upper()
        return f"FKSW{suffix}"

    @property
    def hostname(self) -> str:
        return f"fake-switch-{self.index:02d}"

    @property
    def _all_persist_fields(self) -> tuple[str, ...]:
        return self._BASE_PERSIST_FIELDS + self._SWITCH_PERSIST_FIELDS

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    def _port_counter(self, idx: int) -> TrafficCounter:
        """Return (and lazily create) a TrafficCounter for the given port."""
        if idx not in self._port_counters:
            seed = _mac_seed(self.mac) ^ (idx * 0x9E37)
            # Uplink port (1) carries more traffic; others get lighter load
            if idx == 1:
                bps = (5_000, 50_000)
            else:
                bps = (500, 8_000)
            self._port_counters[idx] = TrafficCounter(seed=seed, base_rate_bps=bps)
        return self._port_counters[idx]

    def _tick_stats(self, interval: float) -> None:
        """Tick device-level + all per-port counters."""
        super()._tick_stats(interval)
        # Ensure all port counters exist and tick them
        model_norm = self.model.upper()
        copper_ports = 24 if model_norm == "US24" else 8
        sfp_ports = 2 if model_norm == "US24" else 0
        total_ports = copper_ports + sfp_ports
        for idx in range(1, total_ports + 1):
            self._port_counter(idx).tick(interval)

    def _stat_type(self) -> str:
        return "sw"

    def _stat_counters(self) -> dict[str, Any]:
        """Switch stat rollup: port_<n>-<counter> for every port."""
        result: dict[str, Any] = {}
        for idx, ctr in self._port_counters.items():
            for field, val in ctr.port_stat_fields().items():
                if "-r" not in field:   # rollup only stores cumulative + delta, not rates
                    result[f"port_{idx}-{field}"] = val
        return result

    def _stats_extra_snapshot(self) -> dict[str, Any]:
        return {"_port_counters": {str(i): c.to_dict() for i, c in self._port_counters.items()}}

    def _restore_stats_extra(self, snapshot: dict[str, Any]) -> None:
        for k, v in snapshot.get("_port_counters", {}).items():
            ctr = self._port_counter(int(k))
            ctr.from_dict(v)

    def payload_extras(self) -> dict[str, Any]:
        port_table = self._build_port_table(self.model)
        # Build uplink (singular) from the first port counter (uplink port = 1)
        uc = self._port_counter(1)
        rx_r, tx_r = uc.rx_rate(), uc.tx_rate()
        uplink: dict[str, Any] = {
            "type":               "wire",
            "up":                 True,
            "speed":              1000,
            "full_duplex":        True,
            "uplink_mac":         "",
            "uplink_remote_port": 0,
            "port_idx":           1,
            "rx_bytes":           uc.rx_bytes,
            "tx_bytes":           uc.tx_bytes,
            "rx_packets":         uc.rx_packets,
            "tx_packets":         uc.tx_packets,
            "rx_bytes-r":         round(rx_r, 2),
            "tx_bytes-r":         round(tx_r, 2),
        }
        return {
            "jumbo_frame_enabled": self.jumbo_frames,
            "flowctrl_enabled":    self.flow_control,
            "management_vlan":     self.management_vlan,
            "port_table":          port_table,
            "uplink":              uplink,
        }

    def _build_port_table(self, model: str) -> list[dict[str, Any]]:
        model_norm = model.upper()
        if model_norm == "US24":
            copper_ports = 24
            sfp_ports = 2
        else:
            copper_ports = 8
            sfp_ports = 0

        table: list[dict[str, Any]] = []
        for idx in range(1, copper_ports + 1):
            entry = {
                "port_idx": idx,
                "name": f"Port {idx}",
                "enable": True,
                "port_poe": True,
                "poe_enable": True,
                "up": True,
                "speed": 1000,
                "duplex": True,
                "flowctrl_rx": False,
                "flowctrl_tx": False,
                "stp_state": "forwarding",
                # Mark the port that faces the upstream parent device
                "is_uplink": (idx == self.uplink_local_port) if self.uplink_local_port else False,
            }
            # Merge traffic counters
            entry.update(self._port_counter(idx).port_stat_fields())
            entry["poe_power"] = round(self._port_counter(idx)._rng.uniform(3.5, 7.2), 2)
            table.append(self._apply_port_override(idx, entry))

        for offset, idx in enumerate(
            range(copper_ports + 1, copper_ports + sfp_ports + 1), start=1
        ):
            entry = {
                "port_idx": idx,
                "name": f"SFP {offset}",
                "enable": True,
                "port_poe": False,
                "poe_enable": False,
                "up": False,
                "speed": 1000,
                "duplex": True,
                "flowctrl_rx": False,
                "flowctrl_tx": False,
                "stp_state": "forwarding",
                "poe_power": 0.0,
            }
            entry.update(self._port_counter(idx).port_stat_fields())
            table.append(self._apply_port_override(idx, entry))
        return table

    def _port_native_vlan(self, idx: int) -> int:
        fallback: int | None = None
        for vlan in self.vlan_table.values():
            vid = str(vlan.get("id") or "").strip()
            if not vid.isdigit():
                continue
            port_mode = vlan.get("ports", {}).get(str(idx))
            if (port_mode or "").lower() == "untagged":
                return int(vid)
            if port_mode is None and (vlan.get("mode") or "").lower() == "untagged":
                if fallback is None:
                    fallback = int(vid)
        return fallback if fallback is not None else self.management_vlan

    def _port_tagged_vlans(self, idx: int) -> list[int]:
        tagged: list[int] = []
        for vlan in self.vlan_table.values():
            mode = vlan.get("ports", {}).get(str(idx), vlan.get("mode"))
            if (mode or "").lower() == "tagged":
                vid = str(vlan.get("id") or "").strip()
                if vid.isdigit():
                    tagged.append(int(vid))
        return sorted(tagged)

    def _apply_port_override(self, idx: int, entry: dict[str, Any]) -> dict[str, Any]:
        entry["port_vlan"] = self._port_native_vlan(idx)
        tagged = self._port_tagged_vlans(idx)
        if tagged:
            entry["tagged_vlans"] = tagged
        override = self.port_overrides.get(str(idx))
        if not override:
            return entry
        name = override.get("name")
        if name:
            entry["name"] = name
        status = (override.get("status") or "").lower()
        opmode = (override.get("opmode") or "").lower()
        enabled = override.get("enabled")
        if enabled is None and status:
            enabled = status not in {"disabled", "shutdown", "off"}
        if enabled is None and opmode:
            enabled = opmode not in {"shutdown", "disabled", "off"}
        if enabled is not None:
            entry["enable"] = bool(enabled)
            if not enabled:
                entry["up"] = False
        poe = (override.get("poe") or "").lower()
        if poe:
            poe_on = poe not in {"shutdown", "off", "disabled"}
            entry["port_poe"] = poe_on
            entry["poe_enable"] = poe_on
        return entry

    def _apply_system_cfg_hook(self, cfg_map: dict[str, str]) -> None:
        truthy = {"enabled", "true", "1", "yes", "on"}

        jumbo = cfg_map.get("switch.jumboframes")
        if jumbo is not None:
            self.jumbo_frames = jumbo.strip().lower() in truthy

        flowctrl = cfg_map.get("switch.flowctrl")
        if flowctrl is not None:
            self.flow_control = flowctrl.strip().lower() in truthy

        mtu = cfg_map.get("switch.mtu")
        if mtu and mtu.strip().isdigit():
            self.mtu = int(mtu.strip())

        dhcp_status = (
            cfg_map.get("dhcpc.1.status") or cfg_map.get("dhcpc.status") or ""
        ).strip().lower()
        static_ip = (cfg_map.get("netconf.1.ip") or "").strip()
        if dhcp_status in truthy:
            self.ip_mode = "dhcp"
            self.static_ip = ""
        elif static_ip and static_ip not in {"0.0.0.0", ""}:
            self.ip_mode = "static"
            self.static_ip = static_ip

        port_pattern = re.compile(r"^switch\.port\.(\d+)\.(name|opmode|poe|status)$")
        for key, value in cfg_map.items():
            match = port_pattern.match(key)
            if not match:
                continue
            idx, attr = match.group(1), match.group(2)
            self.port_overrides.setdefault(idx, {})[attr] = value

        mgmt_vlan = cfg_map.get("switch.managementvlan")
        if mgmt_vlan and mgmt_vlan.strip().isdigit():
            self.management_vlan = int(mgmt_vlan.strip())

        vlan_status = cfg_map.get("vlan.status")
        if vlan_status is not None:
            self.vlan_enabled = vlan_status.strip().lower() in truthy

        vlan_attr = re.compile(r"^switch\.vlan\.(\d+)\.(id|mode|status)$")
        vlan_port = re.compile(r"^switch\.vlan\.(\d+)\.port\.(\d+)\.mode$")
        for key, value in cfg_map.items():
            m = vlan_attr.match(key)
            if m:
                row, attr = m.group(1), m.group(2)
                self.vlan_table.setdefault(row, {"ports": {}})[attr] = value
                continue
            m = vlan_port.match(key)
            if m:
                row, port = m.group(1), m.group(2)
                vlan = self.vlan_table.setdefault(row, {"ports": {}})
                vlan.setdefault("ports", {})[port] = value

    def process_response(self, response_obj: dict[str, Any]) -> int:
        result = super().process_response(response_obj)
        if self.last_response_summary is not None:
            self.last_response_summary["jumbo_frames"] = self.jumbo_frames
            self.last_response_summary["flow_control"] = self.flow_control
            self.last_response_summary["ip_mode"] = self.ip_mode
            self.last_response_summary["port_overrides"] = len(self.port_overrides)
            self.last_response_summary["management_vlan"] = self.management_vlan
            self.last_response_summary["vlans"] = len(self.vlan_table)
        return result
