from __future__ import annotations

import re
from typing import Any

from ..stats import TrafficCounter, _mac_seed
from .base import BaseDevice


# -------------------------------------------------------------------------
# Model capability tables
# -------------------------------------------------------------------------

# Models with only 2.4 GHz (ng only)
_NG_ONLY = {"BZ2", "BZ2LR", "U2O", "U2S", "U2HSR"}

# Models with dual-band (ng + na)
_DUAL_BAND = {
    "U7P",   # UAP-AC-Pro    : ng(2.4) + na(5)
    "U7LT",  # UAP-AC-Lite
    "U7LR",  # accesspoint-AC-LR
    "U7MP",  # accesspoint-AC-M-Pro
    "U7HD",  # accesspoint-AC-HD  : ng + na + na2 (3-radio) -> treat as dual
    "U7PG2", # UAP-AC-Pro Gen2
    "U7MSH",
    "UP5",   # accesspoint-AC-M
    "UP7",   # accesspoint-AC-M-Pro
    "UP5C",
    "UP7C",
}

# accesspoint-AC-HD / accesspoint-nanoHD / accesspoint-BeaconHD etc. with tri-radio or 2×5
_TRI_BAND_5 = {"U7HD", "U7NHD", "U7SHD"}

# Wi-Fi 6 models (ax radios)
_WIFI6 = {"U6EXTD", "U6LITE", "U6LONG", "U6MESH", "U6PRO", "U6PLUS", "U6IW", "U6ENTERPRISE"}

# Wi-Fi 6E models (triband with 6 GHz)
_WIFI6E = {"U6ENTERPRISEIHD", "U7PRO", "U7PROMESH", "U7PROISP", "UBB"}


def _radio_config(model: str) -> list[dict[str, Any]]:
    """Return list of radio definitions for this AP model."""
    m = model.upper()
    radios: list[dict[str, Any]] = []

    if m in _NG_ONLY:
        radios.append({"radio": "ng", "name": "wifi0", "ht": "20", "channel": 6,
                        "tx_power_mode": "auto", "tx_power": 23,
                        "min_rssi_enabled": False, "min_rssi": -94,
                        "radio_caps": 0, "radio_caps2": 0})
    elif m in _WIFI6E:
        radios = [
            {"radio": "ng", "name": "wifi0", "ht": "20",  "channel": 6,   "tx_power_mode": "auto", "tx_power": 23, "min_rssi_enabled": False, "min_rssi": -94, "radio_caps": 0, "radio_caps2": 0},
            {"radio": "na", "name": "wifi1", "ht": "80",  "channel": 36,  "tx_power_mode": "auto", "tx_power": 23, "min_rssi_enabled": False, "min_rssi": -94, "radio_caps": 0, "radio_caps2": 0},
            {"radio": "6e", "name": "wifi2", "ht": "80",  "channel": 37,  "tx_power_mode": "auto", "tx_power": 23, "min_rssi_enabled": False, "min_rssi": -94, "radio_caps": 0, "radio_caps2": 0},
        ]
    elif m in _WIFI6:
        radios = [
            {"radio": "ng", "name": "wifi0", "ht": "20",  "channel": 6,   "tx_power_mode": "auto", "tx_power": 23, "min_rssi_enabled": False, "min_rssi": -94, "radio_caps": 0, "radio_caps2": 0},
            {"radio": "na", "name": "wifi1", "ht": "80",  "channel": 36,  "tx_power_mode": "auto", "tx_power": 23, "min_rssi_enabled": False, "min_rssi": -94, "radio_caps": 0, "radio_caps2": 0},
        ]
    else:
        # Default: dual-band 802.11n/ac (ng + na)
        radios = [
            {"radio": "ng", "name": "wifi0", "ht": "20",  "channel": 6,   "tx_power_mode": "auto", "tx_power": 23, "min_rssi_enabled": False, "min_rssi": -94, "radio_caps": 0, "radio_caps2": 0},
            {"radio": "na", "name": "wifi1", "ht": "80",  "channel": 36,  "tx_power_mode": "auto", "tx_power": 23, "min_rssi_enabled": False, "min_rssi": -94, "radio_caps": 0, "radio_caps2": 0},
        ]

    return radios


class AccessPointDevice(BaseDevice):
    _AP_PERSIST_FIELDS = (
        "radio_config",
        "wlan_overrides",
        "uplink_ifname",
        "uplink_mac",
        "country_code",
        "wifi_caps",
        "wifi_caps2",
        "fw_caps",
        "hw_caps",
        "has_eth1",
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Per-radio state (mutable copy of the template)
        self.radio_config: list[dict[str, Any]] = [
            dict(r) for r in _radio_config(self.model)
        ]
        # Per-radio traffic counters (keyed by radio name e.g. 'ng', 'na')
        self._radio_counters: dict[str, TrafficCounter] = {}
        # WLAN overrides pushed via system_cfg (keyed by bssid/index)
        self.wlan_overrides: dict[str, dict[str, Any]] = {}
        # Uplink
        self.uplink_ifname: str = "eth0"
        self.uplink_mac: str = ""
        # Capabilities
        self.country_code: int = 0
        self.wifi_caps: int = 0
        self.wifi_caps2: int = 0
        self.fw_caps: int = 0
        self.hw_caps: int = 0
        self.has_eth1: bool = False

    @property
    def device_type(self) -> str:
        return "access_point"

    @property
    def serial(self) -> str:
        suffix = self.mac.replace(":", "").upper()
        return f"FKAP{suffix}"

    @property
    def hostname(self) -> str:
        return f"fake-accesspoint-{self.index:02d}"

    @property
    def _all_persist_fields(self) -> tuple[str, ...]:
        return self._BASE_PERSIST_FIELDS + self._AP_PERSIST_FIELDS

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    def _radio_counter(self, radio: str) -> TrafficCounter:
        """Return (and lazily create) a TrafficCounter for one radio."""
        if radio not in self._radio_counters:
            seed = _mac_seed(self.mac) ^ hash(radio)
            # 5 GHz / 6 GHz radios typically carry more client traffic
            bps = (10_000, 100_000) if radio != "ng" else (5_000, 50_000)
            self._radio_counters[radio] = TrafficCounter(seed=seed, base_rate_bps=bps)
        return self._radio_counters[radio]

    def _tick_stats(self, interval: float) -> None:
        """Tick device-level + all per-radio counters."""
        super()._tick_stats(interval)
        for r in self.radio_config:
            self._radio_counter(r["radio"]).tick(interval)

    def _stat_type(self) -> str:
        return "ap"

    def _stat_counters(self) -> dict[str, Any]:
        """AP stat rollup: <radio>-<counter> for each radio."""
        result: dict[str, Any] = {}
        for r in self.radio_config:
            ctr = self._radio_counter(r["radio"])
            for field in ("tx_bytes", "rx_bytes", "tx_packets", "rx_packets"):
                result[f"{r['radio']}-{field}"] = getattr(ctr, field)
            # Channel-utilization and retry fields
            result[f"{r['radio']}-cu_total"]         = 10  # stable low value
            result[f"{r['radio']}-cu_self_rx"]       = 4
            result[f"{r['radio']}-cu_self_tx"]       = 4
            result[f"{r['radio']}-tx_retries"]       = max(0, int(ctr.tx_packets * 0.03))
            result[f"{r['radio']}-wifi_tx_attempts"] = ctr.tx_packets
            result[f"{r['radio']}-wifi_tx_dropped"]  = 0
            result[f"{r['radio']}-num_sta"]          = 0
        return result

    def _stats_extra_snapshot(self) -> dict[str, Any]:
        return {"_radio_counters": {k: c.to_dict() for k, c in self._radio_counters.items()}}

    def _restore_stats_extra(self, snapshot: dict[str, Any]) -> None:
        for k, v in snapshot.get("_radio_counters", {}).items():
            ctr = self._radio_counter(k)
            ctr.from_dict(v)

    # ------------------------------------------------------------------
    # radio_table / vap_table / radio_table_stats builders
    # ------------------------------------------------------------------

    def _build_radio_table(self) -> list[dict[str, Any]]:
        table = []
        for r in self.radio_config:
            entry: dict[str, Any] = {
                "radio":           r["radio"],
                "name":            r["name"],
                "ht":              r.get("ht", "20"),
                "channel":         r.get("channel", 6),
                "tx_power_mode":   r.get("tx_power_mode", "auto"),
                "tx_power":        r.get("tx_power", 23),
                "min_rssi_enabled": r.get("min_rssi_enabled", False),
                "min_rssi":        r.get("min_rssi", -94),
                "radio_caps":      r.get("radio_caps", 0),
                "radio_caps2":     r.get("radio_caps2", 0),
                "nss":             2,
                "current_antenna_gain": 0,
                "antenna_gain":    0,
                "builtin_antenna": True,
                "builtin_ant_gain": 0,
            }
            # VHT / HE flags based on channel width hint
            if r.get("ht") in ("40", "80", "160"):
                entry["vht_caps_info"] = 0
            table.append(entry)
        return table

    def _build_vap_table(self) -> list[dict[str, Any]]:
        """Return one VAP entry per radio with traffic counters."""
        table = []
        for r in self.radio_config:
            ctr = self._radio_counter(r["radio"])
            rx_r, tx_r = ctr.rx_rate(), ctr.tx_rate()
            entry: dict[str, Any] = {
                "radio":      r["radio"],
                "radio_name": r["name"],
                "name":       r["name"],
                "bssid":      self.mac,
                "essid":      "",
                "is_guest":   False,
                "is_wep":     False,
                "up":         True,
                "usage":      "user",
                "num_sta":    0,
                "rx_bytes":   ctr.rx_bytes,
                "tx_bytes":   ctr.tx_bytes,
                "rx_pkts":    ctr.rx_packets,
                "tx_pkts":    ctr.tx_packets,
                "rx_packets": ctr.rx_packets,
                "tx_packets": ctr.tx_packets,
                "rx_errors":  ctr.rx_errors,
                "tx_errors":  ctr.tx_errors,
                "rx_dropped": ctr.rx_dropped,
                "tx_dropped": ctr.tx_dropped,
                "tx_retries": max(0, int(ctr.tx_packets * 0.03)),
                "rx_bytes-r": round(rx_r, 2),
                "tx_bytes-r": round(tx_r, 2),
            }
            # Apply any operator WLAN overrides (essid, channel, etc.)
            override = self.wlan_overrides.get(r["name"], {})
            if override.get("essid"):
                entry["essid"] = override["essid"]
            table.append(entry)
        return table

    def _build_radio_table_stats(self) -> list[dict[str, Any]]:
        """Runtime stats per radio — driven by per-radio TrafficCounters."""
        result = []
        for r in self.radio_config:
            ctr = self._radio_counter(r["radio"])
            rx_r, tx_r = ctr.rx_rate(), ctr.tx_rate()
            retries = max(0, int(ctr.tx_packets * 0.03))
            result.append({
                "radio":            r["radio"],
                "name":             r["name"],
                "state":            "RUN",
                "channel":          r.get("channel", 6),
                "ast_be_xmit":      ctr.tx_packets,
                "cu_total":         10,
                "cu_self_rx":       4,
                "cu_self_tx":       4,
                "cu_other":         2,
                "gain":             0,
                "num_sta":          0,
                "satisfaction":     100,
                "tx_packets":       ctr.tx_packets,
                "rx_packets":       ctr.rx_packets,
                "tx_bytes":         ctr.tx_bytes,
                "rx_bytes":         ctr.rx_bytes,
                "tx_retries":       retries,
                "wifi_tx_attempts": ctr.tx_packets,
                "wifi_tx_dropped":  0,
                "rx_bytes-r":       round(rx_r, 2),
                "tx_bytes-r":       round(tx_r, 2),
            })
        return result

    def _build_uplink_table(self) -> list[dict[str, Any]]:
        """Wired uplink via eth0 (LAN cable to a switch/router)."""
        # Aggregate all radio counters for the wired uplink totals
        total_rx = sum(c.rx_bytes for c in self._radio_counters.values())
        total_tx = sum(c.tx_bytes for c in self._radio_counters.values())
        total_rxp = sum(c.rx_packets for c in self._radio_counters.values())
        total_txp = sum(c.tx_packets for c in self._radio_counters.values())
        rx_r = sum(c.rx_rate() for c in self._radio_counters.values())
        tx_r = sum(c.tx_rate() for c in self._radio_counters.values())
        return [{
            "ifname":     self.uplink_ifname,
            "type":       "wire",
            "up":         True,
            "speed":      1000,
            "duplex":     True,
            "mac":        self.uplink_mac or self.mac,
            "port_idx":   1,
            "rx_bytes":   total_rx,
            "tx_bytes":   total_tx,
            "rx_packets": total_rxp,
            "tx_packets": total_txp,
            "rx_bytes-r": round(rx_r, 2),
            "tx_bytes-r": round(tx_r, 2),
        }]

    # ------------------------------------------------------------------
    # payload_extras override
    # ------------------------------------------------------------------

    def _build_uplink_singular(self) -> dict[str, Any]:
        """The singular `uplink` object (topology/activity views key off this)."""
        total_rx = sum(c.rx_bytes for c in self._radio_counters.values())
        total_tx = sum(c.tx_bytes for c in self._radio_counters.values())
        total_rxp = sum(c.rx_packets for c in self._radio_counters.values())
        total_txp = sum(c.tx_packets for c in self._radio_counters.values())
        rx_r = sum(c.rx_rate() for c in self._radio_counters.values())
        tx_r = sum(c.tx_rate() for c in self._radio_counters.values())
        return {
            "type":               "wire",
            "up":                 True,
            "speed":              1000,
            "full_duplex":        True,
            "mac":                self.uplink_mac or self.mac,
            "uplink_mac":         self.uplink_mac or "",
            "uplink_remote_port": 0,
            "port_idx":           1,
            "rx_bytes":           total_rx,
            "tx_bytes":           total_tx,
            "rx_packets":         total_rxp,
            "tx_packets":         total_txp,
            "rx_rate":            1000,
            "tx_rate":            1000,
            "rx_bytes-r":         round(rx_r, 2),
            "tx_bytes-r":         round(tx_r, 2),
        }

    def payload_extras(self) -> dict[str, Any]:
        uplink_table = self._build_uplink_table()
        return {
            "radio_table":       self._build_radio_table(),
            "vap_table":         self._build_vap_table(),
            "radio_table_stats": self._build_radio_table_stats(),
            "uplink_table":      uplink_table,
            "uplink":            self._build_uplink_singular(),
            "ethernet_table":    [{
                "mac":      self.mac,
                "num_port": 2 if self.has_eth1 else 1,
                "name":     "eth0",
            }],
            "antenna_table":     [],
            "vwire_table":       [],
            # lldp_table / downlink_table are provided by the base payload
            # (driven by apply_topology); don't override them here.
            "scan_radio_table":  [],
            "port_stats":        [],
            "country_code":      self.country_code,
            "wifi_caps":         self.wifi_caps,
            "wifi_caps2":        self.wifi_caps2,
            "fw_caps":           self.fw_caps,
            "hw_caps":           self.hw_caps,
            "has_eth1":          self.has_eth1,
            "has_fan":           False,
            "has_speaker":       False,
            "has_temperature":   False,
        }

    # ------------------------------------------------------------------
    # system_cfg parsing (AP-specific keys)
    # ------------------------------------------------------------------

    def _apply_system_cfg_hook(self, cfg_map: dict[str, str]) -> None:
        # Radio settings: radio.ng.channel, radio.na.channel, radio.na.txpower, etc.
        radio_pattern = re.compile(r"^radio\.(ng|na|6e|na2)\.(\w+)$")
        for key, value in cfg_map.items():
            m = radio_pattern.match(key)
            if not m:
                continue
            radio_name, attr = m.group(1), m.group(2)
            radio = next((r for r in self.radio_config if r["radio"] == radio_name), None)
            if radio is None:
                continue
            if attr == "channel" and value.strip().lstrip("-").isdigit():
                radio["channel"] = int(value.strip())
            elif attr in ("txpower", "tx_power") and value.strip().isdigit():
                radio["tx_power"] = int(value.strip())
            elif attr in ("txpower_mode", "tx_power_mode"):
                radio["tx_power_mode"] = value.strip().lower()
            elif attr in ("htmode", "ht"):
                # e.g. "HT20" -> "20", "VHT80" -> "80"
                parsed = re.sub(r"[^0-9]", "", value)
                if parsed:
                    radio["ht"] = parsed

        # Wireless network (WLAN) settings: wireless.1.ssid, wireless.1.channel, etc.
        wlan_pattern = re.compile(r"^wireless\.(\d+)\.(ssid|channel|disabled|radio)$")
        for key, value in cfg_map.items():
            m = wlan_pattern.match(key)
            if not m:
                continue
            idx, attr = m.group(1), m.group(2)
            override = self.wlan_overrides.setdefault(idx, {})
            if attr == "ssid":
                override["essid"] = value.strip()
            elif attr == "channel" and value.strip().lstrip("-").isdigit():
                override["channel"] = int(value.strip())
            elif attr == "disabled":
                override["disabled"] = value.strip().lower() in {"1", "true", "yes", "on"}
            elif attr == "radio":
                override["radio"] = value.strip().lower()

        # Country code
        cc = cfg_map.get("country_code") or cfg_map.get("countrycode")
        if cc and cc.strip().isdigit():
            self.country_code = int(cc.strip())

    def process_response(self, response_obj: dict[str, Any]) -> int:
        result = super().process_response(response_obj)
        if self.last_response_summary is not None:
            self.last_response_summary["radio_count"] = len(self.radio_config)
            self.last_response_summary["radios"] = [
                f"{r['radio']}@ch{r['channel']}" for r in self.radio_config
            ]
        return result
