from __future__ import annotations

import datetime as dt
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ..constants import DEFAULT_AUTH_KEY
from ..protocol.packets import build_packet, parse_packet
from ..stats import SystemStats, TrafficCounter, _mac_seed
from ..utils import infer_device_type_from_model


_BASE_PERSIST_FIELDS = (
    "auth_key",
    "previous_auth_key",
    "aes_mode",
    "gcm_disabled",
    "cfgversion",
    "adopted",
    "mgmt_cfg_applied",
    "stun_url",
    "uptime_start",
    "locating",
    "reboot_count",
    "led_enabled",
    "device_name",
)


class BaseDevice:
    _BASE_PERSIST_FIELDS = _BASE_PERSIST_FIELDS

    def __init__(
        self,
        *,
        index: int,
        mac: str,
        model: str,
        firmware: str,
        controller_url: str,
        auth_key: str,
        aes_mode: str,
        interval_seconds: int,
        local_ip: str,
        handshake_mode: bool = False,
        post_adopt_keepalive: bool = False,
        post_adopt_interval: int = 10,
        inform_enabled: bool = True,
        bootstrap_model: str | None = None,
    ) -> None:
        self.index = index
        self.mac = mac
        self.model = model
        self.firmware = firmware
        self.controller_url = controller_url
        self.auth_key = auth_key
        self.aes_mode = aes_mode
        self.interval_seconds = interval_seconds
        self.local_ip = local_ip

        self.adopted: bool = False
        self.cfgversion: str = ""
        self.uptime_start: float = time.time()
        self.handshake_mode: bool = handshake_mode
        self.reset_notif_remaining: int = 0
        self.mgmt_cfg_applied: bool = False
        self.last_response_summary: dict[str, Any] | None = None
        self.post_adopt_keepalive: bool = post_adopt_keepalive
        self.post_adopt_interval: int = post_adopt_interval
        self.previous_auth_key: str = DEFAULT_AUTH_KEY
        self.stun_url: str = ""
        self.gcm_disabled: bool = False
        self.inform_enabled: bool = inform_enabled
        self.bootstrap_model: str | None = bootstrap_model
        self.locating: bool = False
        self.reboot_count: int = 0

        self.led_enabled: bool = True
        self.device_name: str = ""

        # ---- topology -----------------------------------------------------
        # Uplink: MAC address + port index on the parent device
        self.uplink_mac: str = ""
        self.uplink_remote_port: int = 0    # port index on the parent
        self.uplink_local_port: int = 0     # our own port that faces the parent
        # Downlink: devices plugged into us: [{"mac": str, "port_idx": int}, ...]
        self.downlink_table: list[dict[str, Any]] = []
        # LLDP neighbors this device "sees" via its own LLDP. The controller
        # reads `lldp_table` and computes the topology (uplink/downlink) from it.
        # Each entry: {chassis_id, local_port_idx, port_id, chassis_descr, is_wired}
        self.lldp_neighbors: list[dict[str, Any]] = []
        # Wire type for the uplink ("wire" or "wireless"); the controller copies
        # this into the stored uplink object (TopologyTrackingService keys on it).
        self.uplink_type: str = "wire"

        # ---- statistics ---------------------------------------------------
        # Master device-level traffic counter (total inbound/outbound)
        _seed = _mac_seed(mac)
        self._device_counter = TrafficCounter(
            seed=_seed,
            base_rate_bps=(2_000, 20_000),   # 2–20 KB/s device-level baseline
        )
        self._sys_stats = SystemStats(seed=_seed)
        # Timestamp of the last stats tick (used to compute interval)
        self._last_stats_tick: float = time.time()

    @property
    def device_type(self) -> str:
        return infer_device_type_from_model(self.model)

    @property
    def serial(self) -> str:
        suffix = self.mac.replace(":", "").upper()
        return f"FK{suffix}"

    @property
    def hostname(self) -> str:
        return f"fake-device-{self.index:02d}"

    def uptime(self) -> int:
        return int(time.time() - self.uptime_start)

    @property
    def _all_persist_fields(self) -> tuple[str, ...]:
        return self._BASE_PERSIST_FIELDS

    def state_snapshot(self) -> dict[str, Any]:
        snapshot = {field: getattr(self, field) for field in self._all_persist_fields}
        snapshot["mac"] = self.mac
        snapshot["model"] = self.model
        snapshot["hostname"] = self.hostname
        snapshot["controller_url"] = self.controller_url
        snapshot["saved_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        # Persist cumulative counters so they survive restarts
        snapshot["_device_counter"] = self._device_counter.to_dict()
        snapshot.update(self._stats_extra_snapshot())
        return snapshot

    def restore_state(self, snapshot: dict[str, Any]) -> None:
        for field in self._all_persist_fields:
            if field in snapshot:
                setattr(self, field, snapshot[field])
        if "_device_counter" in snapshot:
            self._device_counter.from_dict(snapshot["_device_counter"])
        self._restore_stats_extra(snapshot)

    # Subclasses override these two to persist their own counters
    def _stats_extra_snapshot(self) -> dict[str, Any]:
        return {}

    def _restore_stats_extra(self, snapshot: dict[str, Any]) -> None:
        pass

    # ------------------------------------------------------------------
    # Topology helpers
    # ------------------------------------------------------------------

    def apply_topology(
        self,
        *,
        uplink_mac: str = "",
        uplink_remote_port: int = 0,
        uplink_local_port: int = 0,
        downlink_table: list[dict[str, Any]] | None = None,
        lldp_neighbors: list[dict[str, Any]] | None = None,
        uplink_type: str = "wire",
    ) -> None:
        """Set connection info used to populate the topology in the controller UI.

        The controller does NOT speak LLDP on the wire — it builds the topology
        tree from the device's *self-reported* `lldp_table` + `uplink` string +
        `if_table`
        `doc/DEVICE_PROTOCOL.md` §5.7). Two routines key off the single uplink
        port-name string:

        * port marking — the `lldp_table` entry whose `local_port_name` matches
          the `uplink` string sets `is_uplink=true` on that `port_table` port
          (switches only), and
        * the drawn link — the `if_table` entry whose `name` matches the `uplink`
          string is copied into the device's stored `uplink` object; the UI draws
          the parent/child link from `uplink.uplink_mac` (built here by
          `_build_uplink_iface()` from `uplink_mac` + `uplink_type`).

        `downlink_table` is a supporting parent-side hint. `uplink_type` is the
        wire type stored on the uplink object ("wire" / "wireless").

        Call this after building all devices, once the MAC addresses are known::

            switch.apply_topology(
                uplink_mac=gateway.mac,
                uplink_remote_port=1,   # gateway LAN port 1
                uplink_local_port=1,    # switch uplink on its own port 1
                downlink_table=[{"mac": ap.mac, "port_idx": 5}],
                lldp_neighbors=[
                    # neighbor seen on our uplink port (the gateway)
                    {"chassis_id": gateway.mac, "local_port_idx": 1,
                     "port_id": "eth1", "is_wired": True},
                    # neighbor seen on a downlink port (the AP)
                    {"chassis_id": ap.mac, "local_port_idx": 5,
                     "port_id": "eth0", "is_wired": True},
                ],
            )
        """
        self.uplink_mac = uplink_mac
        self.uplink_remote_port = uplink_remote_port
        self.uplink_local_port = uplink_local_port
        self.downlink_table = downlink_table or []
        self.lldp_neighbors = lldp_neighbors or []
        self.uplink_type = uplink_type or "wire"

    def _build_lldp_table(self) -> list[dict[str, Any]]:
        """Normalize lldp_neighbors into the controller's expected lldp_table shape.

        Field names and validation expected by the controller
        Each entry is
        only kept by the controller if BOTH:
          * `chassis_id`     is a valid MAC address, AND
          * `local_port_name` is non-blank (StringUtils.isNotBlank).
        Entries failing either check are silently dropped ("Incorrect MAC=... in
        chassis_id field" / "Incorrect local_port_name=... in LLDP table entry").
        So we ALWAYS emit a non-blank `local_port_name`.
        """
        table: list[dict[str, Any]] = []
        for n in self.lldp_neighbors:
            local_idx = int(n.get("local_port_idx", 0))
            # local_port_name MUST be non-blank or the controller drops the entry
            local_name = n.get("local_port_name") or f"Port {local_idx}"
            entry = {
                "chassis_id":      n.get("chassis_id", ""),
                "port_id":         n.get("port_id", ""),
                "local_port_idx":  local_idx,
                "local_port_name": local_name,
                "is_wired":        bool(n.get("is_wired", True)),
            }
            if n.get("chassis_descr"):
                entry["chassis_descr"] = n["chassis_descr"]
            if n.get("port_descr"):
                entry["port_descr"] = n["port_descr"]
            table.append(entry)
        return table

    def _build_uplink_iface(self) -> dict[str, Any] | None:
        """Build the `if_table` entry the controller copies into the stored
        `uplink` object (this is what actually draws the topology link).

        
        it reads the top-level `uplink`
        STRING (an interface NAME, default "eth0"), then calls
        a lookup helper over `if_table`
        which returns the `if_table` entry whose `name` field equals that
        string.  That whole entry is then stored as the device's `uplink`
        object, so it MUST carry `uplink_mac` (+ `uplink_remote_port`, etc.).
        The UI's topology view keys off `device.uplink.uplink_mac`.

        Returns None for a root device (no uplink_mac).
        """
        if not self.uplink_mac:
            return None
        ifname = self.uplink_port_name or "Port 1"
        entry: dict[str, Any] = {
            "name":               ifname,
            "uplink_mac":         self.uplink_mac,
            "type":               self.uplink_type,
            "up":                 True,
            "is_uplink":          True,
        }
        if self.uplink_remote_port:
            entry["uplink_remote_port"] = self.uplink_remote_port
        if self.uplink_local_port:
            entry["port_idx"] = self.uplink_local_port
        return entry

    def payload_extras(self) -> dict[str, Any]:
        return {}

    def _apply_system_cfg_hook(self, cfg_map: dict[str, str]) -> None:
        pass

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    def _tick_stats(self, interval: float) -> None:
        """Advance all counters by one inform interval. Called from make_payload."""
        self._device_counter.tick(interval)
        self._sys_stats.tick()
        self._last_stats_tick = time.time()

    def _build_stat_rollup(self) -> dict[str, Any]:
        """
        The `stat` sub-object the controller writes into its time-series store.
        Shape: {"<o>": {o, oid, "<o>":mac, site_id, time, datetime, dur, counters}}.
        Subclasses override `_stat_type()` and `_stat_counters()` to provide
        device-class counters.
        """
        o = self._stat_type()
        now_ms = int(time.time() * 1000)
        entry: dict[str, Any] = {
            "o":        o,
            "oid":      self.mac,
            o:          self.mac,          # duplicate: "ap":mac / "sw":mac / "gw":mac
            "site_id":  "",                # controller fills this; empty is fine
            "time":     now_ms,
            "datetime": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dur":      int(self.interval_seconds * 1000),
        }
        entry.update(self._stat_counters())
        return {o: entry}

    def _stat_type(self) -> str:
        """Override in subclasses: 'ap', 'sw', 'gw'."""
        dt_map = {"access_point": "ap", "switch": "sw", "gateway": "gw"}
        return dt_map.get(self.device_type, "ap")

    def _stat_counters(self) -> dict[str, Any]:
        """Override in subclasses to add device-class-specific stat counters."""
        c = self._device_counter
        return {
            "rx_bytes":   c.rx_bytes,
            "tx_bytes":   c.tx_bytes,
            "rx_packets": c.rx_packets,
            "tx_packets": c.tx_packets,
        }

    def make_payload(self) -> dict[str, Any]:
        # Advance stats counters before building the payload
        now = time.time()
        elapsed = max(1.0, now - self._last_stats_tick)
        self._tick_stats(elapsed)

        payload_model = self.model
        c = self._device_counter
        rx_r, tx_r = c.rx_rate(), c.tx_rate()
        up_s = self.uptime()

        payload: dict[str, Any] = {
            "mac": self.mac,
            "ip": self.local_ip,
            "model": payload_model,
            "type": self.device_type,
            "serial": self.serial,
            "version": self.firmware,
            "short_ver": self.firmware,
            "hostname": self.device_name or self.hostname,
            "state": 0,
            "adopted": self.adopted,
            "inform_url": self.controller_url,
            "cfgversion": self.cfgversion,
            "uptime": up_s,
            "num_sta": 0,
            "guest-num_sta": 0,
            "user-num_sta": 0,
            "required_version": "",
            "locating": self.locating,
            "led_override": "on" if self.led_enabled else "off",
            # ---- common traffic counters ----------------------------------
            "bytes":      c.rx_bytes + c.tx_bytes,
            "rx_bytes":   c.rx_bytes,
            "tx_bytes":   c.tx_bytes,
            "rx_bytes-d": c.rx_bytes_d(),
            "tx_bytes-d": c.tx_bytes_d(),
            "bytes-d":    c.rx_bytes_d() + c.tx_bytes_d(),
            "bytes-r":    round(rx_r + tx_r, 2),
            "rx_bytes-r": round(rx_r, 2),
            "tx_bytes-r": round(tx_r, 2),
            "rx_packets": c.rx_packets,
            "tx_packets": c.tx_packets,
            # ---- system health -------------------------------------------
            "system-stats": self._sys_stats.system_stats_dict(up_s),
            "sys_stats":    self._sys_stats.sys_stats_dict(up_s),
            # ---- stat rollup for controller time-series ------------------
            "stat": self._build_stat_rollup(),
            # ---- topology ------------------------------------------------
            # lldp_table is the PRIMARY topology signal: the neighbors this
            # device discovered via its own LLDP. The controller's
            # wiredLldpProcessor + topologyTrackingService correlate these
            # chassis_id MACs against adopted devices to build the tree.
            "lldp_table": self._build_lldp_table(),
            # downlink_table lists downstream network devices connected to us
            # (supporting hint / fallback for the device-list parent name).
            "downlink_table": list(self.downlink_table),
        }
        # Inject topology into the `uplink` object that subclasses may already
        # have produced via payload_extras().  We do a targeted merge so we
        # don't duplicate the whole object — apply_topology() wins over the
        # defaults that the devices built from TrafficCounters.
        payload.update(self.payload_extras())
        self._apply_topology_to_uplink(payload)
        if self.handshake_mode:
            payload["default"] = not self.mgmt_cfg_applied
            payload["x_has_ssh_hostkey"] = True
            if self.reset_notif_remaining > 0:
                payload["inform_as_notif"] = True
                payload["notif_reason"] = "set-default"
                self.reset_notif_remaining -= 1
            if not payload.get("cfgversion"):
                payload["cfgversion"] = "0000000000000000"
        return payload

    @property
    def uplink_port_name(self) -> str:
        """The name of this device's own uplink port (matches the LLDP
        entry's local_port_name pointing at the parent)."""
        if self.uplink_local_port:
            return f"Port {self.uplink_local_port}"
        return ""

    def _apply_topology_to_uplink(self, payload: dict[str, Any]) -> None:
        """Wire up the inform's `uplink` string + `if_table` so the controller
        both marks the uplink port AND draws the topology link.

        Two INDEPENDENT controller mechanisms key off the SAME top-level
        `uplink` string:

        * PATH A — uplink port marking: the controller finds the `lldp_table`
          entry whose `local_port_name` == `uplink` (and `is_wired`), reads its
          `port_idx`, and sets `is_uplink=true` on that `port_table` port.

        * PATH B — the drawn topology link: the controller calls
          `com/device/service/device/QnvUxbsXyAJZ` to find the `if_table` entry
          whose `name` == `uplink`, and stores that whole entry as the device's
          `uplink` OBJECT.  The UI draws the link from `uplink.uplink_mac`.

        We therefore use a SINGLE port-name string (e.g. "Port 1") as the
        `uplink` value, and make BOTH the matching `lldp_table[*].local_port_name`
        (built in `_build_lldp_table`) AND the `if_table[*].name` (built in
        `_build_uplink_iface`) equal to it.  The if_table entry carries the
        `uplink_mac` that actually draws the link.

        Root devices (no `uplink_mac`, e.g. the gateway) get no `uplink` string
        and any stale uplink object is removed.
        """
        if not self.uplink_mac:
            # Root device (gateway): don't send a bogus uplink object/string.
            if isinstance(payload.get("uplink"), dict):
                payload.pop("uplink", None)
            return

        ifname = self.uplink_port_name or "Port 1"
        # PATH A + PATH B both match this string (against lldp local_port_name
        # and if_table name respectively).
        payload["uplink"] = ifname

        # PATH B: ensure an if_table entry named `ifname` carries uplink_mac.
        iface = self._build_uplink_iface()
        if iface is not None:
            existing = payload.get("if_table")
            if not isinstance(existing, list):
                existing = []
            # Replace any entry with the same name, then append ours.
            existing = [e for e in existing if e.get("name") != iface["name"]]
            existing.append(iface)
            payload["if_table"] = existing

    def _apply_mgmt_cfg(self, mgmt_cfg: str) -> None:
        from ..state import parse_mgmt_cfg_lines
        cfg_map = parse_mgmt_cfg_lines(mgmt_cfg)

        auth_value = cfg_map.get("x_authkey") or cfg_map.get("authkey")
        if auth_value and re.fullmatch(r"[0-9a-fA-F]{32}", auth_value):
            self.previous_auth_key = self.auth_key
            self.auth_key = auth_value.lower()
            self.mgmt_cfg_applied = True

        cfgversion_value = cfg_map.get("cfgversion")
        if cfgversion_value and re.fullmatch(r"[0-9a-fA-F]{8,32}", cfgversion_value):
            self.cfgversion = cfgversion_value

        stun_value = cfg_map.get("stun_url")
        if stun_value:
            self.stun_url = stun_value

        gcm_value = (cfg_map.get("use_aes_gcm") or "").lower()
        if gcm_value in {"true", "1", "yes", "on"} and not self.gcm_disabled:
            self.aes_mode = "gcm"

        if "led_enabled" in cfg_map:
            self.led_enabled = cfg_map["led_enabled"].strip().lower() in {
                "true",
                "1",
                "yes",
                "on",
                "enabled",
            }

        auth_match = re.search(r"(?:x_authkey|authkey)['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F]{32})", mgmt_cfg)
        if auth_match:
            self.previous_auth_key = self.auth_key
            self.auth_key = auth_match.group(1).lower()
            self.mgmt_cfg_applied = True

        inform_match = re.search(r"inform_url['\"]?\s*[:=]\s*['\"]?(https?://[^'\"\s]+)", mgmt_cfg)
        if inform_match:
            self.controller_url = inform_match.group(1)

        cfg_match = re.search(r"cfgversion['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F]{8,32})", mgmt_cfg)
        if cfg_match:
            self.cfgversion = cfg_match.group(1)

    def apply_system_cfg(self, system_cfg: str) -> None:
        from ..state import parse_mgmt_cfg_lines
        cfg_map = parse_mgmt_cfg_lines(system_cfg)

        name = cfg_map.get("resolv.host.1.name")
        if name:
            self.device_name = name

        self._apply_system_cfg_hook(cfg_map)

    def process_response(self, response_obj: dict[str, Any]) -> int:
        prev_auth_key = self.auth_key
        prev_cfgversion = self.cfgversion
        prev_controller_url = self.controller_url
        prev_mgmt_cfg_applied = self.mgmt_cfg_applied

        interval = self.interval_seconds
        if isinstance(response_obj.get("interval"), int):
            interval = max(1, response_obj["interval"])
        if response_obj.get("immediate") is True:
            interval = 1

        cmd = response_obj.get("cmd") or response_obj.get("command") or response_obj.get("_type")
        if cmd == "set-inform":
            url = response_obj.get("inform_url") or response_obj.get("url")
            if isinstance(url, str) and url.startswith("http"):
                self.controller_url = url
        elif cmd == "adopt":
            self.adopted = True
        elif cmd == "setdefault":
            self.auth_key = DEFAULT_AUTH_KEY
            self.mgmt_cfg_applied = False
        elif cmd in ("set-locate", "locate"):
            self.locating = True
        elif cmd in ("unset-locate", "stop-locate"):
            self.locating = False
        elif cmd in ("reboot", "restart"):
            self.reboot_count += 1
            self.uptime_start = time.time()
            self.locating = False

        if isinstance(response_obj.get("x_authkey"), str) and len(response_obj["x_authkey"]) == 32:
            self.auth_key = response_obj["x_authkey"].lower()
            self.mgmt_cfg_applied = True

        if cmd == "setparam":
            mgmt_cfg = response_obj.get("mgmt_cfg")
            if isinstance(mgmt_cfg, str):
                self._apply_mgmt_cfg(mgmt_cfg)
                self.adopted = True
            system_cfg = response_obj.get("system_cfg")
            if isinstance(system_cfg, str):
                self.apply_system_cfg(system_cfg)
                self.adopted = True

        setparam = response_obj.get("setparam")
        if isinstance(setparam, dict):
            mgmt_cfg = setparam.get("mgmt_cfg")
            if isinstance(mgmt_cfg, str):
                self._apply_mgmt_cfg(mgmt_cfg)
                self.adopted = True
            system_cfg = setparam.get("system_cfg")
            if isinstance(system_cfg, str):
                self.apply_system_cfg(system_cfg)
                self.adopted = True

        if isinstance(response_obj.get("cfgversion"), str):
            self.cfgversion = response_obj["cfgversion"]

        self.last_response_summary = {
            "cmd": cmd or "none",
            "authkey_updated": self.auth_key != prev_auth_key,
            "cfgversion_updated": self.cfgversion != prev_cfgversion,
            "cfgversion": self.cfgversion,
            "resp_keys": sorted(response_obj.keys()),
            "inform_url_updated": self.controller_url != prev_controller_url,
            "mgmt_cfg_applied": self.mgmt_cfg_applied,
            "mgmt_cfg_new": (not prev_mgmt_cfg_applied) and self.mgmt_cfg_applied,
            "adopted": self.adopted,
            "locating": self.locating,
            "reboot_count": self.reboot_count,
            "led_enabled": self.led_enabled,
            "device_name": self.device_name,
        }
        if self.post_adopt_keepalive and self.adopted:
            interval = min(interval, max(1, self.post_adopt_interval))
        return interval

    def inform_once(self, timeout: float = 10.0) -> tuple[int, dict[str, Any] | None]:
        def _send_once(key_hex: str, aes_mode: str) -> tuple[int, dict[str, Any] | None]:
            payload = self.make_payload()
            body = build_packet(payload, self.mac, key_hex, aes_mode)
            req = urllib.request.Request(
                self.controller_url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/x-binary"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                if resp.status >= 400:
                    raise RuntimeError(f"HTTP {resp.status}")
                if not data:
                    return self.interval_seconds, None
                try:
                    response_obj = parse_packet(data, key_hex)
                except Exception:
                    return self.interval_seconds, None
                return self.process_response(response_obj), response_obj

        try:
            return _send_once(self.auth_key, self.aes_mode)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and self.handshake_mode and self.adopted:
                fallback_keys = [k for k in [self.previous_auth_key, DEFAULT_AUTH_KEY] if k and k != self.auth_key]
                for fb_key in fallback_keys:
                    try:
                        self.previous_auth_key = self.auth_key
                        self.auth_key = fb_key
                        return _send_once(self.auth_key, "cbc")
                    except urllib.error.HTTPError:
                        continue
            raise
