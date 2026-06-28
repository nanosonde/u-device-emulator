"""
stats.py — synthetic traffic counters and system-stats helpers.

Each TrafficCounter maintains:
  - cumulative rx/tx byte + packet counters (monotonically growing, survives
    multiple ticks, persisted to state so they don't reset on restart).
  - a short sliding window for computing the current *rate* (bytes/s).
  - a 24-hour delta for the "-d" suffix fields the device-list shows.

SystemStats generates cpu/mem/uptime/loadavg values with gentle variation.

All randomness is seeded from the device's MAC so values look stable/plausible
across runs, but vary slowly over time to produce realistic-looking graphs.
"""
from __future__ import annotations

import math
import random
import time
from collections import deque
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mac_seed(mac: str) -> int:
    """Deterministic seed derived from MAC so each device has its own variance."""
    return int(mac.replace(":", ""), 16)


# ---------------------------------------------------------------------------
# TrafficCounter
# ---------------------------------------------------------------------------

class TrafficCounter:
    """
    Tracks cumulative + derived traffic metrics for one logical interface.

    Parameters
    ----------
    seed : int
        Seed for the random traffic variation — pass `_mac_seed(mac) ^ label_hash`
        so each port/radio/WAN gets independent variation.
    base_rate_bps : tuple[int, int]
        (min, max) bytes-per-second the counter advances per tick.
    pps_ratio : float
        Packets per byte (typical IP: 1 pkt / ~1500 bytes ≈ 0.0007).
    """

    # Ring buffer depth for rate averaging (each slot = one tick)
    _RATE_WINDOW = 8
    # Window size used for 24h "-d" tracking (seconds)
    _DAY_S = 86_400

    def __init__(
        self,
        seed: int = 0,
        base_rate_bps: tuple[int, int] = (0, 0),
        pps_ratio: float = 1 / 1200,
    ) -> None:
        self._rng = random.Random(seed)
        self._min_bps, self._max_bps = base_rate_bps
        self._pps_ratio = pps_ratio

        # Cumulative counters
        self.rx_bytes: int = 0
        self.tx_bytes: int = 0
        self.rx_packets: int = 0
        self.tx_packets: int = 0
        self.rx_multicast: int = 0
        self.tx_multicast: int = 0
        self.rx_broadcast: int = 0
        self.tx_broadcast: int = 0
        self.rx_errors: int = 0
        self.tx_errors: int = 0
        self.rx_dropped: int = 0
        self.tx_dropped: int = 0

        # Rate tracking: ring of (timestamp, rx_bytes, tx_bytes)
        self._rate_window: deque[tuple[float, int, int]] = deque(maxlen=self._RATE_WINDOW)
        # 24-h delta: ring of (timestamp, rx_bytes, tx_bytes)
        self._day_window: deque[tuple[float, int, int]] = deque()
        self._last_tick: float = time.time()

    # ------------------------------------------------------------------
    # Advance counters
    # ------------------------------------------------------------------

    def tick(self, interval: float = 10.0) -> None:
        """
        Advance counters by one simulated interval.
        Call once per inform cycle before building the payload.
        """
        now = time.time()

        # Pick a random rate within [min, max] with some jitter
        if self._max_bps > 0:
            mean = (self._min_bps + self._max_bps) / 2
            sigma = (self._max_bps - self._min_bps) / 4
            rate = max(0.0, self._rng.gauss(mean, sigma))
            # asymmetric rx/tx: rx slightly higher
            rx_add = int(rate * interval * self._rng.uniform(0.55, 0.65))
            tx_add = int(rate * interval * self._rng.uniform(0.35, 0.45))
        else:
            rx_add = tx_add = 0

        self.rx_bytes += rx_add
        self.tx_bytes += tx_add
        self.rx_packets += max(0, int(rx_add * self._pps_ratio))
        self.tx_packets += max(0, int(tx_add * self._pps_ratio))
        # Multicast/broadcast ≈ 2–5% of packets
        mcast_frac = self._rng.uniform(0.02, 0.05)
        bcast_frac = self._rng.uniform(0.005, 0.01)
        self.rx_multicast += max(0, int(self.rx_packets * mcast_frac))
        self.tx_multicast += max(0, int(self.tx_packets * mcast_frac))
        self.rx_broadcast += max(0, int(self.rx_packets * bcast_frac))
        self.tx_broadcast += max(0, int(self.tx_packets * bcast_frac))

        # Push rate window entry
        self._rate_window.append((now, self.rx_bytes, self.tx_bytes))

        # Push 24h window entry then prune old ones
        self._day_window.append((now, self.rx_bytes, self.tx_bytes))
        cutoff = now - self._DAY_S
        while self._day_window and self._day_window[0][0] < cutoff:
            self._day_window.popleft()

        self._last_tick = now

    # ------------------------------------------------------------------
    # Derived metrics
    # ------------------------------------------------------------------

    def rx_rate(self) -> float:
        """Current rx bytes/s from the rate window."""
        return self._compute_rate()[0]

    def tx_rate(self) -> float:
        """Current tx bytes/s from the rate window."""
        return self._compute_rate()[1]

    def _compute_rate(self) -> tuple[float, float]:
        if len(self._rate_window) < 2:
            return 0.0, 0.0
        oldest_t, oldest_rx, oldest_tx = self._rate_window[0]
        newest_t, newest_rx, newest_tx = self._rate_window[-1]
        elapsed = newest_t - oldest_t
        if elapsed <= 0:
            return 0.0, 0.0
        return (newest_rx - oldest_rx) / elapsed, (newest_tx - oldest_tx) / elapsed

    def rx_bytes_d(self) -> int:
        """rx_bytes delta over the last 24 hours."""
        if not self._day_window:
            return self.rx_bytes
        oldest_rx = self._day_window[0][1]
        return self.rx_bytes - oldest_rx

    def tx_bytes_d(self) -> int:
        """tx_bytes delta over the last 24 hours."""
        if not self._day_window:
            return self.tx_bytes
        oldest_tx = self._day_window[0][2]
        return self.tx_bytes - oldest_tx

    # ------------------------------------------------------------------
    # Serialization (state persistence)
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "rx_bytes":    self.rx_bytes,
            "tx_bytes":    self.tx_bytes,
            "rx_packets":  self.rx_packets,
            "tx_packets":  self.tx_packets,
            "rx_multicast": self.rx_multicast,
            "tx_multicast": self.tx_multicast,
            "rx_broadcast": self.rx_broadcast,
            "tx_broadcast": self.tx_broadcast,
            "rx_errors":   self.rx_errors,
            "tx_errors":   self.tx_errors,
            "rx_dropped":  self.rx_dropped,
            "tx_dropped":  self.tx_dropped,
        }

    def from_dict(self, d: dict[str, Any]) -> None:
        for k in self.to_dict():
            if k in d:
                setattr(self, k, int(d[k]))

    # ------------------------------------------------------------------
    # Convenience: full stat block for a port/wan/uplink entry
    # ------------------------------------------------------------------

    def port_stat_fields(self) -> dict[str, Any]:
        """All counter + rate fields to merge into a port_table entry."""
        rx_r, tx_r = self._compute_rate()
        return {
            "rx_bytes":     self.rx_bytes,
            "tx_bytes":     self.tx_bytes,
            "rx_packets":   self.rx_packets,
            "tx_packets":   self.tx_packets,
            "rx_multicast": self.rx_multicast,
            "tx_multicast": self.tx_multicast,
            "rx_broadcast": self.rx_broadcast,
            "tx_broadcast": self.tx_broadcast,
            "rx_errors":    self.rx_errors,
            "tx_errors":    self.tx_errors,
            "rx_dropped":   self.rx_dropped,
            "tx_dropped":   self.tx_dropped,
            "rx_bytes-r":   round(rx_r, 2),
            "tx_bytes-r":   round(tx_r, 2),
        }


# ---------------------------------------------------------------------------
# SystemStats
# ---------------------------------------------------------------------------

class SystemStats:
    """
    Produces `system-stats` and `sys_stats` payloads with slowly varying
    CPU/memory/load figures.

    seed: deterministic per device; values drift ±a few percent each tick.
    """

    def __init__(self, seed: int = 0) -> None:
        self._rng = random.Random(seed ^ 0xDEAD)
        # Baseline values
        self._cpu_pct: float = self._rng.uniform(2.0, 8.0)
        self._mem_pct: float = self._rng.uniform(35.0, 55.0)
        self._mem_total: int = 256 * 1024 * 1024  # 256 MB
        self._loadavg: list[float] = [
            self._rng.uniform(0.1, 0.4) for _ in range(3)
        ]

    def tick(self) -> None:
        """Drift CPU/mem/load slightly each inform cycle."""
        self._cpu_pct = max(0.5, min(95.0,
            self._cpu_pct + self._rng.gauss(0, 0.5)))
        self._mem_pct = max(10.0, min(90.0,
            self._mem_pct + self._rng.gauss(0, 0.2)))
        for i in range(3):
            self._loadavg[i] = max(0.0, min(4.0,
                self._loadavg[i] + self._rng.gauss(0, 0.02)))

    def system_stats_dict(self, uptime_s: int) -> dict[str, Any]:
        """Returns `system-stats` (hyphen) — percent-based summary."""
        return {
            "cpu":    f"{self._cpu_pct:.1f}",
            "mem":    f"{self._mem_pct:.1f}",
            "uptime": str(uptime_s),
            "temps":  {},
        }

    def sys_stats_dict(self, uptime_s: int) -> dict[str, Any]:
        """Returns `sys_stats` (underscore) — raw detail."""
        mem_used = int(self._mem_total * self._mem_pct / 100)
        mem_buffer = int(mem_used * 0.05)
        return {
            "loadavg_1":  f"{self._loadavg[0]:.2f}",
            "loadavg_5":  f"{self._loadavg[1]:.2f}",
            "loadavg_15": f"{self._loadavg[2]:.2f}",
            "mem_used":   mem_used,
            "mem_total":  self._mem_total,
            "mem_buffer": mem_buffer,
            "user-rx_bytes": 0,
            "user-tx_bytes": 0,
            "guest-rx_bytes": 0,
            "guest-tx_bytes": 0,
        }
