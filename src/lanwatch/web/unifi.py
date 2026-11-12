"""What the device page shows for a UniFi device beyond its facts: graphs of the
statistics the infra round keeps (uplink rate, CPU and memory use) over 24 h or 7 d.
Drawn like the UPS graphs, from the same table.
"""

from __future__ import annotations

from typing import Any

from lanwatch.models import Device, iso, now_utc
from lanwatch.store import Store
from lanwatch.web.ups import RANGES, chart

# (metric, title, unit, factor from the stored value to the unit)
GRAPHS: list[tuple[str, str, str, float]] = [
    ("unifi.uplink_rx_bps", "Uplink in", "Mbit/s", 1e-6),
    ("unifi.uplink_tx_bps", "Uplink out", "Mbit/s", 1e-6),
    ("unifi.cpu_pct", "CPU", "%", 1),
    ("unifi.mem_pct", "Memory", "%", 1),
]


def unifi_block(s: Store, device: Device, range_key: str) -> dict[str, Any] | None:
    """The graphs for a device that is UniFi gear, or None when it is not or nothing has
    been recorded yet."""
    ud = device.attrs.get("unifi_device")
    mac = ud.get("mac") if isinstance(ud, dict) else None
    if not isinstance(mac, str):
        return None
    range_key = range_key if range_key in RANGES else "24h"
    end = now_utc()
    start = iso(end - RANGES[range_key])
    graphs = []
    for metric, title, unit, factor in GRAPHS:
        series = [(ts, v * factor) for ts, v in s.snmp_series(mac, metric, start)]
        if series:
            graphs.append(
                {"title": title, "unit": unit, "chart": chart(series, start, iso(end), [])}
            )
    return {"range": range_key, "graphs": graphs} if graphs else None
