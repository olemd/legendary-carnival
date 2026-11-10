"""What the web shows for a UPS read over SNMP: the device page's UPS block (state,
gauges, battery, firmware, power events and graphs over 24 h or 7 d) and the dashboard
tile. Graphs are inline SVG drawn from snmp_series, with no JavaScript.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from lanwatch.config import Config
from lanwatch.models import Device, iso, now_utc
from lanwatch.store import Store

RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7)}

# (metric, title, unit, the facts keys of horizontal reference lines)
GRAPHS: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("ups.load_w", "Load", "W", ()),
    ("ups.input_v", "Input voltage", "V", ("transfer_low_v", "transfer_high_v")),
    ("ups.runtime_min", "Runtime", "min", ()),
    ("ups.battery_c", "Battery temperature", "°C", ()),
]


def ups_targets(s: Store, config: Config) -> list[dict[str, Any]]:
    """Configured SNMP targets with UPS facts, in config order: {host, name, data, ups}."""
    rows = {str(r.data.get("host") or r.key): r.data for r in s.infra("snmp-target")}
    out: list[dict[str, Any]] = []
    for t in config.snmp.targets():
        data = rows.get(t.host or "") if t.host else None
        if data is None and t.role == "router":
            data = next((d for d in rows.values() if d.get("role") == "router"), None)
        ups = ((data or {}).get("facts") or {}).get("ups")
        if data is None or not isinstance(ups, dict) or not ups:
            continue
        host = str(data.get("host"))
        out.append(
            {
                "host": host,
                "name": t.name or ups.get("name") or ups.get("model") or host,
                "data": data,
                "ups": ups,
                "stale": bool(data.get("last_error")),
            }
        )
    return out


def chart(
    series: list[tuple[str, float]],
    start: str,
    end: str,
    refs: list[float],
    width: int = 560,
    height: int = 120,
) -> dict[str, Any] | None:
    """Points for an SVG line over a fixed time window (so 24 h always spans the width,
    gaps included), with horizontal reference lines (e.g. transfer voltages) kept inside
    the scale."""
    if not series:
        return None
    t0 = datetime.fromisoformat(start).timestamp()
    t1 = datetime.fromisoformat(end).timestamp()
    span_t = max(1.0, t1 - t0)
    values = [v for _, v in series]
    lo, hi = min(values + refs), max(values + refs)
    pad = max(1.0, (hi - lo) * 0.08)
    lo, hi = lo - pad, hi + pad
    span_v = hi - lo
    top, bottom = 6, height - 6

    def y(v: float) -> float:
        return bottom - (v - lo) * (bottom - top) / span_v

    pts = [
        f"{(datetime.fromisoformat(ts).timestamp() - t0) * (width - 2) / span_t + 1:.1f},{y(v):.1f}"
        for ts, v in series
    ]
    return {
        "points": " ".join(pts),
        "width": width,
        "height": height,
        "refs": [{"value": r, "y": f"{y(r):.1f}"} for r in refs],
        "min": min(values),
        "max": max(values),
        "last": values[-1],
        "n": len(values),
    }


def ups_block(s: Store, config: Config, device: Device, range_key: str) -> dict[str, Any] | None:
    """The device page's UPS block, for a device that is a UPS read over SNMP."""
    if not device.ip:
        return None
    target = next((t for t in ups_targets(s, config) if t["host"] == device.ip), None)
    if target is None:
        return None
    window = RANGES.get(range_key, RANGES["24h"])
    end = now_utc()
    start = iso(end - window)
    ups = target["ups"]
    graphs = []
    for metric, title, unit, ref_keys in GRAPHS:
        refs = [float(ups[k]) for k in ref_keys if isinstance(ups.get(k), int | float)]
        series = s.snmp_series(target["host"], metric, start)
        graphs.append(
            {
                "title": title,
                "unit": unit,
                "chart": chart(series, start, iso(end), refs),
            }
        )
    events = [
        f for f in s.findings(None) if f.rule_id == "ups.power-event" and f.device_id == device.id
    ]
    return {
        **target,
        "range": range_key if range_key in RANGES else "24h",
        "graphs": graphs,
        "events": sorted(events, key=lambda f: str(f.evidence.get("started") or ""), reverse=True)[
            :20
        ],
    }


def ups_tile(s: Store, config: Config) -> dict[str, Any] | None:
    """The dashboard tile: the first UPS, with a 24 h load sparkline. None when there is
    no UPS, so the tile is not drawn at all."""
    targets = ups_targets(s, config)
    if not targets:
        return None
    first = targets[0]
    end = now_utc()
    start = iso(end - RANGES["24h"])
    by_ip = {d.ip: d for d in s.devices() if d.ip}
    return {
        **first,
        "device": by_ip.get(first["host"]),
        "more": len(targets) - 1,
        "chart": chart(
            s.snmp_series(first["host"], "ups.load_w", start), start, iso(end), [], 320, 40
        ),
    }
