"""Junos extras over SNMPv3: health, alarms, config changes, sessions, screens, DHCP and
licences, read from devices whose sysObjectID is Juniper's (enterprise 2636).

A bonus, never required: it needs no config of its own and no change on the device. It
reads a handful of named subtrees (the whole Juniper tree is far too slow to walk every
round), and a table the device does not have is normal: an SRX300 has no chassis
cluster, an EX switch has no security sessions. Such a table is simply left out of the
facts, logged at debug level only. Rules over these facts are in lanwatch/rules/junos.py.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import Any

from lanwatch.collectors.snmp import SnmpClient, SystemInfo, Value, text
from lanwatch.collectors.snmp_clock import parse_date_and_time
from lanwatch.collectors.snmp_kinds import ReaderResult, SnmpReader

log = logging.getLogger(__name__)

JNX = "1.3.6.1.4.1.2636"
# JUNIPER-ALARM-MIB: yellow and red alarm state (1 other, 2 off, 3 on), count, last change.
ALARM_YELLOW = f"{JNX}.3.4.2.2"
ALARM_RED = f"{JNX}.3.4.2.3"
# JUNIPER-MIB jnxOperatingTable, indexed by container.L1.L2.L3. Columns: 5 descr, 6 state,
# 7 temperature °C (0: not measured), 8 CPU %, 11 memory (buffer) %.
OPERATING = f"{JNX}.3.1.13.1"
OP_DESCR, OP_STATE, OP_TEMP, OP_CPU, OP_MEM = 5, 6, 7, 8, 11
OP_STATES = {
    1: "unknown",
    2: "running",
    3: "ready",
    4: "reset",
    5: "running at full speed",
    6: "down",
    7: "standby",
}
# JUNIPER-MIB jnxFruTable. Columns: 5 name, 8 state.
FRU = f"{JNX}.3.1.15.1"
FRU_NAME, FRU_STATE = 5, 8
FRU_STATES = {
    1: "unknown",
    2: "empty",
    3: "present",
    4: "ready",
    5: "announce online",
    6: "online",
    7: "announce offline",
    8: "offline",
    9: "diagnostic",
    10: "standby",
    11: "fault",
}
# JUNIPER-HOSTRESOURCES-MIB: percent used per hrStorageIndex; HOST-RESOURCES names them.
STORAGE_PCT = f"{JNX}.3.31.1.1.1.1"
HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
# JUNIPER-CFGMGMT-MIB: the latest commit, the ring of recent commits (columns 2 time,
# 3 date, 4 source, 5 user), and the rescue configuration.
CFG_CHANGE = f"{JNX}.3.18.1"
CFG_LATEST_INDEX = f"{CFG_CHANGE}.1.0"
CFG_EVENTS = f"{CFG_CHANGE}.7.1"
RESCUE = f"{JNX}.3.18.2"
RESCUE_DATE, RESCUE_USER, RESCUE_STATE = f"{RESCUE}.2.0", f"{RESCUE}.4.0", f"{RESCUE}.5.0"
CFG_SOURCES = {
    1: "other",
    2: "cli",
    3: "junoscript",
    4: "synchronize",
    5: "snmp",
    6: "button",
    7: "autoinstall",
    8: "unknown",
}
# JUNIPER-JS-SPU-MONITORING-MIB per node (one on a standalone SRX, two in a cluster).
SESSIONS_NOW = f"{JNX}.3.39.1.12.1.4.1.3"
SESSIONS_MAX = f"{JNX}.3.39.1.12.1.4.1.4"
# JUNIPER-JS-SCREENING-MIB jnxJsScreenMonTable, one row per zone. Column 1 is the zone
# name; the counters below are the screens worth showing.
SCREENS = f"{JNX}.3.39.1.8.1.1.1.1"
SCREEN_COLUMNS = {
    3: "syn_flood",
    4: "tear_drop",
    6: "ping_of_death",
    8: "land",
    9: "icmp_flood",
    10: "udp_flood",
    12: "port_scan",
    13: "ip_sweep",
    50: "udp_port_scan",
}
# JUNIPER-JDHCP-MIB: DHCPDECLINE messages the local server has received (a client found
# the address it was offered already in use).
DHCP_DECLINES = f"{JNX}.3.61.61.1.1.17"
# JUNIPER-LICENSE-MIB jnxLicenseFeatureListTable. Columns: 2 name, 5 used, 6 installed,
# 7 needed.
LICENCES = f"{JNX}.3.63.1.1.1.2.1"

SUBTREES = (
    ALARM_YELLOW,
    ALARM_RED,
    OPERATING,
    FRU,
    STORAGE_PCT,
    HR_STORAGE_DESCR,
    CFG_CHANGE,
    RESCUE,
    SESSIONS_NOW,
    SESSIONS_MAX,
    SCREENS,
    DHCP_DECLINES,
    LICENCES,
)


def is_juniper(system: SystemInfo) -> bool:
    return system.vendor == "Juniper"


def date_and_time(v: Value | None) -> str | None:
    """SNMPv2-TC DateAndTime (8 or 11 octets) -> ISO 8601 in UTC, or None. Parsed by the
    clock reader's parser, so both read a time the same way: without the offset octets it
    is the device's local time, taken as lanwatch's local zone (RFC 2579). A zero date
    means "never"."""
    t = parse_date_and_time(v)
    return t.at.astimezone(UTC).isoformat(timespec="seconds") if t else None


def _columns(values: dict[str, Value], table: str) -> dict[str, dict[int, Value]]:
    """A table's values as {row index: {column: value}}."""
    rows: dict[str, dict[int, Value]] = {}
    prefix = table + "."
    for oid, v in values.items():
        if not oid.startswith(prefix):
            continue
        col, _, idx = oid[len(prefix) :].partition(".")
        if col.isdigit() and idx:
            rows.setdefault(idx, {})[int(col)] = v
    return rows


def _int(v: Value | None) -> int | None:
    return v if isinstance(v, int) else None


def parse_alarms(values: dict[str, Value]) -> dict[str, Any] | None:
    out: dict[str, Any] = {}
    for name, base in (("red", ALARM_RED), ("yellow", ALARM_YELLOW)):
        state = _int(values.get(f"{base}.1.0"))
        if state is None:
            continue
        out[name] = {
            "on": state == 3,
            "count": _int(values.get(f"{base}.2.0")) or 0,
        }
    return out or None


def parse_components(values: dict[str, Value]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, row in sorted(_columns(values, OPERATING).items()):
        descr = text(row.get(OP_DESCR))
        if not descr:
            continue
        temp = _int(row.get(OP_TEMP))
        out.append(
            {
                "index": idx,
                "descr": descr,
                "state": OP_STATES.get(_int(row.get(OP_STATE)) or 1, "unknown"),
                "temp_c": temp or None,  # 0 means the component has no sensor
                "cpu_pct": _int(row.get(OP_CPU)),
                "mem_pct": _int(row.get(OP_MEM)),
            }
        )
    return out


def parse_frus(values: dict[str, Value]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, row in sorted(_columns(values, FRU).items()):
        name = text(row.get(FRU_NAME))
        state = _int(row.get(FRU_STATE))
        if not name or state is None:
            continue
        out.append({"index": idx, "name": name, "state": FRU_STATES.get(state, "unknown")})
    return out


def _real_partition(descr: str) -> bool:
    """A flash partition that can fill up: a /dev device that is not a memory disk.
    devfs and procfs always read 100 %, as does the read-only image mounted on /junos
    (/dev/md1), and the rest are the same partitions mounted a second time."""
    dev = descr.split(",", 1)[0].strip()
    return dev.startswith("/dev/") and not dev.startswith("/dev/md")


def parse_storage(values: dict[str, Value]) -> list[dict[str, Any]]:
    pct = {
        oid.rsplit(".", 1)[1]: v for oid, v in values.items() if oid.startswith(STORAGE_PCT + ".")
    }
    names = {
        oid.rsplit(".", 1)[1]: text(v)
        for oid, v in values.items()
        if oid.startswith(HR_STORAGE_DESCR + ".")
    }
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, used in sorted(pct.items(), key=lambda kv: int(kv[0])):
        descr = names.get(idx, "")
        if not isinstance(used, int) or not _real_partition(descr):
            continue
        dev = descr.split(",", 1)[0].strip()
        if dev in seen:
            continue
        seen.add(dev)
        mount = descr.partition("mounted on:")[2].strip() or dev
        out.append({"device": dev, "mount": mount, "used_pct": used})
    return out


def parse_config_changes(values: dict[str, Value]) -> dict[str, Any] | None:
    events: list[dict[str, Any]] = []
    for idx, row in _columns(values, CFG_EVENTS).items():
        at = date_and_time(row.get(3))
        if at is None or not idx.isdigit():
            continue
        events.append(
            {
                "index": int(idx),
                "at": at,
                "source": CFG_SOURCES.get(_int(row.get(4)) or 8, "unknown"),
                "user": text(row.get(5)),
            }
        )
    if not events and CFG_LATEST_INDEX not in values:
        return None
    events.sort(key=lambda e: e["at"])
    return {"latest_index": _int(values.get(CFG_LATEST_INDEX)), "events": events}


def parse_rescue(values: dict[str, Value]) -> dict[str, Any] | None:
    state = _int(values.get(RESCUE_STATE))
    if state is None:
        return None
    return {
        "saved": state == 2,  # 1 nonexistant, 2 updated
        "at": date_and_time(values.get(RESCUE_DATE)),
        "user": text(values.get(RESCUE_USER)),
    }


def parse_sessions(values: dict[str, Value]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for oid, now in sorted(values.items()):
        if not oid.startswith(SESSIONS_NOW + "."):
            continue
        node = oid[len(SESSIONS_NOW) + 1 :]
        top = _int(values.get(f"{SESSIONS_MAX}.{node}"))
        if not isinstance(now, int) or not top:
            continue
        out.append({"node": node, "current": now, "max": top})
    return out


def _zone_name(row: dict[int, Value], idx: str) -> str:
    name = text(row.get(1))
    if name:
        return name
    # The index is the zone name as a fixed-length string, padded with zeros.
    return "".join(chr(int(c)) for c in idx.split(".") if c.isdigit() and 31 < int(c) < 127)


def parse_screens(values: dict[str, Value]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, row in sorted(_columns(values, SCREENS).items()):
        counts = {
            name: row[col] for col, name in SCREEN_COLUMNS.items() if isinstance(row.get(col), int)
        }
        if not counts:
            continue
        out.append({"zone": _zone_name(row, idx), "counts": counts})
    return out


def parse_licences(values: dict[str, Value]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for _idx, row in sorted(_columns(values, LICENCES).items(), key=lambda kv: kv[0]):
        name = text(row.get(2))
        if not name:
            continue
        out.append(
            {
                "feature": name,
                "used": _int(row.get(5)) or 0,
                "installed": _int(row.get(6)) or 0,
                "needed": _int(row.get(7)) or 0,
            }
        )
    return out


def parse_junos(values: dict[str, Value]) -> dict[str, Any]:
    """Everything the Junos reader found, leaving out what the device does not have."""
    facts: dict[str, Any] = {}
    parts: dict[str, Any] = {
        "alarms": parse_alarms(values),
        "components": parse_components(values),
        "frus": parse_frus(values),
        "storage": parse_storage(values),
        "config": parse_config_changes(values),
        "rescue": parse_rescue(values),
        "sessions": parse_sessions(values),
        "screens": parse_screens(values),
        "licences": parse_licences(values),
    }
    for key, value in parts.items():
        if value:
            facts[key] = value
        else:
            log.debug("junos: no %s on this device", key)
    declines = _int(values.get(f"{DHCP_DECLINES}.0"))
    if declines is not None:
        facts["dhcp_declines"] = declines
    return facts


async def read_junos(client: SnmpClient, system: SystemInfo) -> ReaderResult:
    values: dict[str, Value] = {}
    for oid in SUBTREES:
        values |= await client.walk(oid)
    return ReaderResult(facts=parse_junos(values))


READERS = [SnmpReader("junos", is_juniper, read_junos)]


def device_view(facts: dict[str, Any] | None) -> dict[str, Any] | None:
    """The bits of the Junos facts the device page shows: the routing engine's health,
    alarms that are on, sessions, and the latest config change."""
    if not facts:
        return None
    comps = facts.get("components") or []
    engine = next((c for c in comps if "routing engine" in str(c.get("descr", "")).lower()), None)
    alarms = facts.get("alarms") or {}
    events = (facts.get("config") or {}).get("events") or []
    return {
        "engine": engine,
        "alarms_on": [name for name, a in alarms.items() if a.get("on")],
        "has_alarms": bool(alarms),
        "sessions": facts.get("sessions") or [],
        "last_change": events[-1] if events else None,
        "rescue": facts.get("rescue"),
    }
