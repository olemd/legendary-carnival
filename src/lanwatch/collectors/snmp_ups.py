"""UPS over SNMPv3: the standard UPS-MIB (RFC 1628), plus APC's PowerNet-MIB where the
device is an APC card (enterprise 318).

UPS-MIB is vendor-neutral and covers what the rules need: on battery or not, battery
status, charge and minutes left, load, input voltage and the alarm table. PowerNet adds
what UPS-MIB leaves out on APC gear: whether the card can still talk to the UPS, a finer
output state (SmartBoost, SmartTrim, bypass), why the UPS last went to battery, power in
W/VA, the battery's replacement dates and indicator, the self-test result, and the UPS's
own firmware.

Only named subtrees are walked, never the whole tree: PowerNet's `318.1.4` is an
undocumented "experimental" branch, and the card's management subtrees hold settings that
have nothing to do with power. Serial numbers are not stored.

Dates: the card writes its own dates (the self-test, the calibration) as mm/dd/yy(yy).
The UPS's dates (the battery's, the manufacture date) are documented as mm/dd/yy(yy) too,
but Smart-UPS firmware 08.8 sends them as dd.mm.yyyy; see ups_date. Anything that does not
parse is unknown (None), never guessed.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta
from typing import Any

from lanwatch.collectors.snmp import SnmpClient, SystemInfo, Value, text
from lanwatch.collectors.snmp_kinds import ReaderResult, SnmpReader
from lanwatch.firmware import is_older
from lanwatch.models import iso, now_utc

UPS_MIB = "1.3.6.1.2.1.33.1"
UPS_IDENT = f"{UPS_MIB}.1"
APC = "1.3.6.1.4.1.318"
POWERNET_UPS = f"{APC}.1.1.1"
# PowerNet ups subtrees read: ident, battery, input, output, test, comm.
POWERNET_PARTS = (1, 2, 3, 4, 7, 8)

# UPS-MIB enumerations
BATTERY_STATUS = {1: "unknown", 2: "normal", 3: "low", 4: "depleted"}
OUTPUT_SOURCE = {
    1: "other",
    2: "none",
    3: "normal",
    4: "bypass",
    5: "battery",
    6: "booster",
    7: "reducer",
}
# upsWellKnownAlarms, 1.3.6.1.2.1.33.1.6.3.<n>
ALARMS = {
    1: "battery bad",
    2: "on battery",
    3: "low battery",
    4: "depleted battery",
    5: "temperature bad",
    6: "input bad",
    7: "output bad",
    8: "output overload",
    9: "on bypass",
    10: "bypass bad",
    11: "output off as requested",
    12: "UPS off as requested",
    13: "charger failed",
    14: "UPS output off",
    15: "UPS system off",
    16: "fan failure",
    17: "fuse failure",
    18: "general fault",
    19: "diagnostic test failed",
    20: "communications lost",
    21: "awaiting power",
    22: "shutdown pending",
    23: "shutdown imminent",
    24: "test in progress",
}
# PowerNet enumerations
APC_OUTPUT_STATUS = {
    1: "unknown",
    2: "on line",
    3: "on battery",
    4: "on SmartBoost",
    5: "timed sleeping",
    6: "software bypass",
    7: "off",
    8: "rebooting",
    9: "switched bypass",
    10: "hardware failure bypass",
    11: "sleeping until power returns",
    12: "on SmartTrim",
    13: "eco mode",
    14: "hot standby",
    15: "on battery test",
    16: "emergency static bypass",
    17: "static bypass standby",
    18: "power saving mode",
    19: "spot mode",
    20: "eConversion",
}
APC_LINE_FAIL_CAUSE = {
    1: "no transfer",
    2: "high line voltage",
    3: "brownout",
    4: "blackout",
    5: "small momentary sag",
    6: "deep momentary sag",
    7: "small momentary spike",
    8: "large momentary spike",
    9: "self-test",
    10: "rate of voltage change",
}
APC_TEST_RESULT = {1: "ok", 2: "failed", 3: "invalid test", 4: "test in progress"}
APC_CALIBRATION_RESULT = {
    1: "ok",
    2: "invalid calibration",
    3: "in progress",
    4: "refused",
    5: "aborted",
    6: "pending",
    7: "unknown",
}
# upsAdvTestDiagnosticSchedule -> days between tests (None: no regular test)
APC_TEST_SCHEDULE_DAYS: dict[int, int | None] = {
    1: None,  # unknown
    2: 14,  # biweekly
    3: 7,  # weekly
    4: None,  # at turn on
    5: None,  # never
    6: 28,  # fourWeeks
    7: 84,  # twelveWeeks
    8: 14,  # biweeklySinceLastTest
    9: 7,  # weeklySinceLastTest
    10: 56,  # eightWeeks
    11: 182,  # twentysixWeeks
    12: 364,  # fiftytwoWeeks
}

# The newest firmware per management card family, pinned by hand: Schneider publishes no
# machine-readable release list. Checked 2026-11-10 against se.com (NMC2 for Smart-UPS:
# 7.2.2, 2025-09-04). NMC3 (AP964x) is not pinned until there is one to compare with.
NMC_LATEST = {"AP9630": "7.2.2", "AP9631": "7.2.2", "AP9635": "7.2.2"}
# When NMC_LATEST was last checked. The table goes stale between lanwatch releases, so
# "newest" is only ever claimed as of this date.
NMC_LATEST_CHECKED = "2026-11-10"
NMC_FAMILY = {"AP9630": "NMC2", "AP9631": "NMC2", "AP9635": "NMC2"}


def _int(v: Value | None) -> int | None:
    return v if isinstance(v, int) else None


def _str(v: Value | None) -> str | None:
    s = text(v).strip() if v is not None else ""
    return s or None


def card_date(v: Value | None) -> str | None:
    """A date the card writes itself: mm/dd/yyyy (or mm/dd/yy). ISO date, or None."""
    return _parse_date(_str(v), ("%m/%d/%Y", "%m/%d/%y"))


def ups_date(v: Value | None) -> str | None:
    """A date the UPS itself reports. PowerNet documents mm/dd/yy(yy); Smart-UPS firmware
    08.8 sends dd.mm.yyyy instead. The separator tells them apart: dotted is day first,
    slashed month first. ISO date, or None."""
    s = _str(v)
    if s and "." in s:
        return _parse_date(s, ("%d.%m.%Y", "%d.%m.%y"))
    return _parse_date(s, ("%m/%d/%Y", "%m/%d/%y"))


def _parse_date(s: str | None, formats: tuple[str, ...]) -> str | None:
    if not s:
        return None
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def parse_card_descr(descr: str) -> dict[str, str]:
    """The NMC's sysDescr: `APC Web/SNMP Management Card (MB:v4.1.0 PF:v7.2.2 ... MN:AP9630
    HR:05 SN: ... MD:07/30/2015)`. Returns model, os (PF), application (AF1), hardware."""
    out: dict[str, str] = {}
    for key, field in (("MN", "model"), ("PF", "os"), ("AF1", "application"), ("HR", "hardware")):
        m = re.search(rf"\b{key}:\s*v?([A-Za-z0-9._-]+)", descr)
        if m:
            out[field] = m.group(1)
    return out


def card_firmware(descr: str, checked: str) -> dict[str, Any] | None:
    """attrs.firmware for an APC management card, in the shape the firmware check uses."""
    card = parse_card_descr(descr)
    version = card.get("application") or card.get("os")
    model = card.get("model", "")
    if not version:
        return None
    latest = NMC_LATEST.get(model)
    return {
        "product": "APC NMC",
        "version": version,
        "latest": latest,
        "latest_checked": NMC_LATEST_CHECKED if latest else None,
        "update": is_older(version, latest) if latest else None,
        "source": "snmp",
        "model": model,
        "platform": NMC_FAMILY.get(model, ""),
        "checked": checked,
    }


def _alarms(values: dict[str, Value]) -> list[str]:
    """Names of the alarms in upsAlarmTable (upsAlarmDescr points at a well-known alarm)."""
    names: list[str] = []
    prefix = f"{UPS_MIB}.6.2.1.2."
    known = f"{UPS_MIB}.6.3."
    for oid, v in sorted(values.items()):
        if not oid.startswith(prefix):
            continue
        target = text(v).lstrip(".")
        if target.startswith(known):
            n = int(target[len(known) :].split(".")[0] or 0)
            names.append(ALARMS.get(n, f"alarm {n}"))
        else:
            names.append(target or "unknown alarm")
    return names


def parse_ups(
    upsmib: dict[str, Value], powernet: dict[str, Value], descr: str = ""
) -> tuple[dict[str, Any], dict[str, float]]:
    """(facts, metrics) from the UPS-MIB and PowerNet walks. Missing values are None."""
    u = upsmib
    p = powernet
    U, P = UPS_MIB, POWERNET_UPS

    def ug(path: str) -> Value | None:
        return u.get(f"{U}.{path}")

    def pg(path: str) -> Value | None:
        return p.get(f"{P}.{path}")

    source = _int(ug("4.1.0"))
    battery = _int(ug("2.1.0"))
    seconds_on_battery = _int(ug("2.2.0"))
    runtime_ticks = _int(pg("2.2.3.0"))
    apc_output = _int(pg("4.1.1.0"))
    comm = _int(pg("8.1.0"))
    replace = _int(pg("2.2.4.0"))
    schedule = _int(pg("7.2.1.0"))
    test_result = _int(pg("7.2.3.0"))
    cal_result = _int(pg("7.2.6.0"))
    fail_cause = _int(pg("3.2.5.0"))

    on_battery: bool | None = None
    if source is not None:
        on_battery = source == 5
    elif apc_output is not None:
        on_battery = apc_output in (3, 15)

    facts: dict[str, Any] = {
        "manufacturer": _str(ug("1.1.0")),
        "model": _str(pg("1.1.1.0")) or _str(ug("1.2.0")),
        "sku": _str(pg("1.2.5.0")),
        "name": _str(pg("1.1.2.0")) or _str(ug("1.5.0")),
        "firmware": _str(pg("1.2.1.0")) or _str(ug("1.3.0")),
        "manufactured": ups_date(pg("1.2.2.0")),
        # Card <-> UPS link. None: no PowerNet (not an APC card), so it cannot be told.
        "communication_ok": None if comm is None else comm == 1,
        "output_source": OUTPUT_SOURCE.get(source) if source is not None else None,
        "output_status": APC_OUTPUT_STATUS.get(apc_output) if apc_output else None,
        "on_battery": on_battery,
        "seconds_on_battery": seconds_on_battery,
        "battery_status": BATTERY_STATUS.get(battery) if battery is not None else None,
        "charge_pct": _int(ug("2.4.0")) if _int(ug("2.4.0")) is not None else _int(pg("2.2.1.0")),
        "runtime_min": _int(ug("2.3.0"))
        if _int(ug("2.3.0")) is not None
        else (runtime_ticks // 6000 if runtime_ticks is not None else None),
        "battery_c": _int(ug("2.7.0")) if _int(ug("2.7.0")) is not None else _int(pg("2.2.2.0")),
        "battery_replace": None if replace is None else replace == 2,
        "battery_last_replaced": ups_date(pg("2.1.3.0")),
        "battery_replace_by": ups_date(pg("2.2.21.0")),
        "battery_cartridge": _str(pg("2.2.19.0")),
        "input_v": _int(ug("3.3.1.3.1"))
        if _int(ug("3.3.1.3.1")) is not None
        else _int(pg("3.2.1.0")),
        "input_v_max": _int(pg("3.2.2.0")),
        "input_v_min": _int(pg("3.2.3.0")),
        "input_hz": _int(pg("3.2.4.0")),
        "last_transfer_cause": APC_LINE_FAIL_CAUSE.get(fail_cause) if fail_cause else None,
        "load_pct": _int(ug("4.4.1.5.1"))
        if _int(ug("4.4.1.5.1")) is not None
        else _int(pg("4.2.3.0")),
        "load_w": _int(pg("4.2.8.0")),
        "load_va": _int(pg("4.2.9.0")),
        "alarms": _alarms(u),
        "self_test_result": APC_TEST_RESULT.get(test_result) if test_result else None,
        "self_test_date": card_date(pg("7.2.4.0")),
        "self_test_every_days": APC_TEST_SCHEDULE_DAYS.get(schedule) if schedule else None,
        "calibration_result": APC_CALIBRATION_RESULT.get(cal_result) if cal_result else None,
        "calibration_date": card_date(pg("7.2.7.0")),
        # UPS-MIB upsConfig: the input voltages where the UPS goes to battery, and the
        # warning it gives before the battery runs out (upsConfigLowBattTime, minutes).
        "transfer_low_v": _int(ug("9.9.0")),
        "transfer_high_v": _int(ug("9.10.0")),
        "low_battery_warning_min": _int(ug("9.7.0")),
        # Not read: upsHighPrecOutputEnergyUsage (4.3.6). The MIB says hundredths of kWh,
        # which gives 63 780 kWh on a 2014 SMT3000 at ~120 W; read as Wh it would be
        # plausible. Until the unit is confirmed it is left out rather than shown wrong.
    }
    if descr.startswith("APC") and "MN:" in descr:
        facts["card"] = parse_card_descr(descr)

    metrics: dict[str, float] = {}
    for metric, key in (
        ("ups.load_w", "load_w"),
        ("ups.load_pct", "load_pct"),
        ("ups.input_v", "input_v"),
        ("ups.runtime_min", "runtime_min"),
        ("ups.charge_pct", "charge_pct"),
        ("ups.battery_c", "battery_c"),
    ):
        value = facts.get(key)
        if isinstance(value, int | float) and not isinstance(value, bool):
            metrics[metric] = float(value)
    return facts, metrics


def is_apc(system: SystemInfo) -> bool:
    return system.object_id.lstrip(".").startswith(f"{APC}.")


def carry_outage_start(old: Any, new: dict[str, Any], at: str) -> None:
    """Set new["on_battery_since"] while the UPS is on battery: kept from the previous read
    if that was on battery too, else the read time less the UPS's own time on battery.
    Worked out once per outage and then carried, so every read during one outage names the
    same start (ups.power-event keys its finding on it), even when the UPS does not report
    its time on battery or the reads drift against it."""
    if new.get("on_battery") is not True:
        return
    since = None
    if isinstance(old, dict) and old.get("on_battery") is True:
        since = old.get("on_battery_since")
    if not isinstance(since, str):
        seconds = new.get("seconds_on_battery")
        start = datetime.fromisoformat(at) - timedelta(
            seconds=seconds if isinstance(seconds, int) else 0
        )
        since = start.isoformat(timespec="seconds")
    new["on_battery_since"] = since


async def read_ups(client: SnmpClient, system: SystemInfo) -> ReaderResult:
    """Any target may be a UPS: one that is not APC is asked for upsIdent first (a handful
    of values), and left alone when it has none. Facts stay empty for a non-UPS."""
    apc = is_apc(system)
    if not apc and not await client.walk(UPS_IDENT):
        return ReaderResult()
    upsmib = await client.walk(UPS_MIB)
    powernet: dict[str, Value] = {}
    if apc:
        for part in POWERNET_PARTS:
            powernet.update(await client.walk(f"{POWERNET_UPS}.{part}"))
    if not upsmib and not powernet:
        # An APC device that is not a UPS (a PDU, an environment monitor): nothing to add.
        return ReaderResult()
    facts, metrics = parse_ups(upsmib, powernet, system.descr)
    attrs: dict[str, Any] = {}
    fw = card_firmware(system.descr, iso(now_utc())) if apc and "MN:" in system.descr else None
    if fw is not None:
        attrs["firmware"] = fw
    return ReaderResult(facts=facts, metrics=metrics, attrs=attrs)


# Every target: an APC card by its enterprise number, any other device by whether it
# answers UPS-MIB (read_ups asks).
READERS = [SnmpReader("ups", lambda system: True, read_ups)]


def days_since(iso_day: str | None, today: date | None = None) -> int | None:
    if not iso_day:
        return None
    try:
        d = date.fromisoformat(iso_day)
    except ValueError:
        return None
    return ((today or now_utc().date()) - d).days
