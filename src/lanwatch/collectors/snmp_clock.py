"""The clock of every SNMP target, compared with lanwatch's own.

Two sources, the first that answers:
  HOST-RESOURCES hrSystemDate  1.3.6.1.2.1.25.1.2.0  DateAndTime (RFC 2579), 8 or 11 octets;
                                                    the 11-octet form carries the UTC offset
  APC management card          1.3.6.1.4.1.318.2.1.6.1.0 / .2.0  mconfigClockDate
                                                    "mm/dd/yyyy" and mconfigClockTime
                                                    "hh:mm:ss", local time, no offset

A time without an offset is taken to be in lanwatch's local zone; the clock-skew rule then
reads a skew of whole hours as a time zone or DST setting rather than a wrong clock. The
device's time is compared with the midpoint of the read, so the walk's own duration does
not count as skew.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from lanwatch.collectors.snmp import SnmpClient, SystemInfo, Value, text
from lanwatch.collectors.snmp_kinds import ReaderResult, SnmpReader
from lanwatch.models import iso, now_utc

HR_SYSTEM_DATE = "1.3.6.1.2.1.25.1.2"
APC_CLOCK = "1.3.6.1.4.1.318.2.1.6"
APC_DATE = "1.3.6.1.4.1.318.2.1.6.1.0"
APC_TIME = "1.3.6.1.4.1.318.2.1.6.2.0"
APC_ENTERPRISE = "1.3.6.1.4.1.318."


@dataclass(frozen=True, slots=True)
class DeviceTime:
    at: datetime  # always timezone-aware
    has_offset: bool  # False: the device gave local time without a zone


def parse_date_and_time(raw: Value | None) -> DeviceTime | None:
    """RFC 2579 DateAndTime: year (2 octets), month, day, hour, minutes, seconds,
    deci-seconds, and optionally direction ('+'/'-'), hours and minutes from UTC."""
    if not isinstance(raw, bytes) or len(raw) not in (8, 11):
        return None
    year = int.from_bytes(raw[0:2], "big")
    month, day, hour, minute, second, deci = raw[2:8]
    try:
        naive = datetime(year, month, day, hour, minute, min(second, 59), deci * 100_000)
    except ValueError:
        return None
    if len(raw) == 8:
        return DeviceTime(naive.astimezone(), has_offset=False)
    sign = chr(raw[8])
    if sign not in "+-" or raw[9] > 14 or raw[10] > 59:
        return None
    delta = timedelta(hours=raw[9], minutes=raw[10])
    tz = timezone(delta if sign == "+" else -delta)
    return DeviceTime(naive.replace(tzinfo=tz), has_offset=True)


def parse_apc_clock(date: Value | None, clock: Value | None) -> DeviceTime | None:
    """The APC card's date (mm/dd/yyyy) and time (hh:mm:ss), in local time."""
    try:
        naive = datetime.strptime(f"{text(date)} {text(clock)}", "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return None
    return DeviceTime(naive.astimezone(), has_offset=False)


def clock_facts(
    device: DeviceTime, before: datetime, after: datetime, source: str
) -> dict[str, object]:
    mid = before + (after - before) / 2
    return {
        "device_time": device.at.isoformat(),
        "offset_s": round((device.at - mid).total_seconds(), 1),
        "read_at": iso(mid),
        "source": source,
        "has_offset": device.has_offset,
    }


async def read_clock(client: SnmpClient, system: SystemInfo) -> ReaderResult:
    before = now_utc()
    values = await client.walk(HR_SYSTEM_DATE)
    after = now_utc()
    device = parse_date_and_time(values.get(f"{HR_SYSTEM_DATE}.0"))
    if device is not None:
        return ReaderResult(facts=clock_facts(device, before, after, "hrSystemDate"))
    if system.object_id.startswith(APC_ENTERPRISE):
        before = now_utc()
        values = await client.walk(APC_CLOCK)
        after = now_utc()
        device = parse_apc_clock(values.get(APC_DATE), values.get(APC_TIME))
        if device is not None:
            return ReaderResult(facts=clock_facts(device, before, after, "apc"))
    return ReaderResult(facts={})


READERS = [SnmpReader("clock", lambda system: True, read_clock)]
