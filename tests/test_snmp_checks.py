"""Checks on every SNMP target: the clock reader and its parsing, clock skew, unreachable."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lanwatch.collectors import snmp_clock
from lanwatch.config import Config
from lanwatch.models import Severity
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine, all_rules
from lanwatch.rules.snmp_checks import SnmpClockSkewRule, SnmpUnreachableRule, classify_skew
from lanwatch.store import Store


def dat(year: int, *rest: int, tz: tuple[str, int, int] | None = None) -> bytes:
    raw = year.to_bytes(2, "big") + bytes(rest)
    if tz is not None:
        raw += tz[0].encode() + bytes(tz[1:])
    return raw


def test_date_and_time_with_offset() -> None:
    # The SRX answered 2026-11-10 21:06:16.0 +01:00.
    t = snmp_clock.parse_date_and_time(b"\x07\xea\x0b\n\x15\x06\x10\x00+\x01\x00")
    assert t is not None and t.has_offset
    assert t.at == datetime(2026, 11, 10, 20, 6, 16, tzinfo=UTC)
    west = snmp_clock.parse_date_and_time(dat(2026, 1, 2, 3, 4, 5, 6, tz=("-", 5, 30)))
    assert west is not None and west.at == datetime(2026, 1, 2, 8, 34, 5, 600_000, tzinfo=UTC)


def test_date_and_time_without_offset_is_local() -> None:
    t = snmp_clock.parse_date_and_time(dat(2026, 11, 10, 21, 6, 16, 0))
    assert t is not None and not t.has_offset
    assert t.at == datetime(2026, 11, 10, 21, 6, 16).astimezone()


@pytest.mark.parametrize(
    "raw",
    [
        None,
        42,
        b"",
        b"\x07\xea\x0b",  # too short
        dat(2026, 13, 1, 0, 0, 0, 0),  # month 13
        dat(2026, 1, 1, 0, 0, 0, 0, tz=("x", 1, 0)),  # no direction
        dat(2026, 1, 1, 0, 0, 0, 0, tz=("+", 15, 0)),  # no such offset
    ],
)
def test_date_and_time_rejects_garbage(raw: Any) -> None:
    assert snmp_clock.parse_date_and_time(raw) is None


def test_apc_clock() -> None:
    t = snmp_clock.parse_apc_clock(b"11/10/2026", b"19:42:39")
    assert t is not None and not t.has_offset
    assert t.at == datetime(2026, 11, 10, 19, 42, 39).astimezone()
    assert snmp_clock.parse_apc_clock(b"10.11.2026", b"19:42:39") is None
    assert snmp_clock.parse_apc_clock(None, b"19:42:39") is None


def test_offset_is_against_the_middle_of_the_read() -> None:
    before = datetime(2026, 11, 10, 18, 0, 0, tzinfo=UTC)
    after = before + timedelta(seconds=4)
    device = snmp_clock.DeviceTime(before + timedelta(seconds=2) - timedelta(seconds=11), True)
    facts = snmp_clock.clock_facts(device, before, after, "apc")
    assert facts["offset_s"] == -11.0 and facts["read_at"] == "2026-11-10T18:00:02+00:00"


class FakeClient:
    host = "192.0.2.9"

    def __init__(self, walks: dict[str, dict[str, Any]]) -> None:
        self.walks = walks
        self.asked: list[str] = []

    async def walk(self, oid: str) -> dict[str, Any]:
        self.asked.append(oid)
        return self.walks.get(oid, {})


def system(object_id: str) -> Any:
    from lanwatch.collectors.snmp import SystemInfo

    return SystemInfo(descr="", object_id=object_id, uptime_s=1, name="x", location="", contact="")


async def test_reader_prefers_hr_system_date_and_falls_back_to_apc() -> None:
    now = datetime.now(UTC)
    hr = (now.year).to_bytes(2, "big") + bytes(
        [now.month, now.day, now.hour, now.minute, now.second, 0]
    )
    client = FakeClient(
        {snmp_clock.HR_SYSTEM_DATE: {f"{snmp_clock.HR_SYSTEM_DATE}.0": hr + b"+\x00\x00"}}
    )
    res = await snmp_clock.read_clock(client, system("1.3.6.1.4.1.2636.1.1.1.2.133"))  # type: ignore[arg-type]
    assert res.facts["source"] == "hrSystemDate" and abs(res.facts["offset_s"]) < 5
    assert client.asked == [snmp_clock.HR_SYSTEM_DATE]

    local = datetime.now().astimezone() - timedelta(seconds=30)
    apc = FakeClient(
        {
            snmp_clock.APC_CLOCK: {
                snmp_clock.APC_DATE: local.strftime("%m/%d/%Y").encode(),
                snmp_clock.APC_TIME: local.strftime("%H:%M:%S").encode(),
            }
        }
    )
    res = await snmp_clock.read_clock(apc, system("1.3.6.1.4.1.318.1.3.27"))  # type: ignore[arg-type]
    assert res.facts["source"] == "apc" and -35 < res.facts["offset_s"] < -25
    assert res.facts["has_offset"] is False

    # Not APC and no hrSystemDate: no clock, and no walk of APC's tree.
    other = FakeClient({})
    res = await snmp_clock.read_clock(other, system("1.3.6.1.4.1.9.1.1"))  # type: ignore[arg-type]
    assert res.facts == {} and other.asked == [snmp_clock.HR_SYSTEM_DATE]


def test_reader_and_rules_are_found() -> None:
    from lanwatch.collectors.snmp_kinds import find_readers

    assert "clock" in [r.name for r in find_readers()]
    ids = [r.id for r in all_rules()]
    assert "snmp.clock-skew" in ids and "snmp.unreachable" in ids


@pytest.mark.parametrize(
    ("offset", "has_offset", "expected"),
    [
        (11, True, None),
        (-120, False, None),
        (121, True, (Severity.LOW, False)),
        (-1800, True, (Severity.LOW, False)),
        (3601, True, (Severity.MEDIUM, False)),
        # Without a zone, whole hours (within 2 min) are a time zone or DST setting.
        (3600 + 90, False, (Severity.LOW, True)),
        (-7200 + 30, False, (Severity.LOW, True)),
        (3600 + 600, False, (Severity.MEDIUM, False)),
        # With a zone, an hour off is a wrong clock.
        (3600, True, (Severity.LOW, False)),
        (3700, True, (Severity.MEDIUM, False)),
    ],
)
def test_classify_skew(offset: float, has_offset: bool, expected: object) -> None:
    assert classify_skew(offset, has_offset) == expected


def target(host: str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "host": host,
        "role": "device",
        "name": "",
        "system": {"name": "dev"},
        "last_ok": "2026-11-10T09:00:00+00:00",
        "last_error": "",
        "fails": 0,
        "facts": {},
    }
    return base | kw


def clock(offset_s: float, has_offset: bool = True) -> dict[str, Any]:
    return {
        "clock": {
            "offset_s": offset_s,
            "has_offset": has_offset,
            "device_time": "x",
            "read_at": "y",
            "source": "hrSystemDate",
        }
    }


def run(store: Store, config: Config, rows: dict[str, dict[str, Any]]) -> list[Any]:
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra("snmp-target", rows, sid)
    ctx = RuleContext(store, config, sid, None, is_baseline=False)
    return [
        f for f in Engine(config, [SnmpClockSkewRule(), SnmpUnreachableRule()]).run(ctx).emitted
    ]


def test_clock_skew_rule(store: Store, config: Config) -> None:
    found = run(
        store,
        config,
        {
            "192.0.2.1": target("192.0.2.1", role="router", facts=clock(11)),
            "192.0.2.9": target("192.0.2.9", name="ups", facts=clock(-3600 - 30, False)),
            "192.0.2.10": target("192.0.2.10", facts=clock(5400)),
            "192.0.2.11": target("192.0.2.11", facts=clock(400)),
            # Failing: its clock is stale, so no skew finding.
            "192.0.2.12": target("192.0.2.12", facts=clock(9999), fails=1, last_error="x"),
            "192.0.2.13": target("192.0.2.13"),  # no clock read
        },
    )
    by_host = {f.evidence["host"]: f for f in found if f.rule_id == "snmp.clock-skew"}
    assert set(by_host) == {"192.0.2.9", "192.0.2.10", "192.0.2.11"}
    assert (
        by_host["192.0.2.9"].title
        == "ups (192.0.2.9): clock 1 h behind, a time zone or summer time setting"
    )
    assert by_host["192.0.2.9"].severity == Severity.LOW
    assert by_host["192.0.2.10"].severity == Severity.MEDIUM
    assert by_host["192.0.2.10"].title == "dev (192.0.2.10): clock 1.5 h ahead"
    assert by_host["192.0.2.11"].title == "dev (192.0.2.11): clock 7 min ahead"


def test_unreachable_counts_and_resolves(store: Store, config: Config) -> None:
    rows = {
        "192.0.2.1": target("192.0.2.1", role="router", fails=3, last_error="Timeout"),
        "192.0.2.9": target("192.0.2.9", fails=2, last_error="Timeout"),
        "192.0.2.66": target("192.0.2.66", system=None, last_ok=None, fails=5, last_error="t"),
    }
    found = [f for f in run(store, config, rows) if f.rule_id == "snmp.unreachable"]
    titles = {f.evidence["host"]: (f.title, f.severity) for f in found}
    assert titles == {
        "192.0.2.1": ("SNMP: dev (192.0.2.1) not read for 3 rounds", Severity.MEDIUM),
        "192.0.2.66": ("SNMP: 192.0.2.66 never read", Severity.LOW),
    }
    assert found[0].evidence["help"] == "docs/snmp.md, Troubleshooting"

    rows["192.0.2.1"] = target("192.0.2.1", role="router")
    rows["192.0.2.66"] = target("192.0.2.66")
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra("snmp-target", rows, sid)
    res = Engine(config, [SnmpUnreachableRule()]).run(
        RuleContext(store, config, sid, None, is_baseline=False)
    )
    assert res.emitted == [] and len(res.resolved_ids) == 2
