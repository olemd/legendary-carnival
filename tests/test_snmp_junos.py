"""Junos extras: the reader's parsing (from a recording of an SRX300), its silence on a
device that lacks the tables, and the rules over what it found."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from lanwatch import pipeline
from lanwatch.collectors import snmp, snmp_junos
from lanwatch.collectors.snmp_junos import date_and_time, parse_junos
from lanwatch.config import Config, SnmpConfig
from lanwatch.models import HostObservation, Severity, iso, now_utc
from lanwatch.rules import junos
from lanwatch.rules.base import Rule, RuleContext
from lanwatch.store import Store
from lanwatch.web.app import create_app
from tests.conftest import FIXTURES, snmp_devices
from tests.test_snmp import fake_walker

HOST = "192.0.2.5"


def recording() -> dict[str, snmp.Value]:
    return snmp.parse_walk((FIXTURES / "snmp-junos.txt").read_text())


def test_date_and_time() -> None:
    # 2026-11-10 10:22:20 +01:00, as the SRX reports its last commit.
    assert (
        date_and_time(bytes.fromhex("07EA0B0A0A16140" + "02B0100")) == "2026-11-10T09:22:20+00:00"
    )
    # Without the offset octets: the device's local time, read as lanwatch's local zone,
    # the same as the clock reader (snmp_clock.parse_date_and_time).
    local = datetime(2026, 11, 10, 10, 22, 20).astimezone()
    assert date_and_time(bytes.fromhex("07EA0B0A0A161400")) == local.astimezone(UTC).isoformat()
    assert date_and_time(bytes.fromhex("07EA0B0A0A1614002D011E")) == "2026-11-10T11:52:20+00:00"
    assert date_and_time(bytes(8)) is None  # zero: never
    assert date_and_time(b"\x07\xea\x0d\x01\x00\x00\x00\x00") is None  # month 13
    assert date_and_time(b"short") is None and date_and_time(5) is None


def test_parse_the_srx300_recording() -> None:
    facts = parse_junos(recording())
    assert facts["alarms"] == {
        "red": {"on": False, "count": 0},
        "yellow": {"on": False, "count": 0},
    }
    engine = next(c for c in facts["components"] if c["descr"] == "Routing Engine")
    assert engine == {
        "index": "9.1.0.0",
        "descr": "Routing Engine",
        "state": "running",
        "temp_c": 48,
        "cpu_pct": 17,
        "mem_pct": 33,
    }
    # No sensor reads as 0 and is shown as unknown, not as 0 °C.
    assert next(c for c in facts["components"] if c["descr"] == "midplane")["temp_c"] is None
    assert {f["name"]: f["state"] for f in facts["frus"]}["USB Hub"] == "empty"
    # Only real flash partitions, once each: devfs, procfs and the read-only image (all
    # 100 %) and the second mounts of the same partitions are left out.
    assert facts["storage"] == [
        {"device": "/dev/da0s2a", "mount": "/", "used_pct": 18},
        {"device": "/dev/bo0s3e", "mount": "/config", "used_pct": 0},
        {"device": "/dev/bo0s3f", "mount": "/cf/var", "used_pct": 32},
    ]
    events = facts["config"]["events"]
    assert facts["config"]["latest_index"] == 16 and len(events) == 16
    assert events == sorted(events, key=lambda e: e["at"])
    assert events[-1] == {
        "index": 16,
        "at": "2026-11-10T09:22:20+00:00",
        "source": "cli",
        "user": "admin",
    }
    assert {e["user"] for e in events} == {"admin", "ops"}
    assert facts["rescue"] == {"saved": True, "at": "2024-07-27T16:38:43+00:00", "user": "admin"}
    assert facts["sessions"] == [{"node": "0", "current": 285, "max": 65536}]
    (zone,) = facts["screens"]
    assert zone["zone"] == "untrust" and zone["counts"]["syn_flood"] == 2342
    assert [x["feature"] for x in facts["licences"]] == [
        "remote-access-ipsec-vpn-client",
        "remote-access-juniper-std",
    ]
    assert facts["dhcp_declines"] == 111


def test_missing_tables_are_left_out_quietly(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="lanwatch.collectors.snmp_junos")
    assert parse_junos({}) == {}
    assert all(r.levelno <= logging.DEBUG for r in caplog.records)
    # A switch: chassis and alarms, no security sessions, screens or DHCP server.
    values = {k: v for k, v in recording().items() if k.startswith(snmp_junos.ALARM_RED)}
    assert set(parse_junos(values)) == {"alarms"}


def _walks_from_recording(tmp_path: Path, empty: bool = False) -> None:
    values = (FIXTURES / "snmp-junos.txt").read_text().splitlines()
    for oid in snmp_junos.SUBTREES:
        lines = [] if empty else [x for x in values if x.startswith(f".{oid}.")]
        (tmp_path / "walks" / oid).write_text("\n".join(lines) + "\n")


def _device_config(config: Config) -> None:
    config.snmp = snmp_devices(srx={"host": HOST})


async def test_reader_runs_on_juniper_and_stores_its_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    _device_config(config)
    rec = fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    _walks_from_recording(tmp_path)
    await pipeline.collect_snmp(config, store, store.begin_snapshot("infra", "t"))
    (row,) = store.infra("snmp-target")
    assert row.data["reader_errors"] == {}
    assert row.data["facts"]["junos"]["dhcp_declines"] == 111
    walked = (rec / "args").read_text()
    # Named subtrees only, never the whole Juniper tree.
    assert " 1.3.6.1.4.1.2636\n" not in walked
    assert all(oid in walked for oid in snmp_junos.SUBTREES)


async def test_reader_on_a_device_without_the_tables_is_silent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    store: Store,
    config: Config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    _device_config(config)
    fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    _walks_from_recording(tmp_path, empty=True)
    await pipeline.collect_snmp(config, store, store.begin_snapshot("infra", "t"))
    (row,) = store.infra("snmp-target")
    # Other readers may add facts of their own; the Junos reader found nothing to report
    # and did not fail.
    assert row.data["facts"]["junos"] == {} and "junos" not in row.data["reader_errors"]
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    ctx = RuleContext(store, config, 0, None, is_baseline=False)
    assert [f for rule in junos.RULES for f in rule.evaluate(ctx)] == []


# -- rules ---------------------------------------------------------------------------------


def _with_facts(
    store: Store, config: Config, facts: dict[str, Any], read_at: str = "2026-11-10T10:00:00+00:00"
) -> RuleContext:
    _device_config(config)
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra(
        "snmp-target",
        {
            HOST: {
                "host": HOST,
                "role": "device",
                "name": "srx",
                "system": {"name": "srx-sys", "vendor": "Juniper"},
                "last_ok": read_at,
                "last_error": "",
                "fails": 0,
                "facts": {"junos": facts},
            }
        },
        sid,
    )
    return RuleContext(store, config, sid, None, is_baseline=False)


def _run(rule: Rule, ctx: RuleContext) -> list[tuple[str, Severity]]:
    return [(f.title, f.severity) for f in rule.evaluate(ctx)]


def test_chassis_alarm(store: Store, config: Config) -> None:
    ctx = _with_facts(
        store,
        config,
        {"alarms": {"red": {"on": True, "count": 1}, "yellow": {"on": True, "count": 2}}},
    )
    assert _run(junos.ChassisAlarmRule(), ctx) == [
        ("srx: red chassis alarm on", Severity.HIGH),
        ("srx: yellow chassis alarm on", Severity.MEDIUM),
    ]
    ctx = _with_facts(store, config, {"alarms": {"red": {"on": False, "count": 0}}})
    assert _run(junos.ChassisAlarmRule(), ctx) == []


def test_storage_full(store: Store, config: Config) -> None:
    parts = [
        {"device": "/dev/da0s2a", "mount": "/", "used_pct": 90},
        {"device": "/dev/bo0s3f", "mount": "/cf/var", "used_pct": 95},
    ]
    ctx = _with_facts(store, config, {"storage": parts})
    assert _run(junos.StorageFullRule(), ctx) == [("srx: /cf/var is 95 % full", Severity.MEDIUM)]


def test_fru_not_online(store: Store, config: Config) -> None:
    frus = [
        {"index": "2.1.0.0", "name": "PEM 0", "state": "fault"},
        {"index": "2.2.0.0", "name": "PEM 1", "state": "offline"},
        {"index": "9.1.1.0", "name": "USB Hub", "state": "empty"},
        {"index": "9.1.0.0", "name": "Routing Engine", "state": "online"},
    ]
    ctx = _with_facts(store, config, {"frus": frus})
    assert _run(junos.FruNotOnlineRule(), ctx) == [
        ("srx: PEM 0 is fault", Severity.HIGH),
        ("srx: PEM 1 is offline", Severity.MEDIUM),
    ]


def test_session_table_full(store: Store, config: Config) -> None:
    ctx = _with_facts(
        store,
        config,
        {
            "sessions": [
                {"node": "0", "current": 56000, "max": 65536},
                {"node": "1", "current": 285, "max": 65536},
            ]
        },
    )
    assert _run(junos.SessionTableFullRule(), ctx) == [
        ("srx: session table 85% full", Severity.MEDIUM)
    ]


def test_config_changed_only_after_lanwatch_started_watching(store: Store, config: Config) -> None:
    events = [
        {"index": 15, "at": "2020-01-01T00:00:00+00:00", "source": "cli", "user": "ops"},
        {"index": 16, "at": "2099-01-01T00:00:00+00:00", "source": "junoscript", "user": "admin"},
    ]
    ctx = _with_facts(store, config, {"config": {"latest_index": 16, "events": events}})
    rule = junos.ConfigChangedRule()
    assert _run(rule, ctx) == [("srx: configuration changed by admin (junoscript)", Severity.INFO)]


def test_config_changed_resolves_after_a_week(store: Store, config: Config) -> None:
    """A commit is a finding for a week, then resolves by itself: none to acknowledge."""
    rule = junos.ConfigChangedRule()
    assert rule.auto_resolve

    def commit_ago(days: float) -> RuleContext:
        at = iso(now_utc() - timedelta(days=days))
        ev = {"index": 17, "at": at, "source": "cli", "user": "ops"}
        facts = {"config": {"latest_index": 17, "events": [ev]}}
        ctx = _with_facts(store, config, facts)
        # lanwatch has watched the device for a month, so the commit is not "from before".
        month_ago = iso(now_utc() - timedelta(days=30))
        store._db.execute(
            "UPDATE infra SET first_seen = ? WHERE kind = 'snmp-target'", (month_ago,)
        )
        return ctx

    assert len(_run(rule, commit_ago(6))) == 1
    assert _run(rule, commit_ago(8)) == []


def test_no_rescue_config(store: Store, config: Config) -> None:
    ctx = _with_facts(store, config, {"rescue": {"saved": False, "at": None, "user": ""}})
    assert _run(junos.NoRescueConfigRule(), ctx) == [
        ("srx: no rescue configuration saved", Severity.LOW)
    ]
    ctx = _with_facts(store, config, {"rescue": {"saved": True, "at": None, "user": ""}})
    assert _run(junos.NoRescueConfigRule(), ctx) == []
    ctx = _with_facts(store, config, {})
    assert _run(junos.NoRescueConfigRule(), ctx) == []


def test_dhcp_declines_rising_counts_each_read_once(store: Store, config: Config) -> None:
    rule = junos.DhcpDeclinesRisingRule()
    # The first read has nothing to compare with.
    ctx = _with_facts(store, config, {"dhcp_declines": 111}, read_at="2026-11-10T10:00:00+00:00")
    assert _run(rule, ctx) == []
    ctx = _with_facts(store, config, {"dhcp_declines": 114}, read_at="2026-11-10T10:15:00+00:00")
    found = rule.evaluate(ctx)
    assert [f.title for f in found] == ["srx: 3 DHCP declines since the previous read"]
    assert found[0].evidence == {"host": HOST, "new": 3, "total": 114, "before": 111}
    # Rules run more often than the device is read: the same read keeps the same answer.
    assert [f.title for f in rule.evaluate(ctx)] == ["srx: 3 DHCP declines since the previous read"]
    ctx = _with_facts(store, config, {"dhcp_declines": 114}, read_at="2026-11-10T10:30:00+00:00")
    assert _run(rule, ctx) == []
    # A reboot resets the counter: no growth.
    ctx = _with_facts(store, config, {"dhcp_declines": 2}, read_at="2026-11-10T10:45:00+00:00")
    assert _run(rule, ctx) == []


def test_rules_ignore_targets_no_longer_configured(store: Store, config: Config) -> None:
    ctx = _with_facts(store, config, {"alarms": {"red": {"on": True, "count": 1}}})
    config.snmp = SnmpConfig()
    assert _run(junos.ChassisAlarmRule(), ctx) == []


def test_device_page_shows_the_junos_block(config: Config) -> None:
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(sid, [HostObservation(ip=HOST, mac="aa:bb:cc:00:00:05", source="t")])
        store.finish_snapshot(sid, 1)
        _with_facts(store, config, parse_junos(recording()))
        device = store.device_by_ip(HOST)
        assert device is not None
    page = TestClient(create_app(config)).get(f"/devices/{device.id}").text
    assert "<dt>Junos</dt>" in page
    assert "routing engine running" in page and "CPU 17 %" in page and "48 °C" in page
    assert "no chassis alarms" in page and "sessions 285 of 65536" in page
    assert "by admin (cli)" in page
