"""UPS over SNMP: parsing a real APC Smart-UPS 3000 / AP9630 recording (serials replaced),
the reader through the collector, and the UPS rules."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from lanwatch import pipeline
from lanwatch.collectors import snmp_ups
from lanwatch.collectors.snmp import parse_system, parse_walk
from lanwatch.config import Config
from lanwatch.models import HostObservation, iso, now_utc
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store
from tests.conftest import FIXTURES, snmp_devices
from tests.test_snmp import fake_walker

UPS = "192.0.2.9"


def _walk(name: str) -> dict[str, Any]:
    return parse_walk((FIXTURES / f"snmp-ups-{name}.txt").read_text())


def _facts() -> dict[str, Any]:
    descr = parse_system(_walk("system")).descr
    facts, _ = snmp_ups.parse_ups(_walk("upsmib"), _walk("powernet"), descr)
    return facts


def test_fixtures_carry_no_serial_numbers() -> None:
    for name in ("system", "upsmib", "powernet"):
        raw = (FIXTURES / f"snmp-ups-{name}.txt").read_text()
        for serial in ("AS1424144803", "ZA1531020871"):
            assert serial not in raw
            assert " ".join(f"{b:02X}" for b in serial.encode()) not in raw


def test_parse_a_real_smart_ups() -> None:
    facts = _facts()
    assert facts["model"] == "Smart-UPS 3000" and facts["sku"] == "SMT3000RMI2U"
    assert facts["firmware"] == "UPS 08.8 (ID18)"
    assert facts["communication_ok"] is True
    assert facts["on_battery"] is False and facts["output_status"] == "on line"
    assert facts["battery_status"] == "normal" and facts["charge_pct"] == 100
    assert facts["runtime_min"] == 146 and facts["battery_c"] == 23
    assert facts["load_pct"] == 5 and facts["load_w"] == 121 and facts["load_va"] == 150
    assert (facts["input_v"], facts["input_v_min"], facts["input_v_max"]) == (231, 231, 233)
    assert (facts["transfer_low_v"], facts["transfer_high_v"]) == (207, 253)
    assert facts["battery_replace"] is False and facts["battery_cartridge"] == "RBC43"
    # The UPS's own dates are dd.mm.yyyy, the card's mm/dd/yyyy.
    assert facts["battery_last_replaced"] == "2025-12-15"
    assert facts["battery_replace_by"] == "2030-05-31"
    assert facts["manufactured"] == "2014-06-13"
    assert facts["self_test_date"] == "2026-11-06" and facts["self_test_result"] == "ok"
    assert facts["self_test_every_days"] == 14
    assert facts["calibration_date"] is None  # "Unknown"
    assert facts["alarms"] == [] and facts["last_transfer_cause"] == "no transfer"
    assert facts["card"]["model"] == "AP9630" and facts["card"]["application"] == "7.2.2"
    assert "serial" not in " ".join(facts)


def test_dates_by_their_own_format() -> None:
    assert snmp_ups.ups_date(b"15.12.2025") == "2025-12-15"
    assert snmp_ups.ups_date(b"12/15/25") == "2025-12-15"  # as PowerNet documents it
    assert snmp_ups.ups_date(b"31.02.2025") is None
    assert snmp_ups.ups_date(b"Unknown") is None and snmp_ups.ups_date(None) is None
    assert snmp_ups.card_date(b"11/06/2026") == "2026-11-06"
    assert snmp_ups.card_date(b"11/06/26") == "2026-11-06"
    assert snmp_ups.card_date(b"06.11.2026") is None  # not a format the card writes


def test_card_firmware_against_the_pinned_latest() -> None:
    descr = parse_system(_walk("system")).descr
    fw = snmp_ups.card_firmware(descr, "t")
    assert fw is not None
    assert (fw["product"], fw["version"], fw["model"], fw["latest"], fw["update"]) == (
        "APC NMC",
        "7.2.2",
        "AP9630",
        "7.2.2",
        False,
    )
    older = snmp_ups.card_firmware(descr.replace("AF1:v7.2.2", "AF1:v6.9.6"), "t")
    assert older is not None and older["update"] is True
    unknown = snmp_ups.card_firmware(descr.replace("MN:AP9630", "MN:AP9641"), "t")
    assert unknown is not None and unknown["latest"] is None and unknown["update"] is None


def _powernet_walks(tmp_path: Path) -> None:
    """Serve the recordings per walked OID, the way the reader asks for them."""
    walks = tmp_path / "walks"
    walks.mkdir(exist_ok=True)
    (walks / snmp_ups.UPS_MIB).write_text((FIXTURES / "snmp-ups-upsmib.txt").read_text())
    lines = (FIXTURES / "snmp-ups-powernet.txt").read_text().splitlines()
    for part in snmp_ups.POWERNET_PARTS:
        prefix = f".{snmp_ups.POWERNET_UPS}.{part}."
        (walks / f"{snmp_ups.POWERNET_UPS}.{part}").write_text(
            "\n".join(x for x in lines if x.startswith(prefix)) + "\n"
        )


async def test_reader_through_the_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    config.snmp = snmp_devices(ups={"host": UPS})
    disc = store.begin_snapshot("discovery", "t")
    store.record_hosts(disc, [HostObservation(ip=UPS, mac="aa:bb:cc:00:00:09", source="t")])
    store.finish_snapshot(disc, 1)
    rec = fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-ups-system.txt").read_text())
    _powernet_walks(tmp_path)
    await pipeline.collect_snmp(config, store, store.begin_snapshot("infra", "t"))

    (row,) = store.infra("snmp-target")
    ups = row.data["facts"]["ups"]
    assert ups["runtime_min"] == 146 and ups["battery_cartridge"] == "RBC43"
    walked = (rec / "args").read_text()
    assert "1.3.6.1.4.1.318.1.4" not in walked  # never the experimental branch
    assert [v for _, v in store.snmp_series(UPS, "ups.load_w", "")] == [121.0]
    assert [v for _, v in store.snmp_series(UPS, "ups.input_v", "")] == [231.0]
    d = store.device_by_ip(UPS)
    assert d is not None and d.attrs["firmware"]["product"] == "APC NMC"


async def test_a_device_without_ups_mib_gets_no_ups_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    config.snmp = snmp_devices(srx={"host": UPS})
    rec = fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    (tmp_path / "walks" / snmp_ups.UPS_IDENT).write_text("")
    await pipeline.collect_snmp(config, store, store.begin_snapshot("infra", "t"))
    (row,) = store.infra("snmp-target")
    assert row.data["facts"]["ups"] == {}
    # A Juniper box is asked for upsIdent only, nothing more.
    walked = (rec / "args").read_text()
    assert snmp_ups.UPS_IDENT in walked and "318.1.1.1" not in walked
    assert store.snmp_series(UPS, "ups.load_w", "") == []


# -- rules -------------------------------------------------------------------------------


def _with_ups(store: Store, config: Config, **changes: Any) -> int:
    """Store one read UPS (the recording, with `changes`) and return the snapshot id."""
    config.snmp = snmp_devices(ups={"host": UPS})
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra(
        "snmp-target",
        {
            UPS: {
                "host": UPS,
                "role": "device",
                "name": "ups",
                "system": {"vendor": "APC"},
                "last_ok": iso(now_utc()),
                "last_error": "",
                "fails": 0,
                "facts": {"ups": _facts() | changes},
            }
        },
        sid,
    )
    return sid


def _titles(store: Store, config: Config, sid: int, rule: str) -> list[str]:
    ctx = RuleContext(store, config, sid, None, is_baseline=False)
    return [f.title for f in Engine(config).run(ctx).emitted if f.rule_id == rule]


def test_a_healthy_ups_raises_nothing(store: Store, config: Config) -> None:
    sid = _with_ups(store, config)
    ctx = RuleContext(store, config, sid, None, is_baseline=False)
    assert [f for f in Engine(config).run(ctx).emitted if f.rule_id.startswith("ups.")] == []


def test_on_battery_low_and_the_power_event(store: Store, config: Config) -> None:
    sid = _with_ups(
        store,
        config,
        on_battery=True,
        output_status="on battery",
        seconds_on_battery=300,
        runtime_min=8,
        last_transfer_cause="blackout",
    )
    assert _titles(store, config, sid, "ups.on-battery") == [
        "ups (192.0.2.9) is on battery, 8 min left"
    ]
    ctx = RuleContext(store, config, sid, None, is_baseline=False)
    emitted = Engine(config).run(ctx).emitted
    low = [f for f in emitted if f.rule_id == "ups.battery-low"]
    assert len(low) == 1 and low[0].severity == "critical"
    events = [f for f in emitted if f.rule_id == "ups.power-event"]
    assert len(events) == 1 and "(blackout)" in events[0].title
    # Power back: on-battery resolves, the event stays until acknowledged.
    sid2 = _with_ups(store, config)
    result = Engine(config).run(RuleContext(store, config, sid2, None, is_baseline=False))
    open_ids = {f.id for f in store.findings()}
    assert events[0].id in open_ids
    assert any(i for i in result.resolved_ids)


def test_low_battery_without_mains_loss_is_medium(store: Store, config: Config) -> None:
    sid = _with_ups(store, config, battery_status="low")
    ctx = RuleContext(store, config, sid, None, is_baseline=False)
    (f,) = [f for f in Engine(config).run(ctx).emitted if f.rule_id == "ups.battery-low"]
    assert f.severity == "medium" and "battery low" in f.title


def test_battery_replace_alarm_and_self_test(store: Store, config: Config) -> None:
    long_ago = (datetime.now(UTC) - timedelta(days=40)).date().isoformat()
    sid = _with_ups(
        store,
        config,
        battery_replace=True,
        battery_replace_by="2020-01-01",
        alarms=["on battery", "fan failure"],
        self_test_date=long_ago,
    )
    (replace,) = _titles(store, config, sid, "ups.battery-replace")
    assert "RBC43" in replace
    assert _titles(store, config, sid, "ups.alarm") == ["ups (192.0.2.9): fan failure"]
    (stale,) = _titles(store, config, sid, "ups.self-test-stale")
    assert "40 days ago" in stale and "every 14" in stale
    sid = _with_ups(store, config, self_test_result="failed")
    assert _titles(store, config, sid, "ups.self-test-stale") == [
        "ups (192.0.2.9): the last self-test failed (2026-11-06)"
    ]


def test_lost_card_link_silences_the_other_rules(store: Store, config: Config) -> None:
    sid = _with_ups(
        store, config, communication_ok=False, on_battery=True, battery_status="depleted"
    )
    ctx = RuleContext(store, config, sid, None, is_baseline=False)
    ids = {f.rule_id for f in Engine(config).run(ctx).emitted if f.rule_id.startswith("ups.")}
    assert ids == {"ups.no-communication"}


def test_a_failed_read_is_not_current(store: Store, config: Config) -> None:
    sid = _with_ups(store, config, on_battery=True)
    (row,) = store.infra("snmp-target")
    store.replace_infra("snmp-target", {UPS: row.data | {"last_error": "Timeout"}}, sid)
    assert _titles(store, config, sid, "ups.on-battery") == []


# -- web ---------------------------------------------------------------------------------


def test_ups_on_the_device_page_and_dashboard(config: Config) -> None:
    from fastapi.testclient import TestClient

    from lanwatch.web.app import create_app

    assert "_ups_tile" not in TestClient(create_app(config)).get("/").text
    assert 'aria-label="UPS load' not in TestClient(create_app(config)).get("/").text

    with Store(config.store_path) as store:
        disc = store.begin_snapshot("discovery", "t")
        store.record_hosts(disc, [HostObservation(ip=UPS, mac="aa:bb:cc:00:00:09", source="t")])
        store.finish_snapshot(disc, 1)
        sid = _with_ups(store, config, on_battery=True, seconds_on_battery=120, runtime_min=40)
        device = store.device_by_ip(UPS)
        assert device is not None
        fw = snmp_ups.card_firmware(parse_system(_walk("system")).descr, iso(now_utc()))
        store.merge_device_attrs(device.id, {"firmware": fw})
        now = now_utc()
        for i, (w, v) in enumerate(((110, 231), (121, 229), (300, 236))):
            ts = iso(now - timedelta(hours=3 - i))
            store.add_snmp_series(UPS, {"ups.load_w": w, "ups.input_v": v}, ts=ts)
        store.add_snmp_series(UPS, {"ups.load_w": 50}, ts=iso(now - timedelta(days=3)))
        Engine(config).run(RuleContext(store, config, sid, None, is_baseline=False))

    client = TestClient(create_app(config))
    page = client.get(f"/devices/{device.id}").text
    assert 'id="ups"' in page and "on battery" in page
    assert "RBC43" in page and "2030-05-31" in page
    assert "AP9630" in page and "newest" in page
    assert page.count('class="ups-chart"') == 2  # load and input voltage have readings
    assert 'class="ref"' in page and ">207 V<" in page and ">253 V<" in page
    assert "Went on battery" in page
    week = client.get(f"/devices/{device.id}?range=7d").text
    assert 'href="?range=7d#ups" aria-current="true"' in week
    dash = client.get("/").text
    assert "UPS ups" in dash and "40 min runtime" in dash and f"/devices/{device.id}#ups" in dash
    assert 'aria-label="UPS load' in dash
