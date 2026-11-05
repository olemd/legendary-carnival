from __future__ import annotations

from pathlib import Path
from typing import Any

from lanwatch.config import Config, RuleOverride
from lanwatch.models import FindingStatus, HostObservation, Severity
from lanwatch.overview import render, update
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store


def _round(store: Store, config: Config, hosts: list[HostObservation]) -> RuleContext:
    baseline = store.finished_snapshot_count("discovery") == 0
    prev = store.latest_snapshot("discovery")
    sid = store.begin_snapshot("discovery", "test")
    rec = store.record_hosts(sid, hosts)
    store.finish_snapshot(sid, len(rec.seen_device_ids))
    return RuleContext(
        store=store,
        config=config,
        snapshot_id=sid,
        previous_snapshot_id=prev.id if prev else None,
        is_baseline=baseline,
        new_device_ids=rec.new_device_ids,
        ip_changes=rec.ip_changes,
    )


def test_baseline_then_new_device(store: Store, config: Config) -> None:
    engine = Engine(config)
    ctx = _round(
        store, config, [HostObservation(ip="10.0.0.1", mac="aa:bb:cc:00:00:01", source="t")]
    )
    assert ctx.is_baseline
    assert engine.run(ctx).emitted == []

    ctx = _round(
        store,
        config,
        [
            HostObservation(ip="10.0.0.1", mac="aa:bb:cc:00:00:01", source="t"),
            HostObservation(ip="10.0.0.2", mac="aa:bb:cc:00:00:02", vendor="Acme", source="t"),
        ],
    )
    res = engine.run(ctx)
    assert [f.rule_id for f in res.emitted] == ["inventory.new-device"]
    assert res.emitted[0].severity is Severity.MEDIUM
    assert res.emitted[0].evidence["mac"] == "aa:bb:cc:00:00:02"

    # Next round without changes: event-style finding stays open.
    ctx = _round(
        store, config, [HostObservation(ip="10.0.0.1", mac="aa:bb:cc:00:00:01", source="t")]
    )
    engine.run(ctx)
    assert len(store.findings(FindingStatus.OPEN)) == 1


def test_rule_overrides(store: Store, config: Config) -> None:
    config.rules["inventory.new-device"] = RuleOverride(severity=Severity.CRITICAL)
    config.rules["inventory.ip-changed"] = RuleOverride(enabled=False)
    engine = Engine(config)
    engine.run(
        _round(store, config, [HostObservation(ip="10.0.0.1", mac="aa:bb:cc:00:00:01", source="t")])
    )
    res = engine.run(
        _round(
            store,
            config,
            [
                HostObservation(ip="10.0.0.5", mac="aa:bb:cc:00:00:01", source="t"),
                HostObservation(ip="10.0.0.2", mac="aa:bb:cc:00:00:02", source="t"),
            ],
        )
    )
    assert res.skipped_rules == ["inventory.ip-changed"]
    assert [f.severity for f in res.emitted] == [Severity.CRITICAL]


def test_overview_renders_and_writes_only_on_change(
    store: Store, config: Config, tmp_path: Path
) -> None:
    engine = Engine(config)
    engine.run(
        _round(
            store,
            config,
            [HostObservation(ip="10.0.0.1", mac="aa:bb:cc:00:00:01", hostname="gw", source="t")],
        )
    )
    engine.run(
        _round(
            store,
            config,
            [
                HostObservation(ip="10.0.0.1", mac="aa:bb:cc:00:00:01", source="t"),
                HostObservation(ip="10.0.0.2", mac="aa:bb:cc:00:00:02", source="t"),
            ],
        )
    )
    text = render(store, config)
    assert "# Network overview" in text
    assert "| ● |" in text and "gw" in text
    assert "inventory.new-device" not in text  # titles, not rule ids, in the table
    assert "New device:" in text

    path = update(store, config)
    assert path == config.overview_path and path.exists()
    assert update(store, config) is None  # unchanged content -> no rewrite


def test_watched_device_offline_raises_and_resolves(store: Store, config: Config) -> None:
    engine = Engine(config)
    nas = HostObservation(ip="10.0.0.5", mac="00:11:32:00:00:05", hostname="nas", source="t")
    tv = HostObservation(ip="10.0.0.6", mac="a4:77:33:00:00:06", hostname="tv", source="t")
    engine.run(_round(store, config, [nas, tv]))
    nas_dev = store.device_by_key("00:11:32:00:00:05")
    assert nas_dev is not None
    store.edit_device(nas_dev.id, name="NAS", kind=None, description=None, watch=True)

    def offline_findings() -> list[str]:
        return [
            f.title
            for f in store.findings(FindingStatus.OPEN)
            if f.rule_id == "inventory.watched-offline"
        ]

    # One missed round is not an outage; the default waits for two in a row.
    engine.run(_round(store, config, [tv]))
    assert offline_findings() == []
    result = engine.run(_round(store, config, [tv]))
    assert offline_findings() == ["Watched device offline: NAS"]
    assert len(result.new_ids) == 1  # new finding, so it is notified like any other
    f = store.finding(result.new_ids[0])
    assert f is not None and f.severity is Severity.HIGH and f.evidence["missed_rounds"] == 2

    # Still gone: same finding, no new one. The unwatched TV never raises anything.
    assert engine.run(_round(store, config, [])).new_ids == []
    assert offline_findings() == ["Watched device offline: NAS"]

    # Back: resolves by itself.
    result = engine.run(_round(store, config, [nas, tv]))
    assert offline_findings() == [] and len(result.resolved_ids) == 1

    # Unwatched again: going away is nobody's business.
    store.set_device_watch(nas_dev.id, False)
    for _ in range(3):
        engine.run(_round(store, config, [tv]))
    assert offline_findings() == []


def _open_titles(store: Store, rule_id: str) -> list[str]:
    return [f.title for f in store.findings(FindingStatus.OPEN) if f.rule_id == rule_id]


def test_two_devices_answering_for_one_ip(store: Store, config: Config) -> None:
    engine = Engine(config)
    printer = HostObservation(
        ip="10.0.0.60", mac="00:1e:c0:00:00:60", hostname="printer", source="t"
    )
    laptop = HostObservation(ip="10.0.0.20", mac="f0:18:98:00:00:20", source="t")
    engine.run(_round(store, config, [printer, laptop]))
    assert _open_titles(store, "net.ip-conflict") == []

    # Someone gave another machine the printer's address.
    clash = HostObservation(ip="10.0.0.60", mac="b8:27:eb:00:00:99", source="t")
    result = engine.run(_round(store, config, [printer, laptop, clash]))
    (title,) = _open_titles(store, "net.ip-conflict")
    assert title.startswith("Two devices answer for 10.0.0.60:")
    assert "00:1e:c0:00:00:60 (printer)" in title and "b8:27:eb:00:00:99" in title
    f = next(f for f in store.findings() if f.rule_id == "net.ip-conflict")
    assert f.severity is Severity.HIGH and f.id in result.new_ids

    # Sorted out: resolves by itself.
    engine.run(_round(store, config, [printer, laptop]))
    assert _open_titles(store, "net.ip-conflict") == []

    # The same address seen once with and once without a MAC is not two devices.
    no_mac = HostObservation(ip="10.0.0.20", source="t")
    engine.run(_round(store, config, [printer, laptop, no_mac]))
    assert _open_titles(store, "net.ip-conflict") == []


def test_gateway_answering_from_another_mac(store: Store, config: Config) -> None:
    import json

    engine = Engine(config)
    router = HostObservation(ip="10.0.0.1", mac="74:ac:b9:00:00:01", hostname="gw", source="t")
    laptop = HostObservation(ip="10.0.0.20", mac="f0:18:98:00:00:20", hostname="mbp", source="t")
    rule = "net.infrastructure-mac-changed"

    def discovery(hosts: list[HostObservation]) -> None:
        ctx = _round(store, config, hosts)
        # What run_discovery does between recording the round and running the rules.
        store.meta_set("net.gateways", json.dumps(["10.0.0.1"]))
        store.pin_infrastructure(["10.0.0.1"])
        engine.run(ctx)

    discovery([router, laptop])
    assert store.meta_get("net.pin.10.0.0.1") == "74:ac:b9:00:00:01"
    discovery([router, laptop])
    assert _open_titles(store, rule) == []

    # The laptop starts answering for the gateway address as well: a conflict on an
    # address everything depends on, so critical.
    spoof = HostObservation(ip="10.0.0.1", mac="f0:18:98:00:00:20", source="t")
    discovery([router, spoof])
    conflict = next(f for f in store.findings() if f.rule_id == "net.ip-conflict")
    assert conflict.severity is Severity.CRITICAL and "(gateway)" in conflict.title
    assert _open_titles(store, rule) == []  # the real gateway still answers too

    # Only the impostor answers: the gateway address has changed hands.
    discovery([spoof])
    (title,) = _open_titles(store, rule)
    assert (
        title == "Gateway 10.0.0.1 now answers from f0:18:98:00:00:20 (mbp), was 74:ac:b9:00:00:01"
    )
    f = next(f for f in store.findings() if f.rule_id == rule)
    assert f.severity is Severity.CRITICAL and f.evidence["first_seen_mac"] == "74:ac:b9:00:00:01"
    assert store.meta_get("net.pin.10.0.0.1") == "74:ac:b9:00:00:01"  # the pin does not follow

    # The real router is back alone: resolved. Gateway offline for a round: nothing to say.
    discovery([router, laptop])
    assert _open_titles(store, rule) == []
    discovery([laptop])
    assert _open_titles(store, rule) == []


def test_infrastructure_addresses_come_from_routes_and_dhcp(store: Store) -> None:
    import json

    from lanwatch.rules.infra import infrastructure_ips

    assert infrastructure_ips(store) == {}
    store.meta_set("net.gateways", json.dumps(["192.168.1.1"]))
    sid = store.begin_snapshot("infra", "t")
    offer = {"interface": "eth0", "server": "192.168.1.2", "router": "192.168.1.1"}
    store.replace_infra(
        "dhcp", {"eth0/192.168.1.2": {**offer, "dns": ["192.168.1.3", "9.9.9.9"]}}, sid
    )
    assert infrastructure_ips(store) == {
        "192.168.1.1": "Gateway",
        "192.168.1.2": "DHCP server",
        "192.168.1.3": "DNS server",
        "9.9.9.9": "DNS server",
    }


def test_dhcp_announcing_other_settings_than_before(store: Store, config: Config) -> None:
    engine = Engine(config)
    rule = "net.dhcp-settings-changed"
    offer: dict[str, Any] = {
        "interface": "eth0",
        "server": "192.168.1.1",
        "router": "192.168.1.1",
        "dns": ["192.168.1.1"],
        "ntp": ["192.168.1.1"],
        "domain": "lan",
    }

    def infra_round(data: dict[str, Any]) -> None:
        sid = store.begin_snapshot("infra", "t")
        store.replace_infra("dhcp", {"eth0/192.168.1.1": data}, sid)
        store.pin_dhcp_settings()  # as run_infra does
        store.finish_snapshot(sid, 1)
        engine.run(
            RuleContext(
                store=store,
                config=config,
                snapshot_id=sid,
                previous_snapshot_id=None,
                is_baseline=False,
            )
        )

    infra_round(offer)
    infra_round({**offer, "dns": ["192.168.1.1"]})
    assert _open_titles(store, rule) == []

    # The router starts handing out someone else's resolver, and a different time server.
    infra_round({**offer, "dns": ["203.0.113.66", "192.168.1.1"], "ntp": []})
    titles = sorted(_open_titles(store, rule))
    assert titles == [
        "DHCP server 192.168.1.1 now announces DNS 192.168.1.1, 203.0.113.66, was 192.168.1.1",
        "DHCP server 192.168.1.1 now announces NTP nothing, was 192.168.1.1",
    ]
    by_setting = {f.evidence["setting"]: f for f in store.findings() if f.rule_id == rule}
    assert by_setting["dns"].severity is Severity.HIGH
    assert by_setting["ntp"].severity is Severity.MEDIUM

    # Put back: both resolve.
    infra_round(offer)
    assert _open_titles(store, rule) == []
