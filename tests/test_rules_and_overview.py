from __future__ import annotations

from pathlib import Path

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
