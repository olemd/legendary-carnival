from __future__ import annotations

from lanwatch.config import Config
from lanwatch.models import Finding, FindingStatus, HostObservation, Kind, Severity
from lanwatch.store import MIGRATIONS, Store


def obs(ip: str, mac: str | None = None, **kw: str) -> HostObservation:
    return HostObservation(ip=ip, mac=mac, source="test", **kw)


def test_migration_is_idempotent(store: Store) -> None:
    assert store.schema_version == len(MIGRATIONS)
    store.migrate()
    assert store.schema_version == len(MIGRATIONS)


def test_record_hosts_new_then_seen(store: Store) -> None:
    s1 = store.begin_snapshot("discovery", "test")
    r1 = store.record_hosts(s1, [obs("10.0.0.1", "aa:bb:cc:00:00:01"), obs("10.0.0.2")])
    store.finish_snapshot(s1, 2)
    assert len(r1.new_device_ids) == 2

    s2 = store.begin_snapshot("discovery", "test")
    r2 = store.record_hosts(s2, [obs("10.0.0.9", "AA-BB-CC-00-00-01", hostname="pi")])
    store.finish_snapshot(s2, 1)
    assert r2.new_device_ids == []
    assert r2.ip_changes == [(r1.new_device_ids[0], "10.0.0.1", "10.0.0.9")]

    devs = store.devices()
    assert len(devs) == 2
    pi = store.device_by_key("aa:bb:cc:00:00:01")
    assert pi is not None and pi.ip == "10.0.0.9" and pi.hostname == "pi" and pi.online
    other = store.device_by_key("ip:10.0.0.2")
    assert other is not None and not other.online
    assert len(store.devices(online_only=True)) == 1


def test_duplicate_keys_in_one_round_are_collapsed(store: Store) -> None:
    s = store.begin_snapshot("discovery", "test")
    r = store.record_hosts(
        s, [obs("10.0.0.1", "aa:bb:cc:00:00:01"), obs("10.0.0.1", "aa:bb:cc:00:00:01")]
    )
    assert len(r.new_device_ids) == 1


def _finding(fid: str, rule: str = "r.a") -> Finding:
    return Finding(id=fid, rule_id=rule, severity=Severity.LOW, kind=Kind.PROBLEM, title=fid)


def test_findings_lifecycle(store: Store) -> None:
    new, resolved = store.upsert_findings([_finding("f1"), _finding("f2")], {"r.a"}, {"r.a"})
    assert sorted(new) == ["f1", "f2"] and resolved == []

    # f2 disappears from an auto-resolving rule -> resolved. f1 stays open.
    new, resolved = store.upsert_findings([_finding("f1")], {"r.a"}, {"r.a"})
    assert new == [] and resolved == ["f2"]
    assert [f.id for f in store.findings(FindingStatus.OPEN)] == ["f1"]

    # Reappearing resolved finding reopens.
    store.upsert_findings([_finding("f1"), _finding("f2")], {"r.a"}, {"r.a"})
    assert {f.id for f in store.findings(FindingStatus.OPEN)} == {"f1", "f2"}

    # Acked stays acked when re-emitted, and is not auto-resolved when rule didn't run.
    assert store.ack("f1")
    assert not store.ack("f1")
    store.upsert_findings([_finding("f1"), _finding("f2")], {"r.a"}, {"r.a"})
    f1 = store.finding("f1")
    assert f1 is not None and f1.status is FindingStatus.ACKED
    store.upsert_findings([], {"r.other"}, {"r.other"})
    assert {f.id for f in store.findings(None)} == {"f1", "f2"}
    assert store.finding("f2").status is FindingStatus.OPEN  # type: ignore[union-attr]


def test_non_auto_resolve_rules_keep_findings(store: Store) -> None:
    store.upsert_findings([_finding("e1", "inventory.new-device")], {"inventory.new-device"}, set())
    store.upsert_findings([], {"inventory.new-device"}, set())
    assert store.finding("e1").status is FindingStatus.OPEN  # type: ignore[union-attr]


def test_findings_sorted_by_severity(store: Store) -> None:
    hi = Finding(id="h", rule_id="r", severity=Severity.HIGH, kind=Kind.SECURITY, title="h")
    store.upsert_findings([_finding("lo"), hi], {"r", "r.a"}, set())
    assert [f.id for f in store.findings()] == ["h", "lo"]


def test_llm_cache(store: Store) -> None:
    assert store.llm_cache_get("k") is None
    store.llm_cache_put("k", "m", "v")
    assert store.llm_cache_get("k") == "v"


def test_prune_drops_old_history_but_keeps_current_state(store: Store) -> None:
    def backdate(table: str, column: str, row_id: int, ts: str) -> None:
        store._db.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (ts, row_id))

    old, cutoff = "2026-01-01T00:00:00+00:00", "2026-06-01T00:00:00+00:00"
    host = obs("10.0.0.1", "aa:bb:cc:00:00:01")

    # Two old discovery rounds and one recent one; an old inventory round a service still
    # points to; an old infra round that is the newest of its kind.
    rounds = []
    for _ in range(3):
        sid = store.begin_snapshot("discovery", "test")
        rec = store.record_hosts(sid, [host])
        store.finish_snapshot(sid, 1)
        rounds.append(sid)
    device_id = rec.seen_device_ids[0]
    inv = store.begin_snapshot("inventory", "test")
    store._db.execute(
        "INSERT INTO services(device_id, port, proto, state, first_seen, last_seen,"
        " last_snapshot_id) VALUES (?, 22, 'tcp', 'open', ?, ?, ?)",
        (device_id, old, old, inv),
    )
    store.finish_snapshot(inv, 1)
    inv2 = store.begin_snapshot("inventory", "test")
    store.finish_snapshot(inv2, 0)
    infra = store.begin_snapshot("infra", "test")
    store.finish_snapshot(infra, 0)
    for sid in (rounds[0], rounds[1], inv, infra):
        backdate("snapshots", "started_at", sid, old)

    store.add_event("device.new", "an old event", device_id)
    store.add_event("device.named", "a recent event", device_id)
    store._db.execute("UPDATE events SET ts = ? WHERE summary = 'an old event'", (old,))
    store.record_notification("ntfy", "findings", "old", True, None)
    store.record_notification("ntfy", "findings", "recent", True, None)
    backdate("notifications", "ts", 1, old)

    deleted = store.prune(rounds_before=cutoff, events_before=cutoff, notifications_before=cutoff)
    assert deleted["sightings"] == 2 and deleted["snapshots"] == 2  # the two old rounds
    assert deleted["notifications"] == 1 and deleted["events"] == 1

    assert store.snapshot(rounds[2]) is not None  # recent
    assert store.snapshot(inv) is not None  # old, but a service row refers to it
    assert store.snapshot(infra) is not None  # old, but the newest infra round
    device = store.device(device_id)
    assert device is not None and device.online  # "online" comes from the newest round
    assert [n.title for n in store.notifications()] == ["recent"]
    assert "an old event" not in [e.summary for e in store.events(limit=50)]
    assert "a recent event" in [e.summary for e in store.events(limit=50)]

    # Nothing left to do, and None means "keep everything".
    assert not any(store.prune(cutoff, cutoff, cutoff).values())
    assert not any(store.prune().values())


async def test_maintenance_honours_retention_settings(store: Store, config: Config) -> None:
    from lanwatch.pipeline import run_maintenance

    store.add_event("device.new", "ancient", None)
    store._db.execute("UPDATE events SET ts = '2020-01-01T00:00:00+00:00'")
    config.store.keep_events_days = 0  # keep forever
    assert (await run_maintenance(config, store))["events"] == 0
    config.store.keep_events_days = 365
    assert (await run_maintenance(config, store))["events"] == 1
