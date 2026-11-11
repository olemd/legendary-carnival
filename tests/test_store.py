from __future__ import annotations

from pathlib import Path

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


def test_private_mac_detection() -> None:
    from lanwatch.models import is_private_mac

    assert is_private_mac("da:a1:19:00:00:01") and is_private_mac("02:00:00:00:00:01")
    assert not is_private_mac("f0:18:98:11:22:01") and not is_private_mac("3c:22:fb:11:22:02")
    assert not is_private_mac(None) and not is_private_mac("zz:00:00:00:00:00")


def _one_round(store: Store, *hosts: HostObservation) -> list[int]:
    sid = store.begin_snapshot("discovery", "test")
    rec = store.record_hosts(sid, list(hosts))
    store.finish_snapshot(sid, len(rec.seen_device_ids))
    return rec.seen_device_ids


def test_a_persons_classification_is_not_overwritten(store: Store) -> None:
    (did,) = _one_round(store, obs("10.0.0.5", "f0:18:98:00:00:05"))
    store.set_device_classification(did, "laptop", "Probably a MacBook", 0.6)

    # Saving the form with nothing changed about the kind does not pin it.
    store.edit_device(did, name="Work Mac", kind="laptop", description="Probably a MacBook")
    d = store.device(did)
    assert d is not None and d.name == "Work Mac" and not d.kind_manual

    store.edit_device(did, name="Work Mac", kind="workstation", description="Mac Studio")
    assert store.set_device_classification(did, "laptop", "Probably a MacBook", 0.6) is False
    d = store.device(did)
    assert d is not None and d.kind_manual and d.kind_confidence is None
    assert (d.kind, d.description) == ("workstation", "Mac Studio")

    # Clearing both hands the device back to the LLM.
    store.edit_device(did, name="Work Mac", kind=None, description=None)
    assert store.set_device_classification(did, "laptop", "Probably a MacBook", 0.6) is True
    d = store.device(did)
    assert d is not None and not d.kind_manual and d.kind == "laptop"
    assert store.edit_device(999, name=None, kind=None, description=None) is False


def test_forgetting_a_device_removes_it_and_it_can_come_back(store: Store) -> None:
    host = obs("10.0.0.5", "f0:18:98:00:00:05", hostname="old-printer")
    (did,) = _one_round(store, host)
    assert store.delete_device(did) is True and store.delete_device(did) is False
    assert store.devices() == []
    forgotten = [e for e in store.events(limit=20) if e.kind == "device.forgotten"]
    assert forgotten and "old-printer" in forgotten[0].summary
    assert all(e.device_id is None for e in store.events(limit=20))  # history kept, unlinked
    # Still on the network: the next round adds it back as a new device.
    sid = store.begin_snapshot("discovery", "test")
    rec = store.record_hosts(sid, [host])
    store.finish_snapshot(sid, 1)
    assert len(rec.new_device_ids) == 1 and len(store.devices()) == 1


def test_merging_makes_the_other_address_an_alias(store: Store) -> None:
    phone = obs("10.0.0.7", "da:a1:19:00:00:01", hostname="pixel")
    keep, dup = _one_round(store, phone, obs("10.0.0.8", "5e:11:22:00:00:02", hostname="pixel"))
    store.set_device_name(keep, "Ole's phone")

    assert store.merge_devices(keep, dup) is True
    assert store.merge_devices(keep, dup) is False and store.merge_devices(keep, keep) is False
    assert [d.id for d in store.devices()] == [keep]
    assert store.device_aliases(keep) == ["5e:11:22:00:00:02"]
    assert any(e.kind == "device.merged" for e in store.events(device_id=keep, limit=20))

    # The phone shows up under the other address again: same device, not a new one.
    sid = store.begin_snapshot("discovery", "test")
    rec = store.record_hosts(sid, [obs("10.0.0.9", "5e:11:22:00:00:02", hostname="pixel")])
    store.finish_snapshot(sid, 1)
    assert rec.new_device_ids == [] and rec.seen_device_ids == [keep]
    d = store.device(keep)
    assert d is not None and d.online and d.ip == "10.0.0.9" and d.name == "Ole's phone"

    # Both addresses answering in one round still count as one device.
    assert _one_round(store, phone, obs("10.0.0.9", "5e:11:22:00:00:02")) == [keep]


def test_accepting_a_finding_sticks_and_can_be_undone(store: Store) -> None:
    store.upsert_findings([_finding("f1"), _finding("f2")], {"r.a"}, {"r.a"})

    # Acknowledged only: when it resolves and comes back, it is open again.
    assert store.ack("f1")
    # Accepted with a reason: it comes back acknowledged, reason intact.
    assert store.ack("f2", accept=True, note="Lab switch, telnet is the only way in")
    store.upsert_findings([], {"r.a"}, {"r.a"})  # both conditions go away
    store.upsert_findings([_finding("f1"), _finding("f2")], {"r.a"}, {"r.a"})  # and return
    f1, f2 = store.finding("f1"), store.finding("f2")
    assert f1 is not None and f1.status is FindingStatus.OPEN and not f1.accepted
    assert f2 is not None and f2.status is FindingStatus.ACKED and f2.accepted
    assert f2.note == "Lab switch, telnet is the only way in"
    kinds = [e.kind for e in store.events(limit=50)]
    assert "finding.accepted" in kinds
    assert kinds.count("finding.reopened") == 1  # f1 only; f2 came back quietly

    # An acknowledged finding can be upgraded to accepted, and either can be reopened.
    assert store.ack("f1") and store.ack("f1", accept=True, note="known")
    assert store.reopen("f2") and not store.reopen("f2")
    f2 = store.finding("f2")
    assert f2 is not None and f2.status is FindingStatus.OPEN
    assert not f2.accepted and f2.note is None
    assert not store.reopen("no-such-finding")


def test_concurrent_writers_wait_instead_of_failing(tmp_path: Path) -> None:
    """The service and a CLI command writing at the same moment: both must succeed."""
    import threading
    import time

    path = tmp_path / "shared.db"
    a = Store(path)
    a.meta_set("k", "initial")
    errors: list[BaseException] = []
    started = threading.Event()

    def other_process() -> None:
        try:
            with Store(path) as b:
                started.set()
                b.meta_set("k", "from the other writer")
        except BaseException as e:  # reported to the main thread below
            errors.append(e)

    t = threading.Thread(target=other_process)
    with a._tx():
        assert a.meta_get("k") == "initial"  # read first, then write: what record_hosts does
        t.start()
        started.wait(timeout=5)
        time.sleep(0.1)  # the other writer is now either done (the bug) or waiting (correct)
        a.meta_set("k", "from the transaction")
    t.join(timeout=10)
    assert errors == []
    assert a.meta_get("k") == "from the other writer"  # it waited, then wrote last
    a.close()


def test_v11_moves_the_router_state_out_of_meta(tmp_path: Path) -> None:
    """A 0.8.0 database keeps the router's SNMP state in meta keys; v11 moves it to the
    router's snmp-target row, so nothing is lost and nothing reads the old keys."""
    import json
    import sqlite3

    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    for version, sql in enumerate(MIGRATIONS[:10], start=1):
        db.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;")
    system = {"name": "gw", "vendor": "Juniper", "uptime_s": 5}
    db.executemany(
        "INSERT INTO meta(key, value) VALUES (?, ?)",
        [
            ("snmp.host", "192.0.2.1"),
            ("snmp.system", json.dumps(system)),
            ("snmp.last_ok", "2026-11-10T09:00:00+00:00"),
            ("snmp.last_error", "Timeout"),
        ],
    )
    db.commit()
    db.close()

    with Store(path) as store:
        (row,) = store.infra("snmp-target")
        assert row.key == "192.0.2.1"
        assert row.data == {
            "host": "192.0.2.1",
            "role": "router",
            "name": "",
            "system": system,
            "last_ok": "2026-11-10T09:00:00+00:00",
            "last_error": "Timeout",
            "fails": 1,
        }
        assert store.meta_get("snmp.system") is None and store.meta_get("snmp.host") is None


def test_v11_without_router_state_adds_nothing(tmp_path: Path) -> None:
    with Store(tmp_path / "new.db") as store:
        assert store.infra("snmp-target") == []


def test_snmp_series_and_pruning(store: Store) -> None:
    t1, t2 = "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"
    store.add_snmp_series("192.0.2.9", {"ups.load_w": 121, "ups.input_v": 231.5}, ts=t1)
    store.add_snmp_series("192.0.2.9", {"ups.load_w": 130}, ts=t2)
    store.add_snmp_series("192.0.2.9", {})
    assert store.snmp_series("192.0.2.9", "ups.load_w", t1) == [(t1, 121.0), (t2, 130.0)]
    assert store.snmp_series("192.0.2.9", "ups.input_v", "2026-01-01T12:00:00+00:00") == []
    deleted = store.prune(rounds_before="2026-01-01T12:00:00+00:00")
    assert deleted["snmp_series"] == 2
    assert store.snmp_series("192.0.2.9", "ups.load_w", "") == [(t2, 130.0)]
