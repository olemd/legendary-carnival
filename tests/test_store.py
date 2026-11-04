from __future__ import annotations

from lanwatch.models import Finding, FindingStatus, HostObservation, Kind, Severity
from lanwatch.store import Store


def obs(ip: str, mac: str | None = None, **kw: str) -> HostObservation:
    return HostObservation(ip=ip, mac=mac, source="test", **kw)


def test_migration_is_idempotent(store: Store) -> None:
    assert store.schema_version == 1
    store.migrate()
    assert store.schema_version == 1


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
