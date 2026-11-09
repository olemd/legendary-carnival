from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from lanwatch.collectors.latency import measure, parse_ping, resolve_targets
from lanwatch.config import Config
from lanwatch.models import Severity, iso, now_utc
from lanwatch.rules.base import RuleContext
from lanwatch.rules.infra import PacketLossRule
from lanwatch.store import Store
from lanwatch.web.app import create_app

OK = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.21 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.98 ms

--- 192.168.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.980/1.095/1.210/0.115 ms
"""
LOST = """--- 192.0.2.1 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3050ms
"""
PARTIAL = """--- 192.168.1.1 ping statistics ---
4 packets transmitted, 2 received, 50% packet loss, time 3012ms
rtt min/avg/max/mdev = 2.000/3.500/5.000/1.500 ms
"""


def test_parse_ping() -> None:
    r = parse_ping("192.168.1.1", OK)
    assert r is not None and r.sent == 2 and r.received == 2 and r.avg_ms == 1.095
    assert r.max_ms == 1.21 and r.loss == 0.0
    lost = parse_ping("192.0.2.1", LOST)
    assert lost is not None and lost.received == 0 and lost.avg_ms is None and lost.loss == 1.0
    assert parse_ping("x", "ping: unknown host x") is None


def test_resolve_targets() -> None:
    gws = ["192.168.1.1", "192.168.1.2"]
    assert resolve_targets(["gateway"], gws) == gws
    assert resolve_targets(["gateway", "1.1.1.1", "192.168.1.1"], gws) == [*gws, "1.1.1.1"]
    assert resolve_targets(["gateway"], []) == []


class FakeExecutor:
    name = "fake"

    def __init__(self, outputs: dict[str, tuple[int, str]]) -> None:
        self.outputs = outputs
        self.calls: list[list[str]] = []

    async def run(self, args: list[str], timeout: float) -> tuple[int, str, str]:
        self.calls.append(args)
        rc, out = self.outputs[args[-1]]
        return rc, out, ""

    async def which(self, binary: str) -> tuple[bool, bool]:
        return True, False


async def test_measure_pings_each_target() -> None:
    ex = FakeExecutor({"192.168.1.1": (0, OK), "192.0.2.1": (1, LOST), "bad": (2, "ping: bad")})
    results = await measure(ex, ["192.168.1.1", "192.0.2.1", "bad"], count=4)
    assert [r.target for r in results] == ["192.168.1.1", "192.0.2.1"]
    assert ex.calls[0] == ["ping", "-c", "4", "-W", "1", "192.168.1.1"]


def _record(store: Store, target: str, text: str, ago_s: int) -> None:
    r = parse_ping(target, text)
    assert r is not None
    store.record_latency(target, r.sent, r.received, r.avg_ms, r.max_ms)
    # Spread the rows out in time so ordering is unambiguous.
    store._db.execute(
        "UPDATE latency SET ts = ? WHERE rowid = (SELECT MAX(rowid) FROM latency)",
        (iso(now_utc() - timedelta(seconds=ago_s)),),
    )


def test_store_series_and_prune(store: Store) -> None:
    _record(store, "192.168.1.1", OK, 3600 * 30)
    _record(store, "192.168.1.1", PARTIAL, 60)
    assert store.latency_targets() == ["192.168.1.1"]
    assert [
        r.loss for r in store.latency_series("192.168.1.1", iso(now_utc() - timedelta(days=1)))
    ] == [0.5]
    assert store.latency_recent("192.168.1.1", 1)[0].avg_ms == 3.5
    deleted = store.prune(rounds_before=iso(now_utc() - timedelta(days=1)))
    assert deleted["latency"] == 1


def _ctx(store: Store, config: Config) -> RuleContext:
    sid = store.begin_snapshot("discovery", "t")
    store.finish_snapshot(sid, 0)
    return RuleContext(
        store=store, config=config, snapshot_id=sid, previous_snapshot_id=None, is_baseline=False
    )


def test_packet_loss_rule(store: Store, config: Config) -> None:
    rule = PacketLossRule()
    # Two bad rounds are not enough; a good one in between resets.
    _record(store, "192.168.1.1", PARTIAL, 900)
    _record(store, "192.168.1.1", OK, 600)
    _record(store, "192.168.1.1", PARTIAL, 300)
    assert rule.evaluate(_ctx(store, config)) == []
    _record(store, "192.168.1.1", PARTIAL, 1)
    _record(store, "192.168.1.1", PARTIAL, 0)
    found = rule.evaluate(_ctx(store, config))
    assert len(found) == 1 and found[0].severity is Severity.MEDIUM
    assert found[0].title.startswith("Packet loss to 192.168.1.1: 50%")
    # Nothing at all back for three rounds: a harder problem, higher severity.
    for ago in (3, 2, 1):
        _record(store, "1.1.1.1", LOST.replace("192.0.2.1", "1.1.1.1"), ago)
    titles = {f.title: f.severity for f in rule.evaluate(_ctx(store, config))}
    assert titles["1.1.1.1 unreachable for the last 3 rounds"] is Severity.HIGH


def test_dashboard_shows_latency_tile(config: Config, tmp_path: Path) -> None:
    with Store(config.store_path) as store:
        _record(store, "192.168.1.1", OK, 120)
        _record(store, "192.168.1.1", PARTIAL, 0)
    client = TestClient(create_app(config))
    html = client.get("/").text
    assert "Latency to 192.168.1.1" in html and "3.5 <span" in html
    assert "loss in 1 of 2 rounds" in html
