from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

from lanwatch.config import Config, DecoyConfig
from lanwatch.decoy import Decoys, port_label, record_hit
from lanwatch.models import FindingStatus, HostObservation
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return int(s.getsockname()[1])


class _Writer:
    """Stands in for the stream of an accepted connection."""

    def __init__(self, peer: str, local: str) -> None:
        self._info = {"peername": (peer, 40000), "sockname": (local, 23)}
        self.closed = False

    def get_extra_info(self, name: str) -> Any:
        return self._info[name]

    def close(self) -> None:
        self.closed = True


async def test_ports_in_use_are_skipped_not_fought_over() -> None:
    free, busy = _free_port(), _free_port()
    real_service = socket.socket()
    real_service.bind(("", busy))
    real_service.listen()
    hits: list[tuple[str, int]] = []
    decoys = Decoys(DecoyConfig(ports=[free, busy]), lambda ip, port: hits.append((ip, port)))
    try:
        await decoys.start()
        assert decoys.listening == [free]
        assert decoys.skipped == {busy: "in use by another service"}
        # A connection is accepted and dropped without a byte being exchanged. This one comes
        # from the machine itself, as lanwatch's own service scan does, so it is not a hit.
        reader, writer = await asyncio.open_connection("127.0.0.1", free)
        assert await asyncio.wait_for(reader.read(), timeout=2) == b""
        writer.close()
        assert hits == []
    finally:
        await decoys.stop()
        real_service.close()
    # Released again once stopped.
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # past the closed connection
        s.bind(("", free))


async def test_disabled_means_no_listeners() -> None:
    port = _free_port()
    decoys = Decoys(DecoyConfig(enabled=False, ports=[port]), lambda ip, p: None)
    await decoys.start()
    assert decoys.listening == [] and decoys.skipped == {}


async def test_who_counts_as_a_hit() -> None:
    hits: list[tuple[str, int]] = []
    cfg = DecoyConfig(ports=[23], ignore=["192.168.1.9"])
    decoys = Decoys(cfg, lambda ip, port: hits.append((ip, port)))

    async def connect(peer: str, local: str = "192.168.1.10", port: int = 23) -> _Writer:
        w = _Writer(peer, local)
        await decoys._connected(w, port)  # type: ignore[arg-type]
        return w

    assert (await connect("192.168.1.52")).closed
    assert hits == [("192.168.1.52", 23)]
    await connect("192.168.1.52")  # knocking again within ten minutes: one event is enough
    await connect("192.168.1.52", port=3389)  # another port is news
    await connect("192.168.1.10")  # this machine scanning itself
    await connect("127.0.0.1", local="127.0.0.1")
    await connect("192.168.1.9")  # the administrator's own scanner
    await connect("::ffff:192.168.1.60", local="::ffff:192.168.1.10")  # IPv4 on a dual socket
    assert hits == [("192.168.1.52", 23), ("192.168.1.52", 3389), ("192.168.1.60", 23)]


def test_only_sources_on_watched_networks_are_recorded(store: Store) -> None:
    sid = store.begin_snapshot("discovery", "t")
    tv = HostObservation(ip="192.168.1.52", mac="a4:77:33:00:00:52", hostname="tv", source="t")
    store.record_hosts(sid, [tv])
    store.finish_snapshot(sid, 1)
    store.meta_set("net.subnets", json.dumps(["192.168.1.0/24"]))

    assert record_hit(store, "192.168.1.52", 23) is True
    assert record_hit(store, "203.0.113.50", 23) is False  # the internet knocking: not news
    (event,) = store.events(kinds=["decoy.touched"])
    assert event.summary == "tv (192.168.1.52) connected to decoy port 23 (telnet)"
    assert event.data == {"ip": "192.168.1.52", "port": 23} and event.device_id is not None
    assert port_label(23) == "23 (telnet)" and port_label(4711) == "4711"


def test_decoy_connections_become_one_finding_per_source_and_day(
    store: Store, config: Config
) -> None:
    rule = "ids.decoy-touched"

    def findings() -> list[str]:
        return sorted(f.title for f in store.findings(FindingStatus.OPEN) if f.rule_id == rule)

    def run_rules() -> list[str]:
        sid = store.begin_snapshot("discovery", "t")
        store.finish_snapshot(sid, 0)
        ctx = RuleContext(
            store=store,
            config=config,
            snapshot_id=sid,
            previous_snapshot_id=None,
            is_baseline=False,
        )
        return Engine(config).run(ctx).new_ids

    assert run_rules() == [] and findings() == []
    record_hit(store, "192.168.1.52", 23)
    record_hit(store, "192.168.1.52", 3389)
    record_hit(store, "192.168.1.77", 5555)
    new = run_rules()
    assert len(new) == 2
    assert findings() == [
        "192.168.1.52 probed decoy ports 23 (telnet), 3389 (rdp)",
        "192.168.1.77 probed decoy port 5555 (adb)",
    ]
    f = next(f for f in store.findings() if "192.168.1.52" in f.title)
    assert f.evidence["connections"] == 2 and f.evidence["ports"] == [23, 3389]

    # Acknowledged findings stay closed while the same day's events are still in the window...
    for fid in new:
        store.ack(fid)
    assert run_rules() == [] and findings() == []
    # ...but the same device probing on another day is a new finding.
    record_hit(store, "192.168.1.52", 23)
    newest = store._db.execute("SELECT MAX(id) FROM events").fetchone()[0]
    store._db.execute(
        "UPDATE events SET ts = replace(ts, substr(ts, 1, 10), date(ts, '+1 day')) WHERE id = ?",
        (newest,),
    )
    assert len(run_rules()) == 1
    assert findings() == ["192.168.1.52 probed decoy port 23 (telnet)"]
