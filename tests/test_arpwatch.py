from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from lanwatch import helper
from lanwatch.arpwatch import ArpWatch, parse_arp
from lanwatch.config import Config
from lanwatch.models import FindingStatus, HostObservation, Severity
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store
from tests.conftest import HELPER_POLICY

GATEWAY, ROUTER_MAC, IMPOSTOR_MAC = "192.168.1.1", "74:ac:b9:00:00:01", "f0:18:98:00:00:66"


def arp(op: int, sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    """An Ethernet/IPv4 ARP packet as the packet socket delivers it (no link header)."""
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
        + bytes.fromhex(sender_mac.replace(":", ""))
        + socket.inet_aton(sender_ip)
        + b"\x00" * 6
        + socket.inet_aton(target_ip)
    )


def test_parse_arp() -> None:
    assert parse_arp(arp(2, ROUTER_MAC, GATEWAY, "192.168.1.20")) == (
        2,
        ROUTER_MAC,
        GATEWAY,
        "192.168.1.20",
    )
    assert parse_arp(b"") is None and parse_arp(b"\x00" * 27) is None
    not_ethernet_ipv4 = struct.pack("!HHBBH", 6, 0x0800, 6, 4, 1) + b"\x00" * 20
    assert parse_arp(not_ethernet_ipv4) is None


def test_alternating_claims_are_a_conflict_but_a_handover_is_not() -> None:
    w = ArpWatch()
    # A DHCP lease moved from one device to another: the address changes hands once.
    w.feed(arp(2, "aa:00:00:00:00:01", "192.168.1.50", "192.168.1.1"), now=10)
    w.feed(arp(2, "aa:00:00:00:00:02", "192.168.1.50", "192.168.1.1"), now=200)
    # Spoofing: the router and an impostor keep overwriting each other.
    for t, mac in ((20, ROUTER_MAC), (21, IMPOSTOR_MAC), (25, ROUTER_MAC), (26, IMPOSTOR_MAC)):
        w.feed(arp(2, mac, GATEWAY, "192.168.1.20"), now=t)
    report = w.report(window_s=300, now=300)
    assert report["conflicts"] == {GATEWAY: sorted([ROUTER_MAC, IMPOSTOR_MAC])}
    assert report["frames"] == 6

    # Outside the window nothing is left of it.
    assert w.report(window_s=30, now=300)["conflicts"] == {}


def test_a_sender_asking_for_many_addresses_and_what_is_ignored() -> None:
    w = ArpWatch()
    for host in range(1, 61):
        w.feed(arp(1, IMPOSTOR_MAC, "192.168.1.66", f"192.168.1.{host}"), now=host)
        # Our own ARP scan does the same and must not count.
        w.feed(arp(1, "02:00:00:00:00:aa", "192.168.1.10", f"192.168.1.{host}"), True, now=host)
    # An address probe (sender 0.0.0.0) is no claim, and a chatty-but-normal host is no sweep.
    w.feed(arp(1, "aa:00:00:00:00:03", "0.0.0.0", "192.168.1.77"), now=5)
    for host in (1, 20, 31):
        w.feed(arp(1, "aa:00:00:00:00:04", "192.168.1.20", f"192.168.1.{host}"), now=6)
    report = w.report(window_s=600, now=100)
    (sweep,) = report["sweeps"]
    assert sweep["mac"] == IMPOSTOR_MAC and sweep["ip"] == "192.168.1.66"
    assert len(sweep["targets"]) == 60
    assert "0.0.0.0" not in report["conflicts"]


async def test_listener_without_privilege_reports_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    w = ArpWatch()
    opened: list[int] = []

    def refuse(*args: int) -> socket.socket:
        opened.append(1)
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(socket, "socket", refuse)
    assert w.start() is False and w.error == "Operation not permitted" and not w.listening
    monkeypatch.undo()

    # The helper answers the report request either way; unprivileged, the report is null.
    monkeypatch.setattr("lanwatch.collectors.base.privileged", lambda: False)
    reply = await helper.handle_request(
        {"op": "arp-report", "window": 300}, asyncio.Semaphore(1), HELPER_POLICY
    )
    assert reply == {"report": None}


def _ctx(store: Store, config: Config, hosts: list[HostObservation]) -> RuleContext:
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, hosts)
    store.finish_snapshot(sid, len(hosts))
    return RuleContext(
        store=store, config=config, snapshot_id=sid, previous_snapshot_id=None, is_baseline=False
    )


def test_heard_conflict_joins_the_ip_conflict_rule(store: Store, config: Config) -> None:
    import json

    router = HostObservation(ip=GATEWAY, mac=ROUTER_MAC, hostname="gw", source="t")
    laptop = HostObservation(ip="192.168.1.20", mac=IMPOSTOR_MAC, hostname="mbp", source="t")
    ctx = _ctx(store, config, [router, laptop])
    store.meta_set("net.gateways", json.dumps([GATEWAY]))
    # The scan saw one answer for the gateway; the listener heard two MACs fight over it.
    row = {"ip": GATEWAY, "macs": [ROUTER_MAC, IMPOSTOR_MAC]}
    store.replace_infra("arp-conflict", {GATEWAY: row}, ctx.snapshot_id)
    Engine(config).run(ctx)
    (f,) = [f for f in store.findings(FindingStatus.OPEN) if f.rule_id == "net.ip-conflict"]
    assert f.severity is Severity.CRITICAL and "(gateway)" in f.title
    assert f"{IMPOSTOR_MAC} (mbp)" in f.title and f"{ROUTER_MAC} (gw)" in f.title


def test_sweep_rule_counts_only_addresses_nobody_has(store: Store, config: Config) -> None:
    rule = "ids.arp-sweep"
    known = [
        HostObservation(ip=f"192.168.1.{n}", mac=f"aa:00:00:00:01:{n:02x}", source="t")
        for n in range(1, 31)
    ]
    scanner = HostObservation(ip="192.168.1.66", mac=IMPOSTOR_MAC, hostname="kali", source="t")
    ctx = _ctx(store, config, [*known, scanner])

    def titles() -> list[str]:
        return [f.title for f in store.findings(FindingStatus.OPEN) if f.rule_id == rule]

    # A router asking for the thirty clients it has: all of them exist.
    router_mac = "aa:00:00:00:01:01"
    clients = {"mac": router_mac, "ip": "192.168.1.1", "targets": [h.ip for h in known]}
    store.replace_infra("arp-sweep", {router_mac: clients}, ctx.snapshot_id)
    Engine(config).run(ctx)
    assert titles() == []

    # Something walking the whole /24.
    everything = [f"192.168.1.{n}" for n in range(1, 255)]
    sweep = {"mac": IMPOSTOR_MAC, "ip": "192.168.1.66", "targets": everything}
    store.replace_infra("arp-sweep", {IMPOSTOR_MAC: sweep}, ctx.snapshot_id)
    Engine(config).run(ctx)
    assert titles() == [
        f"kali ({IMPOSTOR_MAC}) is sweeping the network: ARP requests for 254 addresses,"
        " 223 of them unused"
    ]
    store.replace_infra("arp-sweep", {}, ctx.snapshot_id)
    Engine(config).run(ctx)
    assert titles() == []
