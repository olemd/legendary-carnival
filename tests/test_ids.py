from __future__ import annotations

import struct
from typing import Any

import pytest

from lanwatch import dnswire, pipeline
from lanwatch.collectors.canary import PoisonAnswer, is_poisoned_answer, random_name
from lanwatch.config import Config
from lanwatch.models import FindingStatus, HostObservation, Severity
from lanwatch.netinfo import parse_ipv6_routers
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store


def _answer(question: bytes, address: bytes, rcode: int = 0, ident: int | None = None) -> bytes:
    """A response to `question` with one A record pointing back at the question name."""
    qid = int.from_bytes(question[:2], "big") if ident is None else ident
    header = struct.pack("!HHHHHH", qid, 0x8000 | rcode, 1, 0 if rcode else 1, 0, 0)
    record = b"" if rcode else b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + address
    return header + question[12:] + record


def test_dns_query_and_response_roundtrip() -> None:
    q = dnswire.build_query("example.com", ident=0x1234)
    assert q[:2] == b"\x12\x34" and b"\x07example\x03com\x00" in q
    r = dnswire.parse_response(_answer(q, bytes([93, 184, 215, 14])))
    assert r.is_response and r.ident == 0x1234 and r.rcode == dnswire.RCODE_OK
    assert r.addresses() == ["93.184.215.14"] and r.answers[0].name == "example.com"

    blocked = dnswire.parse_response(_answer(q, b"", rcode=dnswire.RCODE_NXDOMAIN))
    assert blocked.rcode == dnswire.RCODE_NXDOMAIN and blocked.addresses() == []

    # mDNS: the unicast-reply bit lives in the class field.
    assert dnswire.build_query("x.local", unicast_reply=True)[-2:] == b"\x80\x01"
    for junk in (b"", b"\x00" * 11, q[:20], b"\xff" * 40):
        with pytest.raises(ValueError):
            dnswire.parse_response(junk)


def test_txt_records_and_compressed_names() -> None:
    service = dnswire.encode_name("_esphomelib._tcp.local")  # at offset 12 in the message
    instance = b"\x07kitchen\xc0\x0c"  # "kitchen" + a pointer back to the service name
    txt = b"\x0eversion=2026.1\x08mac=aabb"
    ptr_record = service + struct.pack("!HHIH", dnswire.TYPE_PTR, 1, 120, len(instance))
    instance_at = 12 + len(ptr_record)
    message = (
        struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 1)
        + ptr_record
        + instance
        + struct.pack("!H", 0xC000 | instance_at)  # the TXT record's owner, by pointer
        + struct.pack("!HHIH", dnswire.TYPE_TXT, 1, 120, len(txt))
        + txt
    )
    r = dnswire.parse_response(message)
    assert r.answers[0].text == "kitchen._esphomelib._tcp.local"
    assert r.extra[0].name == "kitchen._esphomelib._tcp.local"
    assert r.extra[0].text.split("\n") == ["version=2026.1", "mac=aabb"]


def test_netbios_name_encoding() -> None:
    # RFC 1001's worked example is "FRED": each byte becomes two letters, padded with spaces.
    packet = dnswire.netbios_query("fred", ident=7)
    assert packet[12:13] == b"\x20"
    assert packet[13:45] == b"EGFCEFEECACACACACACACACACACACAAA"
    assert packet[2:4] == b"\x01\x10"  # broadcast, recursion desired


def test_only_a_positive_answer_to_our_question_counts() -> None:
    name = random_name()
    assert len(name) == 12 and name.isalpha() and name != random_name()
    q = dnswire.build_query(name, recursion=False)
    ident = int.from_bytes(q[:2], "big")
    poison = _answer(q, bytes([192, 168, 1, 66]))

    assert is_poisoned_answer("llmnr", poison, ident, name)
    assert not is_poisoned_answer("llmnr", poison, ident ^ 1, name)  # someone else's answer
    assert not is_poisoned_answer("llmnr", _answer(q, b"", rcode=3), ident, name)  # honest "no"
    assert not is_poisoned_answer("llmnr", q, ident, name)  # our own question echoed
    assert not is_poisoned_answer("llmnr", b"\x00\x01", ident, name)

    mq = dnswire.build_query(f"{name}.local", unicast_reply=True)
    assert is_poisoned_answer("mdns", _answer(mq, bytes([192, 168, 1, 66]), ident=0), 0, name)
    other = dnswire.build_query("printer.local")
    assert not is_poisoned_answer("mdns", _answer(other, bytes([192, 168, 1, 5]), ident=0), 0, name)


def _infra_ctx(store: Store, config: Config) -> RuleContext:
    sid = store.begin_snapshot("infra", "t")
    store.finish_snapshot(sid, 0)
    return RuleContext(
        store=store, config=config, snapshot_id=sid, previous_snapshot_id=None, is_baseline=False
    )


def _titles(store: Store, rule_id: str) -> list[str]:
    return [f.title for f in store.findings(FindingStatus.OPEN) if f.rule_id == rule_id]


def test_a_machine_answering_for_a_nonexistent_name_is_critical(
    store: Store, config: Config
) -> None:
    sid = store.begin_snapshot("discovery", "t")
    kali = HostObservation(ip="192.168.1.66", mac="f0:18:98:00:00:66", hostname="kali", source="t")
    store.record_hosts(sid, [kali])
    store.finish_snapshot(sid, 1)
    engine = Engine(config)

    row = {"responder": "192.168.1.66", "protocols": ["netbios", "llmnr"], "name": "qwkzjvtrplmn"}
    store.replace_infra("name-poisoning", {"192.168.1.66": row}, sid)
    engine.run(_infra_ctx(store, config))
    assert _titles(store, "ids.name-poisoning") == [
        "kali (192.168.1.66) answers lookups for names that do not exist (llmnr, netbios)"
    ]
    f = next(f for f in store.findings() if f.rule_id == "ids.name-poisoning")
    assert f.severity is Severity.CRITICAL and f.evidence["asked_for"] == "qwkzjvtrplmn"

    store.replace_infra("name-poisoning", {}, sid)  # the tool was stopped
    engine.run(_infra_ctx(store, config))
    assert _titles(store, "ids.name-poisoning") == []


def test_ipv6_routers_from_routes_and_neighbours() -> None:
    routes = [
        {"dst": "default", "gateway": "fe80::1", "dev": "eth0", "protocol": "ra"},
        {"dst": "2001:db8::/64", "dev": "eth0"},
        {"dst": "default", "gateway": "fe80::dead", "dev": "tailscale0"},
        {"dst": "default", "dev": "wg0"},
    ]
    neigh = [{"dst": "fe80::1", "dev": "eth0", "lladdr": "74:AC:B9:00:00:01", "router": None}]
    assert parse_ipv6_routers(routes, neigh) == [
        {"gateway": "fe80::1", "dev": "eth0", "mac": "74:ac:b9:00:00:01"},
        {"gateway": "fe80::dead", "dev": "tailscale0", "mac": ""},
    ]
    assert parse_ipv6_routers("nonsense", None) == []


def test_a_new_ipv6_router_is_a_finding_even_where_there_was_none(
    store: Store, config: Config
) -> None:
    engine = Engine(config)
    rule = "net.ipv6-router-new"
    sid = store.begin_snapshot("infra", "t")

    # Before the first infra round there is nothing to compare with.
    engine.run(_infra_ctx(store, config))
    assert _titles(store, rule) == []

    # First round on an IPv4-only network: no routers, and that fact is remembered.
    store.replace_infra("ipv6-router", {}, sid)
    store.pin_ipv6_routers()
    engine.run(_infra_ctx(store, config))
    assert _titles(store, rule) == [] and store.meta_get("net.ipv6-routers") == "[]"

    # Someone starts sending router advertisements.
    rogue = {"gateway": "fe80::bad", "dev": "eth0", "mac": "f0:18:98:00:00:66"}
    store.replace_infra("ipv6-router", {"fe80::bad%eth0": rogue}, sid)
    store.pin_ipv6_routers()  # must not adopt the newcomer
    engine.run(_infra_ctx(store, config))
    assert _titles(store, rule) == ["New IPv6 router on eth0: f0:18:98:00:00:66"]

    store.replace_infra("ipv6-router", {}, sid)
    engine.run(_infra_ctx(store, config))
    assert _titles(store, rule) == []


def test_a_router_present_from_the_start_is_not_news(store: Store, config: Config) -> None:
    sid = store.begin_snapshot("infra", "t")
    real = {"gateway": "fe80::1", "dev": "eth0", "mac": "74:ac:b9:00:00:01"}
    store.replace_infra("ipv6-router", {"fe80::1%eth0": real}, sid)
    store.pin_ipv6_routers()
    Engine(config).run(_infra_ctx(store, config))
    assert _titles(store, "net.ipv6-router-new") == []


async def test_infra_round_records_poisoners(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_infra with the probe switched on stores whoever answered."""
    asked: list[Any] = []

    async def fake_probe(pairs: list[tuple[str, str]]) -> list[PoisonAnswer]:
        asked.append(pairs)
        return [PoisonAnswer("llmnr", "192.168.1.66", "abcdefghijkl")]

    class NoTools:
        name = "fake"

        async def run(self, args: list[str], timeout: float) -> tuple[int, str, str]:
            return -2, "", "not found"

        async def which(self, binary: str) -> tuple[bool, bool]:
            return False, False

    async def no_interfaces(ex: object = None) -> list[Any]:
        return []  # not this machine's real interfaces

    monkeypatch.setattr(pipeline, "probe_name_poisoning", fake_probe)
    monkeypatch.setattr(pipeline, "list_interfaces", no_interfaces)
    config.scan.name_poisoning_check = True
    config.scan.upnp = False
    await pipeline.run_infra(config, store, executor=NoTools())
    assert store.meta_get("dhcp.probed") == "no"  # no raw sockets: the page says why
    assert len(asked) == 1
    assert [r.key for r in store.infra("name-poisoning")] == ["192.168.1.66"]
    assert _titles(store, "ids.name-poisoning")
