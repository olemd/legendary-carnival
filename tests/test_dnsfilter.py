from __future__ import annotations

import ipaddress
import struct
from pathlib import Path
from typing import Any

import pytest

from lanwatch import dnswire
from lanwatch.collectors import dnsfilter
from lanwatch.collectors.dnsfilter import check_resolver, is_blocked, system_resolvers
from lanwatch.config import Config
from lanwatch.models import FindingStatus, Kind
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store


def response(*addresses: str, rcode: int = 0) -> dnswire.Response:
    """A parsed answer with the given A/AAAA addresses."""
    records = []
    for a in addresses:
        ip = ipaddress.ip_address(a)
        rtype = dnswire.TYPE_A if ip.version == 4 else dnswire.TYPE_AAAA
        records.append(dnswire.Record("x", rtype, ip.packed, str(ip)))
    return dnswire.Response(ident=1, is_response=True, rcode=rcode, answers=records)


@pytest.mark.parametrize(
    ("answer", "blocked"),
    [
        (response("142.251.38.102"), False),  # the real thing
        (response("0.0.0.0"), True),  # Pi-hole, AdGuard, Cloudflare for Families
        (response("::"), True),
        (response("146.112.61.108"), True),  # OpenDNS phishing block page
        (response("146.112.59.12"), False),  # OpenDNS's real address for its test names
        (response("192.168.1.2"), True),  # Pi-hole in "answer with my own address" mode
        (response("127.0.0.1"), True),
        (response(rcode=dnswire.RCODE_NXDOMAIN), True),  # Quad9, Mullvad
        (response(rcode=5), True),  # REFUSED, an AdGuard Home option
        (response(), True),  # NODATA mode
        (response(rcode=2), False),  # SERVFAIL says nothing about filtering
        (response("0.0.0.0", "142.251.38.102"), False),  # one real address is not a block
    ],
)
def test_what_counts_as_blocked(answer: dnswire.Response, blocked: bool) -> None:
    assert is_blocked(answer) is blocked


def _resolver(blocks: set[str], dead: bool = False) -> object:
    """A stand-in for dnsfilter.query: resolves everything except the names it blocks."""

    async def query(resolver: str, name: str, timeout: float = 3.0) -> dnswire.Response | None:
        if dead:
            return None
        return response("0.0.0.0") if name in blocks else response("93.184.215.14")

    return query


async def test_check_resolver_verdicts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dnsfilter, "query", _resolver(set()))
    plain = await check_resolver("192.168.1.1")
    assert plain["working"] and plain["ads"] is False and plain["threats"] is False
    assert plain["blocked"] == []

    monkeypatch.setattr(dnsfilter, "query", _resolver({"doubleclick.net"}))
    pihole = await check_resolver("192.168.1.2")
    assert pihole["ads"] is True and pihole["threats"] is False
    assert pihole["blocked"] == ["doubleclick.net"]

    monkeypatch.setattr(dnsfilter, "query", _resolver({"isitblocked.org"}))
    quad9 = await check_resolver("9.9.9.9")
    assert quad9["threats"] is True and quad9["provider"] == "Quad9" and quad9["ads"] is False

    # No answer at all, or a resolver that "blocks" even the control name: no verdict.
    monkeypatch.setattr(dnsfilter, "query", _resolver(set(), dead=True))
    assert (await check_resolver("192.0.2.1"))["working"] is False
    monkeypatch.setattr(dnsfilter, "query", _resolver({"example.com", "doubleclick.net"}))
    captive = await check_resolver("10.0.0.1")
    assert captive["working"] is False and captive["ads"] is None


def test_system_resolvers(tmp_path: Path) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text(
        "# comment\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nsearch lan\nnameserver junk\n"
    )
    assert system_resolvers(conf) == ["192.168.1.1", "fe80::1"]
    assert system_resolvers(tmp_path / "missing") == []


def test_unfiltered_resolver_is_an_improvement_suggestion(store: Store, config: Config) -> None:
    sid = store.begin_snapshot("infra", "t")
    store.finish_snapshot(sid, 0)
    ctx = RuleContext(
        store=store, config=config, snapshot_id=sid, previous_snapshot_id=None, is_baseline=False
    )
    rows: dict[str, dict[str, Any]] = {
        "192.168.1.1": {"working": True, "ads": False, "threats": False, "announced_by_dhcp": True},
        "192.168.1.2": {"working": True, "ads": True, "threats": False},  # a Pi-hole
        "9.9.9.9": {"working": True, "ads": False, "threats": True},
        "192.0.2.1": {"working": False, "ads": None, "threats": None},  # did not answer
        "192.0.2.2": {"working": True, "ads": None, "threats": None},  # tests got no answer
    }
    store.replace_infra("dns-filter", rows, sid)
    Engine(config).run(ctx)
    found = [
        f for f in store.findings(FindingStatus.OPEN) if f.rule_id == "improvement.dns-not-filtered"
    ]
    assert [f.title for f in found] == [
        "DNS resolver 192.168.1.1 does not filter ads or malicious domains"
    ]
    assert found[0].kind is Kind.IMPROVEMENT and found[0].evidence["announced_by_dhcp"] is True


def test_the_dns_wire_helpers_agree_with_the_check() -> None:
    # A raw NXDOMAIN packet, as Quad9 sends for a blocked name, parses to "blocked".
    q = dnswire.build_query("isitblocked.org", ident=9)
    raw = struct.pack("!HHHHHH", 9, 0x8183, 1, 0, 0, 0) + q[12:]
    assert is_blocked(dnswire.parse_response(raw))
