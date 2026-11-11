"""End-to-end: fake interfaces and a fake backend through run_discovery, rules and overview."""

from __future__ import annotations

import ipaddress

import pytest

from lanwatch import pipeline
from lanwatch.collectors.base import LocalExecutor
from lanwatch.collectors.latency import PingResult
from lanwatch.config import Config, ScanConfig
from lanwatch.models import FindingStatus, HostObservation
from lanwatch.netinfo import Interface, Subnet
from lanwatch.store import Store


class FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.hosts: list[HostObservation] = []
        self.seen_subnets: list[Subnet] = []

    async def available(self, ex: object) -> bool:
        return True

    async def discover(
        self, ex: object, subnets: list[Subnet], cfg: ScanConfig
    ) -> list[HostObservation]:
        self.seen_subnets = subnets
        return list(self.hosts)


async def test_run_discovery_end_to_end(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    ifaces = [
        Interface("lo", None, [ipaddress.IPv4Interface("127.0.0.1/8")]),
        Interface("eth0", "aa:bb:cc:dd:ee:ff", [ipaddress.IPv4Interface("192.168.1.10/24")]),
    ]
    backend = FakeBackend()
    backend.hosts = [
        HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="fake"),
        # nmap lists the scanning machine too, without a MAC; it must not become a second
        # device next to the one known from the interface list.
        HostObservation(ip="192.168.1.10", source="fake"),
    ]

    async def fake_ifaces(ex: object = None) -> list[Interface]:
        return ifaces

    async def fake_select(ex: object, cfg: ScanConfig) -> FakeBackend:
        return backend

    async def no_nmap(ex: object) -> bool:
        return False

    async def gateways(ex: object = None) -> list[str]:
        return ["192.168.1.1"]  # not this machine's real routing table

    monkeypatch.setattr(pipeline, "default_gateways", gateways)
    monkeypatch.setattr(pipeline, "list_interfaces", fake_ifaces)
    monkeypatch.setattr(pipeline, "select_backend", fake_select)
    monkeypatch.setattr(pipeline, "nmap_available", no_nmap)
    config.network.exclude_hosts = ["192.168.1.99"]

    first = await pipeline.run_discovery(config, store)
    assert first.baseline and first.backend == "fake"
    assert first.subnets == ["192.168.1.0/24 via eth0"]
    assert first.hosts == 2  # gateway + this host itself, once
    assert config.overview_path.exists()
    assert store.device_by_key("ip:192.168.1.10") is None
    assert store.meta_get("net.pin.192.168.1.1") == "aa:bb:cc:00:00:01"  # gateway pinned
    assert not [f for f in store.findings() if f.rule_id == "net.ip-conflict"]

    backend.hosts.append(HostObservation(ip="192.168.1.99", mac="aa:bb:cc:00:00:99", source="fake"))
    backend.hosts.append(HostObservation(ip="192.168.1.50", mac="aa:bb:cc:00:00:50", source="fake"))
    second = await pipeline.run_discovery(config, store)
    assert not second.baseline
    assert second.hosts == 3  # excluded host is not recorded
    assert len(second.new_devices) == 1 and len(second.new_findings) == 1
    assert store.device_by_key("aa:bb:cc:00:00:99") is None

    f = store.findings(FindingStatus.OPEN)[0]
    assert f.rule_id == "inventory.new-device" and f.evidence["ip"] == "192.168.1.50"
    assert "192.168.1.50" in config.overview_path.read_text()


async def test_run_inventory_with_fake_nmap(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lanwatch.collectors.services import ServiceScanResult, parse_nmap_xml_services
    from tests.conftest import fixture_text

    res = parse_nmap_xml_services(fixture_text("nmap-services.xml"))
    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(
        sid,
        [
            HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="t"),
            HostObservation(ip="192.168.1.40", source="t"),
            HostObservation(ip="192.168.1.77", source="t"),  # will not answer the scan
        ],
    )
    store.finish_snapshot(sid, 3)
    scanned: list[list[str]] = []

    async def fake_scan(
        ex: object, targets: list[str], cfg: ScanConfig, deep: bool
    ) -> ServiceScanResult:
        scanned.append(sorted(targets))
        return res

    monkeypatch.setattr(pipeline, "scan_services", fake_scan)
    out = await pipeline.run_inventory(config, store)
    assert scanned == [["192.168.1.1", "192.168.1.40", "192.168.1.77"]]
    assert out.devices == 2 and out.opened == 7 and out.closed == 0
    assert len(out.new_findings) == 6
    assert store.services(rec.new_device_ids[2]) == []
    assert "22/tcp ssh" in config.overview_path.read_text()

    # Deep scan only targets devices never deep-scanned; after it, nothing is due.
    out2 = await pipeline.run_inventory(config, store, deep=True)
    assert out2.devices == 2 and out2.new_findings == []
    out3 = await pipeline.run_inventory(config, store, deep=True)
    assert out3.devices == 0 and scanned[-1] != scanned[-2]


async def test_skip_hosts_are_tracked_but_never_scanned(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """scan.skip_hosts names devices by IP or MAC (any case). They stay in the inventory,
    and no scan, scheduled or asked for by device id, puts them in nmap's target list."""
    from lanwatch.collectors.services import ServiceScanResult

    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(
        sid,
        [
            HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="t"),
            HostObservation(ip="192.168.1.40", source="t"),
            HostObservation(ip="192.168.1.77", source="t"),
        ],
    )
    store.finish_snapshot(sid, 3)
    config.scan.skip_hosts = ["AA:BB:CC:00:00:01", "192.168.1.77"]
    scanned: list[list[str]] = []

    async def fake_scan(
        ex: object, targets: list[str], cfg: ScanConfig, deep: bool
    ) -> ServiceScanResult:
        scanned.append(sorted(targets))
        return ServiceScanResult(hosts=[])

    monkeypatch.setattr(pipeline, "scan_services", fake_scan)
    await pipeline.run_inventory(config, store)
    assert scanned == [["192.168.1.40"]]
    # Asking for the skipped device by id does not override the list either.
    out = await pipeline.run_inventory(config, store, device_ids=[rec.new_device_ids[0]])
    assert out.devices == 0 and scanned == [["192.168.1.40"]]
    assert len(store.devices()) == 3  # still tracked


class Pinger:
    """Stands in for latency.measure and the neighbour table: no packets leave the test."""

    def __init__(self) -> None:
        self.asked: list[list[str]] = []
        self.answers: dict[str, str] = {}  # ip -> MAC of whoever answers the slow ping

    async def measure(
        self, ex: object, targets: list[str], count: int, wait_s: int = 1
    ) -> list[PingResult]:
        assert (count, wait_s) == (pipeline.RECHECK_COUNT, pipeline.RECHECK_WAIT_S)
        self.asked.append(list(targets))
        return [
            PingResult(t, count, count if t in self.answers else 0, None, None) for t in targets
        ]

    async def neighbours(self, ex: object) -> dict[str, str]:
        return dict(self.answers)


def _discovery_round(store: Store, hosts: list[HostObservation]) -> int:
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, hosts)
    store.finish_snapshot(sid, len(hosts))
    return sid


async def test_recheck_pings_only_who_should_be_there(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lanwatch.config import UnifiConfig

    pinger = Pinger()
    monkeypatch.setattr(pipeline, "measure", pinger.measure)
    monkeypatch.setattr(pipeline, "neighbour_table", pinger.neighbours)
    subnets = [Subnet(ipaddress.IPv4Network("192.168.1.0/24"), "eth0")]
    gw = HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="t")
    phone = HostObservation(ip="192.168.1.50", mac="aa:bb:cc:00:00:50", source="t")
    tv = HostObservation(ip="192.168.1.60", mac="aa:bb:cc:00:00:60", source="t")
    previous = _discovery_round(store, [gw, phone, tv])
    store.replace_infra(
        "unifi-client",
        {
            "ec:94:cb:77:99:00": {"mac": "ec:94:cb:77:99:00", "ip": "192.168.1.224"},  # asleep
            "aa:bb:cc:00:00:77": {"mac": "aa:bb:cc:00:00:77", "ip": "10.0.20.7"},  # other VLAN
            "aa:bb:cc:00:00:78": {"mac": "aa:bb:cc:00:00:78", "ip": None},  # no address
            "aa:bb:cc:00:00:01": {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.1"},  # answered
        },
        store.begin_snapshot("infra", "t"),
    )
    config.network.exclude_hosts = ["192.168.1.60"]  # never touched, also not by the recheck
    this_round = [gw]  # the phone and the charger slept through the scan

    async def recheck() -> list[HostObservation]:
        return await pipeline.recheck_silent(
            config,
            store,
            LocalExecutor(),  # never runs anything: measure and the neighbour table are fakes
            subnets,
            this_round,
            previous,
        )

    config.scan.recheck_silent = True
    assert await recheck() == [] and pinger.asked == [["192.168.1.50"]]  # unifi is off
    config.unifi = UnifiConfig(enabled=True, url="https://console.lan", api_key="k")
    pinger.answers = {"192.168.1.224": "ec:94:cb:77:99:00"}
    found = await recheck()
    assert pinger.asked[-1] == ["192.168.1.50", "192.168.1.224"]
    assert [(h.ip, h.mac, h.source) for h in found] == [
        ("192.168.1.224", "ec:94:cb:77:99:00", "recheck")
    ]
    # A reply this host has no neighbour entry for has no MAC: not recorded.
    pinger.answers = {}
    monkeypatch.setattr(pinger, "neighbours", lambda ex: _const({}))
    assert await recheck() == []
    # The router's ARP table and leases (SNMP) are places to look too, never presence.
    from tests.conftest import snmp_devices

    store.replace_infra(
        "router-arp",
        {"192.168.1.70": {"ip": "192.168.1.70", "mac": "aa:bb:cc:00:00:70"}},
        store.begin_snapshot("infra", "t"),
    )
    pinger.answers = {}
    await recheck()
    assert "192.168.1.70" not in pinger.asked[-1]  # snmp is off
    config.snmp = snmp_devices(gw={"router": True})
    assert await recheck() == []  # asked, did not answer: stays offline
    assert pinger.asked[-1][-1] == "192.168.1.70"
    config.scan.recheck_silent = False
    asked = len(pinger.asked)
    assert await recheck() == [] and len(pinger.asked) == asked  # off: no pings at all


async def _const(value: dict[str, str]) -> dict[str, str]:
    return value


async def test_recheck_keeps_a_sleepy_device_online_and_still_sees_it_leave(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the recheck is presence that only lanwatch's own probes vouch for: a
    device that misses arp-scan but answers the slower ping stays online, and one that
    answers neither goes offline in that very round."""
    ifaces = [Interface("eth0", "aa:bb:cc:dd:ee:ff", [ipaddress.IPv4Interface("192.168.1.10/24")])]
    backend = FakeBackend()
    gw = HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="fake")
    charger = HostObservation(ip="192.168.1.224", mac="ec:94:cb:77:99:00", source="fake")
    backend.hosts = [gw, charger]
    pinger = Pinger()

    async def fake_ifaces(ex: object = None) -> list[Interface]:
        return ifaces

    async def fake_select(ex: object, cfg: ScanConfig) -> FakeBackend:
        return backend

    async def no_nmap(ex: object) -> bool:
        return False

    async def gateways(ex: object = None) -> list[str]:
        return ["192.168.1.1"]

    monkeypatch.setattr(pipeline, "default_gateways", gateways)
    monkeypatch.setattr(pipeline, "list_interfaces", fake_ifaces)
    monkeypatch.setattr(pipeline, "select_backend", fake_select)
    monkeypatch.setattr(pipeline, "nmap_available", no_nmap)
    monkeypatch.setattr(pipeline, "measure", pinger.measure)
    monkeypatch.setattr(pipeline, "neighbour_table", pinger.neighbours)
    config.scan.recheck_silent = True

    await pipeline.run_discovery(config, store)  # baseline: everyone answered
    assert pinger.asked == []  # nobody missing, nothing to ping

    backend.hosts = [gw]  # the charger dozes through arp-scan ...
    pinger.answers = {"192.168.1.224": "ec:94:cb:77:99:00"}  # ... but answers a patient ping
    await pipeline.run_discovery(config, store)
    device = store.device_by_key("ec:94:cb:77:99:00")
    assert pinger.asked == [["192.168.1.224"]]
    assert device is not None and device.online
    assert not [e for e in store.events() if e.kind == "presence.offline"]

    pinger.answers = {}  # now it is really gone
    await pipeline.run_discovery(config, store)
    device = store.device_by_key("ec:94:cb:77:99:00")
    assert device is not None and not device.online  # this round, not 45 minutes later
    assert [e.kind for e in store.events() if e.kind == "presence.offline"] == ["presence.offline"]


async def test_hostnames_resolved_whatever_the_backend(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """arp-scan never names hosts and nmap runs with -n, so scan.resolve_hostnames must
    apply after any backend, not only after the ping sweep (regression: it did not)."""
    import socket

    ifaces = [Interface("eth0", "aa:bb:cc:dd:ee:ff", [ipaddress.IPv4Interface("192.168.1.10/24")])]
    backend = FakeBackend()
    backend.hosts = [
        HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="arp-scan"),
        HostObservation(ip="192.168.1.9", mac="aa:bb:cc:00:00:09", source="arp-scan"),
        HostObservation(ip="192.168.1.20", mac="aa:bb:cc:00:00:20", source="arp-scan"),
        HostObservation(ip="192.168.1.99", mac="aa:bb:cc:00:00:99", source="arp-scan"),
    ]
    names = {"192.168.1.9": "hydra.example.net", "192.168.1.99": "excluded.example.net"}
    asked: list[str] = []

    def fake_getnameinfo(addr: tuple[str, int], flags: int) -> tuple[str, str]:
        asked.append(addr[0])
        assert flags & socket.NI_NAMEREQD
        if addr[0] not in names:
            raise socket.gaierror(socket.EAI_NONAME, "no name")
        return names[addr[0]], "0"

    async def fake_ifaces(ex: object = None) -> list[Interface]:
        return ifaces

    async def fake_select(ex: object, cfg: ScanConfig) -> FakeBackend:
        return backend

    async def no_nmap(ex: object) -> bool:
        return False

    async def gateways(ex: object = None) -> list[str]:
        return ["192.168.1.1"]

    monkeypatch.setattr(socket, "getnameinfo", fake_getnameinfo)
    monkeypatch.setattr(pipeline, "default_gateways", gateways)
    monkeypatch.setattr(pipeline, "list_interfaces", fake_ifaces)
    monkeypatch.setattr(pipeline, "select_backend", fake_select)
    monkeypatch.setattr(pipeline, "nmap_available", no_nmap)
    config.network.exclude_hosts = ["192.168.1.99"]

    config.scan.resolve_hostnames = False
    await pipeline.run_discovery(config, store)
    assert asked == []
    hydra = store.device_by_key("aa:bb:cc:00:00:09")
    assert hydra is not None and hydra.hostname is None

    # Switched on (the default): known devices get their name on the next round, a
    # failed lookup leaves the name empty, and excluded hosts are never looked up.
    config.scan.resolve_hostnames = True
    await pipeline.run_discovery(config, store)
    hydra = store.device_by_key("aa:bb:cc:00:00:09")
    other = store.device_by_key("aa:bb:cc:00:00:20")
    assert hydra is not None and hydra.hostname == "hydra.example.net"
    assert other is not None and other.hostname is None
    assert "192.168.1.99" not in asked and "192.168.1.9" in asked


async def test_resolve_hostnames_keeps_backend_names_and_survives_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket
    import time

    from lanwatch.collectors.discovery import resolve_hostnames

    def fake_getnameinfo(addr: tuple[str, int], flags: int) -> tuple[str, str]:
        if addr[0] == "10.0.0.3":
            time.sleep(0.3)  # a resolver that does not answer in time
        return f"host-{addr[0].rsplit('.', 1)[1]}", "0"

    monkeypatch.setattr(socket, "getnameinfo", fake_getnameinfo)
    hosts = [
        HostObservation(ip="10.0.0.1", hostname="from-nmap", source="nmap"),
        HostObservation(ip="10.0.0.2", source="arp-scan"),
        HostObservation(ip="10.0.0.3", source="arp-scan"),
    ]
    got = await resolve_hostnames(hosts, timeout=0.1)
    assert [h.hostname for h in got] == ["from-nmap", "host-2", None]
