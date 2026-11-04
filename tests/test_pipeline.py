"""End-to-end: fake interfaces and a fake backend through run_discovery, rules and overview."""

from __future__ import annotations

import ipaddress

import pytest

from lanwatch import pipeline
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
    backend.hosts = [HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="fake")]

    async def fake_ifaces(ex: object = None) -> list[Interface]:
        return ifaces

    async def fake_select(ex: object, cfg: ScanConfig) -> FakeBackend:
        return backend

    async def no_nmap(ex: object) -> bool:
        return False

    monkeypatch.setattr(pipeline, "list_interfaces", fake_ifaces)
    monkeypatch.setattr(pipeline, "select_backend", fake_select)
    monkeypatch.setattr(pipeline, "nmap_available", no_nmap)
    config.network.exclude_hosts = ["192.168.1.99"]

    first = await pipeline.run_discovery(config, store)
    assert first.baseline and first.backend == "fake"
    assert first.subnets == ["192.168.1.0/24 via eth0"]
    assert first.hosts == 2  # gateway + this host itself
    assert config.overview_path.exists()

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
