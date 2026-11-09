from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx2
import pytest

from lanwatch.collectors import upnp
from lanwatch.collectors.infra import (
    InfraResult,
    build_broadcast_args,
    build_ipv6_scan_args,
    parse_broadcast_results,
    parse_ipv6_neigh,
)
from lanwatch.collectors.services import PortObservation, PortSet
from lanwatch.config import Config, ScanConfig
from lanwatch.models import FindingStatus, HostObservation
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.rules.versions import version_tuple
from lanwatch.store import Store
from tests.conftest import fixture_text, helper_refusal

SOAP_MAPPING = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>{int}</NewInternalPort><NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{desc}</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""
SOAP_EXT_IP = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"""
SOAP_ERR = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
<detail><UPnPError><errorCode>713</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"""


def test_parse_broadcast_fixture() -> None:
    offers, mdns = parse_broadcast_results(fixture_text("nmap-broadcast.xml"), "eth0")
    assert [o.server for o in offers] == ["192.168.1.1", "192.168.1.66"]
    assert offers[0].dns == ["192.168.1.1", "1.1.1.1"] and offers[0].domain == "lan"
    assert mdns == {
        "192.168.1.40": ["_http._tcp.local (5000/tcp)", "_smb._tcp.local (445/tcp)"],
        "192.168.1.33": ["_ssh._tcp.local (22/tcp)"],
    }
    assert parse_broadcast_results("<nmaprun/>", "eth0") == ([], {})


def test_ipv6_neigh_and_args() -> None:
    data: list[dict[str, object]] = [
        {"dst": "fe80::1", "lladdr": "aa:bb:cc:00:00:01", "state": ["REACHABLE"]},
        {"dst": "2a01:4f8::10", "lladdr": "aa:bb:cc:00:00:01", "state": ["STALE"]},
        {"dst": "2a01:4f8::11", "lladdr": "AA-BB-CC-00-00-01", "state": ["REACHABLE"]},
        {"dst": "fd00::5", "lladdr": "aa:bb:cc:00:00:02", "state": ["REACHABLE"]},
        {"dst": "2001:db8::1", "lladdr": "aa:bb:cc:00:00:02", "state": ["REACHABLE"]},  # doc prefix
        {"dst": "2a01:4f8::99", "lladdr": "aa:bb:cc:00:00:03", "state": ["FAILED"]},
        {"dst": "192.168.1.1", "lladdr": "aa:bb:cc:00:00:04", "state": ["REACHABLE"]},
    ]
    assert parse_ipv6_neigh(data) == {"aa:bb:cc:00:00:01": ["2a01:4f8::10", "2a01:4f8::11"]}
    cfg = ScanConfig()
    assert helper_refusal(build_ipv6_scan_args(["2001:db8::10"], cfg)) is None
    assert helper_refusal(build_broadcast_args("eth0", cfg)) is None


async def test_upnp_description_and_mappings() -> None:
    calls: list[tuple[str, str]] = []

    def handle(req: httpx2.Request) -> httpx2.Response:
        action = req.headers.get("SOAPAction", "")
        calls.append((req.url.path, action))
        if req.url.path == "/desc.xml":
            return httpx2.Response(200, text=fixture_text("upnp-igd.xml"))
        if "GetExternalIPAddress" in action:
            return httpx2.Response(200, text=SOAP_EXT_IP)
        if "GetGenericPortMappingEntry" in action:
            idx = int(req.content.decode().split("<NewPortMappingIndex>")[1].split("<")[0])
            rows = [
                (443, 8443, "192.168.1.40", "nas https"),
                (25565, 25565, "192.168.1.50", "minecraft"),
            ]
            if idx < len(rows):
                e, i, c, d = rows[idx]
                return httpx2.Response(
                    200, text=SOAP_MAPPING.format(ext=e, int=i, client=c, desc=d)
                )
            return httpx2.Response(500, text=SOAP_ERR)
        return httpx2.Response(404)

    r = upnp.parse_ssdp_response(
        b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\n"
        b"ST: upnp:rootdevice\r\nSERVER: Linux UPnP/1.0\r\n\r\n",
        "192.168.1.1",
    )
    assert r and r.location == "http://192.168.1.1:5000/desc.xml" and r.server == "Linux UPnP/1.0"
    assert upnp.parse_ssdp_response(b"NOTIFY * HTTP/1.1\r\n", "x") is None

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handle)) as client:
        resp = await client.get(r.location)
        d = upnp.parse_device_description(resp.text, r.location, "192.168.1.1")
        assert d.is_igd and d.friendly_name == "Home Router" and d.model == "AC-3000 v2"
        assert d.control_url == "http://192.168.1.1:5000/ctl/IPConn"
        assert d.info()["device_type"] == "InternetGatewayDevice"
        await upnp.fetch_mappings(client, d)
    assert d.external_ip == "203.0.113.9"
    assert [(m.external_port, m.internal_client, m.internal_port) for m in d.mappings] == [
        (443, "192.168.1.40", 8443),
        (25565, "192.168.1.50", 25565),
    ]
    assert sum(1 for _, a in calls if "GetGenericPortMappingEntry" in a) == 3


def _seed(store: Store) -> dict[str, int]:
    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(
        sid,
        [
            HostObservation(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", source="t"),
            HostObservation(ip="192.168.1.40", mac="aa:bb:cc:00:00:40", hostname="nas", source="t"),
            HostObservation(ip="192.168.1.50", mac="aa:bb:cc:00:00:50", source="t"),
        ],
    )
    store.finish_snapshot(sid, 3)
    return dict(zip(["gw", "nas", "pc"], rec.new_device_ids, strict=True))


async def test_run_infra_end_to_end(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ipaddress

    from lanwatch import pipeline
    from lanwatch.netinfo import Interface

    ids = _seed(store)
    ifaces = [Interface("eth0", "aa:bb:cc:dd:ee:ff", [ipaddress.IPv4Interface("192.168.1.10/24")])]

    async def fake_ifaces(ex: object = None) -> list[Interface]:
        return ifaces

    probes = InfraResult(probed_dhcp=True)
    from lanwatch.collectors.infra import DhcpOffer

    probes.dhcp = [DhcpOffer("192.168.1.1", "eth0"), DhcpOffer("192.168.1.66", "eth0")]
    probes.mdns = {"192.168.1.40": ["_smb._tcp.local (445/tcp)"]}
    probes.ipv6 = {"aa:bb:cc:00:00:40": ["2001:db8::40"]}
    probes.ipv6_open = {"2001:db8::40": ["445/tcp", "5000/tcp"]}

    async def fake_probes(
        ex: object, interfaces: list[str], cfg: ScanConfig, root: bool
    ) -> InfraResult:
        assert interfaces == ["eth0"]
        return probes

    igd = upnp.UpnpDevice(
        addr="192.168.1.1",
        location="http://192.168.1.1:5000/desc.xml",
        friendly_name="Home Router",
        manufacturer="Acme",
        model="AC-3000",
        device_type="urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        is_igd=True,
        external_ip="203.0.113.9",
        mappings=[
            upnp.PortMapping(443, "TCP", "192.168.1.40", 8443, "nas https"),
            upnp.PortMapping(25565, "TCP", "192.168.1.99", 25565, "old"),
        ],
    )
    tv = upnp.UpnpDevice(
        addr="192.168.1.50", location="http://192.168.1.50/d.xml", friendly_name="Living room TV"
    )

    async def fake_upnp(bind_ips: list[str], timeout: float = 3.0) -> list[upnp.UpnpDevice]:
        assert bind_ips == ["192.168.1.10"]
        return [igd, tv]

    class Ex:
        name = "fake"

        async def run(self, args: list[str], timeout: float) -> tuple[int, str, str]:
            return 0, "", ""

        async def which(self, binary: str) -> tuple[bool, bool]:
            return True, True

    monkeypatch.setattr(pipeline, "list_interfaces", fake_ifaces)
    monkeypatch.setattr(pipeline, "run_probes", fake_probes)
    monkeypatch.setattr(pipeline, "discover_upnp", fake_upnp)
    out = await pipeline.run_infra(config, store, executor=Ex())
    assert out.dhcp_servers == ["192.168.1.1", "192.168.1.66"]
    assert store.meta_get("dhcp.probed") == "yes"
    assert out.upnp_devices == 2 and out.igd_mappings == 2 and out.ipv6_devices == 1
    assert out.devices_enriched == 3

    rules = {f.rule_id: f for f in store.findings(FindingStatus.OPEN)}
    assert "net.rogue-dhcp" in rules and rules["net.rogue-dhcp"].evidence["servers"] == [
        "192.168.1.1",
        "192.168.1.66",
    ]
    assert rules["router.upnp-igd"].device_id == ids["gw"]
    mappings = [
        f for f in store.findings(FindingStatus.OPEN) if f.rule_id == "router.upnp-mappings"
    ]
    assert len(mappings) == 2
    assert any("nas (192.168.1.40):8443" in f.title and f.device_id == ids["nas"] for f in mappings)
    assert any("192.168.1.99:25565" in f.title and f.device_id is None for f in mappings)
    v6 = rules["net.ipv6-global-exposed"]
    assert v6.device_id == ids["nas"] and v6.evidence["open_ports"] == ["445/tcp", "5000/tcp"]

    nas = store.device(ids["nas"])
    assert (
        nas
        and nas.attrs["mdns"] == ["_smb._tcp.local (445/tcp)"]
        and nas.attrs["ipv6"] == ["2001:db8::40"]
    )
    pc = store.device(ids["pc"])
    assert pc and pc.attrs["upnp"]["friendly_name"] == "Living room TV"
    text = config.overview_path.read_text()
    assert (
        "## Infrastructure" in text
        and "more than one" in text
        and "443/TCP -> 192.168.1.40:8443" in text
    )

    # Second run: one DHCP server and no mappings -> findings auto-resolve, infra table replaced.
    probes.dhcp = probes.dhcp[:1]
    igd.mappings = []
    await pipeline.run_infra(config, store, executor=Ex())
    open_rules = {f.rule_id for f in store.findings(FindingStatus.OPEN)}
    assert "net.rogue-dhcp" not in open_rules and "router.upnp-mappings" not in open_rules
    assert "router.upnp-igd" in open_rules
    assert len(store.infra("dhcp")) == 1


def test_version_rules(store: Store, config: Config) -> None:
    assert version_tuple("7.4p1 Debian") == (7, 4) and version_tuple(None) is None
    ids = _seed(store)
    sid = store.begin_snapshot("inventory", "t")
    scanned = {"tcp": PortSet.from_spec("1-65535")}
    vulners: dict[str, Any] = {
        "cpe:/a:openbsd:openssh:6.6": [
            {"id": "CVE-2016-0777", "cvss": "5.0", "type": "cve"},
            {"id": "CVE-2023-38408", "cvss": "9.8", "type": "cve"},
            {"id": "EDB-1", "cvss": "9.0", "type": "exploitdb"},
        ]
    }
    store.record_services(
        sid,
        ids["gw"],
        [
            PortObservation(
                port=22,
                proto="tcp",
                state="open",
                name="ssh",
                product="OpenSSH",
                version="6.6.1p1",
                scripts={"vulners": {"output": "", "data": vulners}},
            ),
            PortObservation(
                port=80, proto="tcp", state="open", name="http", product="nginx", version="1.24.0"
            ),
            PortObservation(
                port=53, proto="tcp", state="open", name="domain", product="dnsmasq", version="2.80"
            ),
        ],
        scanned,
    )
    store.finish_snapshot(sid, 1)
    res = Engine(config).run(
        RuleContext(
            store=store,
            config=config,
            snapshot_id=sid,
            previous_snapshot_id=None,
            is_baseline=False,
        )
    )
    legacy = sorted(f.title for f in res.emitted if f.rule_id == "service.legacy-version")
    assert legacy == [
        "Legacy OpenSSH 6.6.1p1: aa:bb:cc:00:00:01 (192.168.1.1)",
        "Legacy dnsmasq 2.80: aa:bb:cc:00:00:01 (192.168.1.1)",
    ]
    cves = [f for f in res.emitted if f.rule_id == "service.known-cves"]
    assert len(cves) == 1 and cves[0].evidence["total"] == 1  # only cve type >= 7.0
    assert cves[0].evidence["cves"][0]["id"] == "CVE-2023-38408"


def test_flat_network_rule(store: Store, config: Config) -> None:
    ids = _seed(store)
    store.set_device_classification(ids["nas"], "nas", "x", 0.9)
    store.set_device_classification(ids["pc"], "camera", "x", 0.9)
    sid = store.begin_snapshot("infra", "t")
    store.finish_snapshot(sid, 0)
    res = Engine(config).run(
        RuleContext(
            store=store,
            config=config,
            snapshot_id=sid,
            previous_snapshot_id=None,
            is_baseline=False,
        )
    )
    flat = [f for f in res.emitted if f.rule_id == "improvement.flat-network"]
    assert len(flat) == 1 and flat[0].evidence["subnet"] == "192.168.1.0/24"
    assert flat[0].kind.value == "improvement"


def test_web_infra_page(tmp_path: Path, config: Config) -> None:
    from fastapi.testclient import TestClient

    from lanwatch.web.app import create_app

    with Store(config.store_path) as store:
        ids = _seed(store)
        sid = store.begin_snapshot("infra", "t")
        store.replace_infra(
            "dhcp",
            {
                "eth0/192.168.1.1": {
                    "interface": "eth0",
                    "server": "192.168.1.1",
                    "offered_ip": "",
                    "router": "",
                    "dns": [],
                    "domain": "",
                }
            },
            sid,
        )
        store.replace_infra(
            "upnp",
            {
                "192.168.1.1": {
                    "friendly_name": "Home Router",
                    "manufacturer": "Acme",
                    "model": "AC",
                    "device_type": "InternetGatewayDevice",
                    "server": "",
                    "location": "http://x",
                    "is_igd": True,
                    "external_ip": "203.0.113.9",
                    "mappings": [
                        {
                            "external_port": 443,
                            "protocol": "TCP",
                            "internal_client": "192.168.1.40",
                            "internal_port": 8443,
                            "description": "nas",
                            "enabled": True,
                            "remote_host": "",
                            "lease_seconds": 0,
                        }
                    ],
                }
            },
            sid,
        )
        store.merge_device_attrs(
            ids["nas"],
            {
                "ipv6": ["2001:db8::40"],
                "ipv6_open": {"2001:db8::40": ["445/tcp"]},
                "mdns": ["_smb._tcp.local (445/tcp)"],
            },
        )
        store.finish_snapshot(sid, 1)
    client = TestClient(create_app(config))
    r = client.get("/infra")
    assert (
        r.status_code == 200
        and "Home Router" in r.text
        and "203.0.113.9" in r.text
        and "8443" in r.text
    )
    assert "2001:db8::40" in r.text
    assert "1 port mapping" in client.get("/").text
    d = client.get(f"/devices/{ids['nas']}").text
    assert "_smb._tcp.local" in d and "2001:db8::40" in d
    assert json.loads(client.get("/api/devices").text)[0]["attrs"] is not None


def test_infra_page_says_why_there_is_no_dhcp_result(config: Config) -> None:
    """ "Needs root or the helper" was shown before the first infra round too, while the
    helper was running fine and the round was only queued."""
    from fastapi.testclient import TestClient

    from lanwatch.web.app import create_app

    with Store(config.store_path):
        pass
    client = TestClient(create_app(config))
    assert "Not probed yet: the first infra round has not run." in client.get("/infra").text
    with Store(config.store_path) as store:
        store.finish_snapshot(store.begin_snapshot("infra", "helper"), 0)
        store.meta_set("dhcp.probed", "no")
    text = client.get("/infra").text
    assert "Not probed: the DHCP probe needs root, CAP_NET_RAW or the helper." in text
    with Store(config.store_path) as store:
        store.meta_set("dhcp.probed", "yes")
    assert "No DHCP server answered the last probe." in client.get("/infra").text
