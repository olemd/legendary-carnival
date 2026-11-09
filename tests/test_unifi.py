from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient

from lanwatch import pipeline
from lanwatch.collectors.unifi import (
    UnifiAuthError,
    UnifiError,
    UnifiSnapshot,
    fetch_unifi,
    make_client,
    parse_client,
    parse_device,
    parse_network,
    parse_ssid,
    tls_verify,
)
from lanwatch.config import Config, ConfigError, UnifiConfig, load_config
from lanwatch.llm.tasks import device_facts
from lanwatch.models import HostObservation, Severity
from lanwatch.pipeline import collect_unifi, run_unifi
from lanwatch.rules.base import RuleContext
from lanwatch.rules.infra import FlatNetworkRule
from lanwatch.rules.unifi import IotOnMainNetworkRule, UnifiDeviceOfflineRule, UnifiOnlyClientRule
from lanwatch.rules.versions import FirmwareOutdatedRule
from lanwatch.store import Store
from lanwatch.web.app import create_app
from lanwatch.web.topology import MAX_CLIENTS_PER_DEVICE, build_topology
from tests.conftest import fixture_text

SITE = "33333333-0000-0000-0000-000000000001"
GW, AP, SW = (f"11111111-0000-0000-0000-00000000000{i}" for i in (1, 2, 3))
NET_DEFAULT, NET_IOT = (f"22222222-0000-0000-0000-00000000000{i}" for i in (1, 2))
PREFIX = "/proxy/network/integration/v1"


def _fx(name: str) -> Any:
    return json.loads(fixture_text(f"unifi/{name}.json"))


def _cfg(**kw: Any) -> UnifiConfig:
    return UnifiConfig(enabled=True, url="https://console.lan", api_key="k", **kw)


class Controller:
    """A fake console: answers from the fixtures, records every request."""

    def __init__(self, status: int | None = None, broken_details: bool = False) -> None:
        self.calls: list[str] = []
        self.status = status
        self.broken_details = broken_details

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(
            str(request.url.path) + ("?" + request.url.query.decode() if request.url.query else "")
        )
        assert request.headers["X-API-Key"] == "k"
        assert request.headers["Accept"] == "application/json"
        assert request.url.path.startswith(PREFIX)
        if self.status is not None:
            return httpx2.Response(self.status, text="nope")
        path = request.url.path.removeprefix(PREFIX)
        params = dict(request.url.params)
        if path == "/info":
            return httpx2.Response(200, json=_fx("info"))
        if path == "/sites":
            return httpx2.Response(200, json=_fx("sites"))
        if path == f"/sites/{SITE}/clients":
            return httpx2.Response(
                200, json=_fx("clients-1" if params.get("offset") == "0" else "clients-2")
            )
        if path == f"/sites/{SITE}/devices":
            return httpx2.Response(200, json=_fx("devices"))
        if path.startswith(f"/sites/{SITE}/devices/"):
            if self.broken_details:
                return httpx2.Response(500, text="boom")
            which = {GW: "device-gw", AP: "device-ap", SW: "device-sw"}[path.rsplit("/", 1)[1]]
            return httpx2.Response(200, json=_fx(which))
        if path == f"/sites/{SITE}/networks":
            return httpx2.Response(200, json=_fx("networks"))
        if path.startswith(f"/sites/{SITE}/networks/"):
            which = {NET_DEFAULT: "network-default", NET_IOT: "network-iot"}[path.rsplit("/", 1)[1]]
            return httpx2.Response(200, json=_fx(which))
        if path == f"/sites/{SITE}/wifi/broadcasts":
            return httpx2.Response(200, json=_fx("wifi-broadcasts"))
        raise AssertionError(f"unexpected request {path}")

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            base_url="https://console.lan" + PREFIX,
            headers={"X-API-Key": "k", "Accept": "application/json"},
            transport=httpx2.MockTransport(self.handle),
        )


# -- parsing ----------------------------------------------------------------------


def test_parse_client_checks_fields() -> None:
    rows = _fx("clients-1")["data"]
    wired = parse_client(rows[0])
    assert wired is not None and wired.wired and wired.mac == "a8:bb:cc:00:00:40"
    assert wired.uplink_device_id == GW and not wired.guest and wired.name == "nas"
    guest = parse_client(rows[1])
    assert guest is not None and not guest.wired and guest.guest
    vpn = parse_client(_fx("clients-2")["data"][0])
    assert vpn is not None and vpn.type == "VPN" and vpn.mac is None
    assert parse_client({"type": "WIRED"}) is None  # no id
    odd = parse_client({"id": "x", "type": "ALIEN", "macAddress": 42, "access": "GUEST"})
    assert odd is not None and odd.type == "WIRED" and odd.mac is None and not odd.guest


def test_parse_device_details() -> None:
    gw = parse_device(_fx("devices")["data"][0], _fx("device-gw"))
    assert gw is not None and gw.is_gateway and gw.is_access_point and not gw.offline
    assert gw.ports_summary() == {"total": 2, "up": 1, "poe": 0}
    assert [r["band"] for r in gw.radios_summary()] == [5, 2.4]
    assert gw.firmware_updatable and gw.uplink_device_id is None and gw.adopted_at
    ap = parse_device(_fx("devices")["data"][1], _fx("device-ap"))
    assert ap is not None and ap.uplink_device_id == GW and ap.ports_summary()["poe"] == 1
    sw = parse_device(_fx("devices")["data"][2])  # no details on an older release
    assert sw is not None and sw.offline and sw.ports == [] and not sw.firmware_updatable
    assert parse_device({"name": "no id"}) is None


def test_parse_network_subnet_and_lookup() -> None:
    rows = _fx("networks")["data"]
    default = parse_network(rows[0], _fx("network-default"))
    iot = parse_network(rows[1], _fx("network-iot"))
    legacy = parse_network(rows[2])
    assert default is not None and default.subnet == "192.168.1.0/24" and default.default
    assert iot is not None and iot.subnet == "192.168.20.0/24" and iot.isolation is True
    assert legacy is not None and legacy.subnet is None and legacy.management == "UNMANAGED"
    snap = UnifiSnapshot(networks=[default, iot, legacy])
    assert snap.network_for_ip("192.168.20.9") is iot
    assert snap.network_for_ip("192.168.1.9") is default
    assert snap.network_for_ip("10.0.0.1") is None and snap.network_for_ip("junk") is None


def test_parse_ssid_and_ssids_for_network() -> None:
    rows = _fx("wifi-broadcasts")["data"]
    home, things = parse_ssid(rows[0]), parse_ssid(rows[1])
    assert home is not None and home.network_type == "NATIVE" and home.network_id is None
    assert things is not None and things.type == "IOT_OPTIMIZED" and things.network_id == NET_IOT
    nets = [parse_network(r) for r in _fx("networks")["data"]]
    snap = UnifiSnapshot(networks=[n for n in nets if n], ssids=[home, things])
    assert snap.ssids_for_network(NET_DEFAULT) == ["Home Wi-Fi"]
    assert snap.ssids_for_network(NET_IOT) == ["Things"]


# -- HTTP -------------------------------------------------------------------------


async def test_fetch_paginates_and_authenticates() -> None:
    ctl = Controller()
    snap = await fetch_unifi(_cfg(), ctl.client())
    assert snap.version == "10.1.84" and snap.site_name == "Home" and snap.site_id == SITE
    assert [c.id for c in snap.clients] == ["c1", "c2", "c3"]
    assert [d.model for d in snap.devices] == ["UX7", "U7-Pro", "USW-Lite-8-PoE"]
    assert snap.devices[1].uplink_device_id == GW  # from the detail call
    assert [n.subnet for n in snap.networks] == ["192.168.1.0/24", "192.168.20.0/24", None]
    client_pages = [c for c in ctl.calls if c.endswith("limit=200") and "/clients?" in c]
    assert [c.split("offset=")[1].split("&")[0] for c in client_pages] == ["0", "2"]
    # Details for every device, but only for the gateway-managed networks.
    assert sum(1 for c in ctl.calls if "/devices/" in c) == 3
    assert sum(1 for c in ctl.calls if "/networks/" in c) == 2


async def test_auth_and_server_errors() -> None:
    with pytest.raises(UnifiAuthError):
        await fetch_unifi(_cfg(), Controller(status=401).client())
    with pytest.raises(UnifiError):
        await fetch_unifi(_cfg(), Controller(status=500).client())

    def not_json(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, text="<html>login</html>")

    with pytest.raises(UnifiError, match="not JSON"):
        await fetch_unifi(_cfg(), httpx2.AsyncClient(transport=httpx2.MockTransport(not_json)))


async def test_site_by_name_and_detail_failure_keeps_overview() -> None:
    snap = await fetch_unifi(_cfg(site="Home"), Controller(broken_details=True).client())
    assert snap.site_id == SITE and len(snap.devices) == 3
    assert snap.devices[1].uplink_device_id is None  # overview only
    with pytest.raises(UnifiError, match="no site called"):
        await fetch_unifi(_cfg(site="Cabin"), Controller().client())


def test_tls_flags(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert tls_verify(_cfg()) is True
    assert tls_verify(_cfg(verify_tls=False)) is False
    assert tls_verify(_cfg(ca_file=tmp_path / "ca.pem")) == str(tmp_path / "ca.pem")
    seen: dict[str, Any] = {}

    class Recorder:
        def __init__(self, **kw: Any) -> None:
            seen.update(kw)

    monkeypatch.setattr("lanwatch.collectors.unifi.httpx2.AsyncClient", Recorder)
    make_client(_cfg(verify_tls=False))
    assert seen["base_url"] == "https://console.lan" + PREFIX
    assert seen["verify"] is False and seen["trust_env"] is False
    assert seen["headers"]["X-API-Key"] == "k"


def test_config_validation() -> None:
    with pytest.raises(ValueError, match="api_key"):
        UnifiConfig(enabled=True)
    with pytest.raises(ValueError, match="https"):
        UnifiConfig(url="http://console.lan")
    with pytest.raises(ValueError, match="contradict"):
        UnifiConfig(verify_tls=False, ca_file=Path("/x"))
    assert not UnifiConfig().enabled
    with pytest.raises(ConfigError):
        load_config(None, {"unifi": {"enabled": True}}, environ={})


# -- merging into lanwatch ----------------------------------------------------------


def _seed(store: Store) -> dict[str, int]:
    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(
        sid,
        [
            HostObservation(ip="192.168.1.1", mac="a8:bb:cc:00:00:01", source="t"),  # the gateway
            HostObservation(ip="192.168.1.2", mac="a8:bb:cc:00:00:02", source="t"),  # the AP
            HostObservation(ip="192.168.1.40", mac="a8:bb:cc:00:00:40", hostname="nas", source="t"),
        ],
    )
    store.finish_snapshot(sid, 3)
    return dict(zip(["gw", "ap", "nas"], rec.new_device_ids, strict=True))


async def test_collect_merges_attrs_rows_names_and_firmware(store: Store, config: Config) -> None:
    config.unifi = _cfg()
    ids = _seed(store)
    sid = store.begin_snapshot("infra", "t")
    out = await collect_unifi(config, store, sid, Controller().client())
    assert out.error is None and out.clients == 2 and out.known_clients == 1 and out.devices == 3
    assert set(out.enriched) == {ids["gw"], ids["ap"], ids["nas"]}

    nas = store.device(ids["nas"])
    assert nas is not None
    u = nas.attrs["unifi"]
    assert u["wired"] and not u["guest"] and u["uplink"]["name"] == "Express"
    assert u["network"] == {"id": NET_DEFAULT, "name": "Default", "vlan": 1, "default": True}
    assert "ssids_on_network" not in u  # wired
    # The controller's "nas" equals the hostname: not a name anyone chose, so not adopted.
    # The gateway and the AP carry names a person typed in: adopted.
    assert nas.name is None and out.named == 2

    gw = store.device(ids["gw"])
    assert gw is not None and gw.name == "Express"  # a real alias: adopted
    assert gw.attrs["unifi_device"]["ports"] == {"total": 2, "up": 1, "poe": 0}
    fw = gw.attrs["firmware"]
    assert fw["update"] is True and fw["latest"] is None and fw["source"] == "unifi"
    assert fw["product"] == "UniFi UX7" and fw["version"] == "4.3.6"
    ap = store.device(ids["ap"])
    assert ap is not None and ap.attrs["firmware"]["update"] is False

    kinds = {
        k: [r.key for r in store.infra(k)]
        for k in ("unifi-network", "unifi-ssid", "unifi-device", "unifi-client")
    }
    assert len(kinds["unifi-network"]) == 3 and len(kinds["unifi-ssid"]) == 2
    assert sorted(kinds["unifi-device"]) == [
        "a8:bb:cc:00:00:01",
        "a8:bb:cc:00:00:02",
        "a8:bb:cc:00:00:03",
    ]
    assert sorted(kinds["unifi-client"]) == ["a8:bb:cc:00:00:40", "a8:bb:cc:00:00:77"]  # no VPN
    visitor = next(r for r in store.infra("unifi-client") if r.key.endswith("77"))
    assert (
        visitor.data["known"] is False
        and visitor.data["guest"]
        and visitor.data["uplink_name"] == "Loft AP"
    )
    assert store.meta_get("unifi.version") == "10.1.84" and store.meta_get("unifi.last_error") == ""


async def test_collect_never_overwrites_a_probed_firmware_or_a_persons_name(
    store: Store, config: Config
) -> None:
    config.unifi = _cfg()
    ids = _seed(store)
    store.set_device_name(ids["gw"], "Ruteren")
    store.merge_device_attrs(
        ids["gw"], {"firmware": {"product": "Other", "version": "1", "source": "http"}}
    )
    await collect_unifi(config, store, store.begin_snapshot("infra", "t"), Controller().client())
    gw = store.device(ids["gw"])
    assert gw is not None and gw.name == "Ruteren" and gw.attrs["firmware"]["product"] == "Other"
    config.unifi = _cfg(adopt_names=False)
    store.set_device_name(ids["gw"], None)
    await collect_unifi(config, store, store.begin_snapshot("infra", "t"), Controller().client())
    gw = store.device(ids["gw"])
    assert gw is not None and gw.name is None


async def test_collect_keeps_state_when_the_controller_is_down(
    store: Store, config: Config
) -> None:
    config.unifi = _cfg()
    _seed(store)
    await collect_unifi(config, store, store.begin_snapshot("infra", "t"), Controller().client())
    before = {r.key for r in store.infra("unifi-client")}
    out = await collect_unifi(
        config, store, store.begin_snapshot("infra", "t"), Controller(status=401).client()
    )
    assert out.error and "401" in out.error
    assert {r.key for r in store.infra("unifi-client")} == before
    assert store.meta_get("unifi.last_error") == out.error

    async def boom(cfg: UnifiConfig, client: object = None) -> UnifiSnapshot:
        raise RuntimeError("wire fell out")

    out = (
        await collect_unifi(config, store, store.begin_snapshot("infra", "t"), None)
        if False
        else out
    )
    import unittest.mock as mock

    with mock.patch.object(pipeline, "fetch_unifi", boom):
        out = await collect_unifi(config, store, store.begin_snapshot("infra", "t"))
    assert out.error == "RuntimeError: wire fell out"


async def test_run_infra_completes_when_the_controller_fails(
    store: Store, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The latency lesson: a side collector must never take the round down."""
    import ipaddress

    from lanwatch.collectors.infra import InfraResult
    from lanwatch.netinfo import Interface

    config.unifi = _cfg()
    config.scan.upnp = False
    config.scan.ipv6 = False
    _seed(store)

    async def fake_ifaces(ex: object = None) -> list[Interface]:
        return [
            Interface("eth0", "aa:bb:cc:dd:ee:ff", [ipaddress.IPv4Interface("192.168.1.10/24")])
        ]

    async def fake_probes(*a: object, **k: object) -> InfraResult:
        return InfraResult()

    async def boom(cfg: UnifiConfig, client: object = None) -> UnifiSnapshot:
        raise UnifiError("/info: HTTP 503")

    async def no_routers(ex: object = None) -> list[dict[str, str]]:
        return []

    class Ex:
        name = "fake"

        async def run(self, args: list[str], timeout: float) -> tuple[int, str, str]:
            return 0, "", ""

        async def which(self, binary: str) -> tuple[bool, bool]:
            return True, True

    monkeypatch.setattr(pipeline, "list_interfaces", fake_ifaces)
    monkeypatch.setattr(pipeline, "run_probes", fake_probes)
    monkeypatch.setattr(pipeline, "fetch_unifi", boom)
    monkeypatch.setattr(pipeline, "ipv6_routers", no_routers)
    out = await pipeline.run_infra(config, store, executor=Ex())
    assert out.unifi_error == "/info: HTTP 503" and out.unifi_clients == 0


async def test_run_unifi_and_rules(store: Store, config: Config) -> None:
    config.unifi = _cfg()
    ids = _seed(store)
    store.set_device_kind(ids["nas"], "nas")
    import unittest.mock as mock

    with mock.patch.object(
        pipeline, "fetch_unifi", lambda cfg, client=None: fetch_unifi(cfg, Controller().client())
    ):
        out = await run_unifi(config, store)
    assert out.error is None
    rules = {f.rule_id: f for f in store.findings()}
    assert "inventory.unifi-only" in rules and "net.unifi-device-offline" in rules
    only = rules["inventory.unifi-only"]
    assert only.title.startswith("Only the controller sees Visitor phone (192.168.1.77, Default)")
    assert only.evidence["guest"] is True
    offline = rules["net.unifi-device-offline"]
    assert (
        offline.title == "UniFi Garage switch (USW-Lite-8-PoE) is offline"
        and offline.device_id is None
    )
    assert offline.severity is Severity.HIGH
    # The gateway has an update, and the controller cannot say which version.
    fw = rules["device.firmware-outdated"]
    assert fw.title.endswith("UniFi UX7 4.3.6 has an update available")
    # A NAS on the default network is not IoT: no segmentation finding.
    assert "net.iot-on-main-network" not in rules


def _ctx(store: Store, config: Config) -> RuleContext:
    sid = store.begin_snapshot("infra", "t")
    return RuleContext(
        store=store, config=config, snapshot_id=sid, previous_snapshot_id=None, is_baseline=False
    )


async def test_iot_on_main_network_rule(store: Store, config: Config) -> None:
    config.unifi = _cfg()
    ids = _seed(store)
    store.set_device_kind(ids["nas"], "camera")  # pretend the "nas" is a camera
    await collect_unifi(config, store, store.begin_snapshot("infra", "t"), Controller().client())
    found = IotOnMainNetworkRule().evaluate(_ctx(store, config))
    assert len(found) == 1 and found[0].device_id == ids["nas"]
    assert found[0].evidence["other_networks"] == ["IoT"] and found[0].evidence["iot_ssids"] == [
        "Things"
    ]
    assert "is on the main network Default while 1 other networks exist" in found[0].title
    # Flat network: drop the IoT network and SSID, and the rule has nothing to say.
    sid = store.begin_snapshot("infra", "t")
    default_only = {r.key: r.data for r in store.infra("unifi-network") if r.data["default"]}
    store.replace_infra("unifi-network", default_only, sid)
    store.replace_infra("unifi-ssid", {}, sid)
    assert IotOnMainNetworkRule().evaluate(_ctx(store, config)) == []
    # No separate network, but an IoT-optimised SSID exists: that counts as somewhere to go.
    store.replace_infra(
        "unifi-ssid", {"s": {"name": "Things", "type": "IOT_OPTIMIZED", "enabled": True}}, sid
    )
    assert len(IotOnMainNetworkRule().evaluate(_ctx(store, config))) == 1


def test_offline_title_names_the_model_once(store: Store, config: Config) -> None:
    """A switch nobody renamed carries its model as its name: "UniFi USW Pro Max 24 USW Pro
    Max 24 is offline" said it twice."""
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra(
        "unifi-device",
        {
            "a8:bb:cc:00:00:24": {"name": "USW Pro Max 24", "model": "USW Pro Max 24"},
            "a8:bb:cc:00:00:25": {"name": None, "model": "USW Flex Mini"},
            "a8:bb:cc:00:00:26": {"name": "stue", "model": "AC Pro"},
        },
        sid,
    )
    rows = {r.key: {**r.data, "state": "OFFLINE"} for r in store.infra("unifi-device")}
    store.replace_infra("unifi-device", rows, sid)
    titles = sorted(f.title for f in UnifiDeviceOfflineRule().evaluate(_ctx(store, config)))
    assert titles == [
        "UniFi USW Flex Mini is offline",
        "UniFi USW Pro Max 24 is offline",
        "UniFi stue (AC Pro) is offline",
    ]


async def test_flat_network_rule_groups_by_controller_network(store: Store, config: Config) -> None:
    config.unifi = _cfg()
    ids = _seed(store)
    store.set_device_kind(ids["nas"], "camera")
    store.set_device_kind(ids["ap"], "server")  # same /24 and same UniFi network
    await collect_unifi(config, store, store.begin_snapshot("infra", "t"), Controller().client())
    found = FlatNetworkRule().evaluate(_ctx(store, config))
    assert len(found) == 1 and found[0].title.endswith("share Default (VLAN 1)")
    assert found[0].evidence["subnet"] == "Default (VLAN 1)"


def test_unifi_only_rule_respects_merged_aliases(store: Store, config: Config) -> None:
    ids = _seed(store)
    other_sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(
        other_sid, [HostObservation(ip="192.168.1.77", mac="a8:bb:cc:00:00:77", source="t")]
    )
    store.finish_snapshot(other_sid, 1)
    store.merge_devices(ids["nas"], rec.new_device_ids[0])  # the visitor's phone is the NAS owner's
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra(
        "unifi-client", {"a8:bb:cc:00:00:77": {"name": "phone", "ip": "192.168.1.77"}}, sid
    )
    assert UnifiOnlyClientRule().evaluate(_ctx(store, config)) == []
    assert UnifiDeviceOfflineRule().evaluate(_ctx(store, config)) == []


def test_firmware_rule_title_without_latest(store: Store, config: Config) -> None:
    ids = _seed(store)
    from lanwatch.models import iso, now_utc

    store.merge_device_attrs(
        ids["gw"],
        {
            "firmware": {
                "product": "UniFi UX7",
                "version": "4.3.6",
                "latest": None,
                "update": True,
                "source": "unifi",
                "checked": iso(now_utc()),
            }
        },
    )
    found = FirmwareOutdatedRule().evaluate(_ctx(store, config))
    assert len(found) == 1 and found[0].title.endswith("has an update available")


async def test_llm_facts_take_only_stable_unifi_fields(store: Store, config: Config) -> None:
    config.unifi = _cfg()
    ids = _seed(store)
    await collect_unifi(config, store, store.begin_snapshot("infra", "t"), Controller().client())
    nas = store.device(ids["nas"])
    assert nas is not None
    facts = device_facts(nas, [])
    assert facts["unifi"] == {"name": "nas", "wired": True, "guest": False, "network": "Default"}


# -- web and CLI ---------------------------------------------------------------------


async def test_pages_show_controller_devices_and_topology(config: Config) -> None:
    config.unifi = _cfg()
    with Store(config.store_path) as store:
        ids = _seed(store)
        await collect_unifi(
            config, store, store.begin_snapshot("infra", "t"), Controller().client()
        )
    client = TestClient(create_app(config))
    infra = client.get("/infra").text
    assert "UniFi controller" in infra and "UniFi Network 10.1.84" in infra and "site Home" in infra
    assert "192.168.20.0/24" in infra and "IoT-optimised" in infra and "Garage switch" in infra
    assert "1 never seen by lanwatch" in infra and "update available" in infra
    device = client.get(f"/devices/{ids['nas']}").text
    assert "<dt>UniFi</dt>" in device and "wired" in device and "via Express" in device
    assert "network Default" in device
    gw = client.get(f"/devices/{ids['gw']}").text
    assert "<dt>UniFi device</dt>" in gw and "ports 1/2 up" in gw and "update available" in gw
    topo = client.get("/topology").text
    assert 'role="img"' in topo and "aria-labelledby" in topo
    assert "Visitor phone" in topo and "Garage switch" in topo and "offline" in topo
    assert f'href="/devices/{ids["nas"]}"' in topo and '<ol class="topo-list">' in topo
    assert 'aria-current="page"' in topo and ">Topology<" in topo


def test_topology_layout_and_overflow(store: Store) -> None:
    assert build_topology(store) is None
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra(
        "unifi-device",
        {
            "aa:00:00:00:00:01": {
                "id": "g",
                "name": "GW",
                "model": "UX7",
                "state": "ONLINE",
                "is_gateway": True,
                "is_access_point": True,
                "uplink": None,
                "ports": {"total": 0, "up": 0, "poe": 0},
                "radios": [],
                "clients": 0,
            },
            "aa:00:00:00:00:02": {
                "id": "a",
                "name": "AP",
                "model": "U7",
                "state": "OFFLINE",
                "is_gateway": False,
                "is_access_point": True,
                "uplink": {"id": "g"},
                "ports": {"total": 0, "up": 0, "poe": 0},
                "radios": [],
                "clients": 45,
            },
            "aa:00:00:00:00:03": {
                "id": "s",
                "name": "Orphan switch",
                "model": "USW",
                "state": "ONLINE",
                "is_gateway": False,
                "is_access_point": False,
                "uplink": {"id": "missing"},
                "ports": {"total": 0, "up": 0, "poe": 0},
                "radios": [],
                "clients": 0,
            },
        },
        sid,
    )
    store.replace_infra(
        "unifi-client",
        {
            f"bb:00:00:00:{i // 256:02x}:{i % 256:02x}": {
                "id": f"c{i}",
                "name": f"client {i:02d}",
                "type": "WIRELESS",
                "ip": f"10.0.{i // 256}.{i % 256}",
                "guest": False,
                "uplink_id": "a",
                "network_id": "n1",
                "network_name": "Default",
                "known": i % 2 == 0,
            }
            for i in range(45)
        },
        sid,
    )
    store.replace_infra(
        "unifi-network",
        {
            "n1": {"id": "n1", "name": "Default", "vlan": 1, "default": True},
            "n2": {"id": "n2", "name": "IoT", "vlan": 20, "default": False},
        },
        sid,
    )
    topo = build_topology(store)
    assert (
        topo is not None and topo["devices"] == 3 and topo["clients"] == 45 and topo["offline"] == 1
    )
    kinds = [n["kind"] for n in topo["nodes"]]
    assert kinds.count("gateway") == 1 and kinds.count("ap") == 1 and kinds.count("switch") == 1
    assert kinds.count("client") == MAX_CLIENTS_PER_DEVICE and kinds.count("more") == 1
    more = next(n for n in topo["nodes"] if n["kind"] == "more")
    assert more["label"] == "+5 more"
    # The orphan hangs off the gateway; every edge ends at a node to the right of its start.
    assert all(x2 > x1 for x1, _, x2, _ in topo["edges"])
    assert topo["unknown_clients"] == 22 and [n["name"] for n in topo["legend"]] == [
        "Default",
        "IoT",
    ]


def test_cli_unifi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from lanwatch.cli import app

    runner = CliRunner()
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "unifi"])
    assert r.exit_code == 1 and "enabled = false" in r.output

    cfg = tmp_path / "c.toml"
    cfg.write_text(
        '[unifi]\nenabled = true\nurl = "https://console.lan"\napi_key = "k"\n'
        "verify_tls = false\n[llm]\nenabled = false\n"
    )

    def fake_fetch(cfg: UnifiConfig, client: object = None) -> Any:
        return fetch_unifi(cfg, Controller().client())

    monkeypatch.setattr(pipeline, "fetch_unifi", fake_fetch)
    r = runner.invoke(app, ["--config", str(cfg), "--data-dir", str(tmp_path), "unifi"])
    assert r.exit_code == 0, r.output
    assert "UniFi Network 10.1.84, site Home" in r.output and "update available" in r.output
    # Device columns are as wide as their longest entry: a long model name ("USW-Lite-8-PoE")
    # no longer runs into the state column.
    rows = r.output.split("devices:\n", 1)[1].split("clients:", 1)[0].splitlines()
    assert len(rows) == 3
    states = {row.index(state) for row in rows for state in ("online", "offline") if state in row}
    assert len(states) == 1, rows
    assert "clients: 2 (1 wired, 1 wireless, 1 guest); 2 not seen by lanwatch" in r.output
    assert "Visitor phone" in r.output

    async def rejected(cfg: UnifiConfig, client: object = None) -> UnifiSnapshot:
        raise UnifiAuthError("/info: HTTP 401, the API key was not accepted")

    monkeypatch.setattr(pipeline, "fetch_unifi", rejected)
    r = runner.invoke(app, ["--config", str(cfg), "--data-dir", str(tmp_path), "unifi"])
    assert r.exit_code == 1 and "rejected the API key" in r.output
