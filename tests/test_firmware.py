from __future__ import annotations

import struct
from typing import Any

import httpx2
import pytest

from lanwatch import dnswire
from lanwatch.collectors.services import PortObservation, PortSet
from lanwatch.config import Config
from lanwatch.firmware import (
    ESPHOME_SERVICE,
    HA_SERVICE,
    Firmware,
    LatestVersions,
    check_firmware,
    is_older,
    parse_txt,
    probe_shelly,
    version_key,
)
from lanwatch.models import FindingStatus, HostObservation, Kind
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("2026.11.0", (2026, 11, 0)),
        ("2026.11.0b1", (2026, 11, 0)),  # an ESPHome beta
        ("v16.0.0", (16, 0, 0)),  # GitHub tags
        ("v12.4", (12, 4)),
        ("14.3.0(tasmota)", (14, 3, 0)),
        ("20230913-113421/v1.14.0-gcb84623", (1, 14, 0)),  # Shelly Gen1
        ("1.40.2.8395-c67dce28e", (1, 40, 2, 8395)),
        ("master", ()),
        ("", ()),
    ],
)
def test_version_key(text: str, key: tuple[int, ...]) -> None:
    assert version_key(text) == key


def test_is_older() -> None:
    assert is_older("2026.9.3", "2026.10.2") is True  # not a string comparison
    assert is_older("2026.10.2", "2026.10.2") is False
    assert is_older("2026.11.0b1", "2026.10.2") is False  # running a beta ahead of stable
    assert is_older("v6.4", "v6.5") is True
    assert is_older("custom-build", "v6.5") is None and is_older("1.0", None) is None


def test_txt_pairs_from_an_mdns_answer() -> None:
    owner = dnswire.encode_name("kitchen._esphomelib._tcp.local")
    txt = b"".join(bytes([len(x)]) + x for x in (b"version=2026.9.1", b"board=esp32dev", b"flag"))
    message = (
        struct.pack("!HHHHHH", 0, 0x8400, 0, 0, 0, 1)
        + owner
        + struct.pack("!HHIH", dnswire.TYPE_TXT, 0x8001, 120, len(txt))
        + txt
    )
    assert parse_txt(message) == {"version": "2026.9.1", "board": "esp32dev"}
    assert parse_txt(b"not dns") == {}


OUTDATED = "device.firmware-outdated"

# -- fake devices and vendors -----------------------------------------------------------------

SHELLY_GEN2 = {"mac": "F008D1D8B8B8", "model": "SNSW-001X16EU", "gen": 2, "ver": "1.4.4"}
SHELLY_GEN1 = {
    "type": "SHSW-1",
    "mac": "5ECF7F1632E8",
    "auth": False,
    "fw": "20230913-113421/v1.14.0-g",
}


def lan(devices: dict[str, dict[str, Any]], seen: list[str]) -> httpx2.AsyncClient:
    """An HTTP client whose "network" is {ip: {path: json}}; everything else is a 404."""

    def handle(request: httpx2.Request) -> httpx2.Response:
        # Recorded with the query string, so a test can tell /ota from /ota?update=1.
        seen.append(f"{request.url.host}{request.url.raw_path.decode()}")
        assert request.method == "GET"
        body = devices.get(request.url.host, {}).get(request.url.path)
        return httpx2.Response(404) if body is None else httpx2.Response(200, json=body)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handle))


def vendors(seen: list[str]) -> httpx2.AsyncClient:
    answers: dict[str, Any] = {
        "version.home-assistant.io/stable.json": {"homeassistant": {"default": "2026.11.0"}},
        "api.github.com/repos/esphome/esphome/releases/latest": {"tag_name": "2026.10.2"},
        "api.github.com/repos/arendst/Tasmota/releases/latest": {"tag_name": "v16.0.0"},
        "api.shelly.cloud/files/firmware": {
            "isok": True,
            "data": {"SHSW-1": {"version": "20240101-000000/v1.14.1-gabc"}},
        },
    }

    def handle(request: httpx2.Request) -> httpx2.Response:
        key = f"{request.url.host}{request.url.path}"
        seen.append(key)
        assert request.headers["user-agent"].startswith("lanwatch/")  # GitHub insists
        return httpx2.Response(200, json=answers[key]) if key in answers else httpx2.Response(404)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handle))


def network(store: Store, hosts: dict[str, tuple[str, list[int]]]) -> dict[str, int]:
    """Record devices {ip: (mac, open tcp ports)}; returns ip -> device id."""
    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(
        sid,
        [
            HostObservation(ip=ip, mac=mac, hostname=f"h{i}", source="t")
            for i, (ip, (mac, _)) in enumerate(hosts.items())
        ],
    )
    store.finish_snapshot(sid, len(hosts))
    inv = store.begin_snapshot("inventory", "t")
    ids = dict(zip(hosts, rec.seen_device_ids, strict=True))
    for ip, (_, ports) in hosts.items():
        observed = [PortObservation(port=p, proto="tcp", state="open") for p in ports]
        store.record_services(inv, ids[ip], observed, {"tcp": PortSet.from_spec("1-65535")})
    store.finish_snapshot(inv, len(hosts))
    return ids


async def test_shelly_reports_its_own_update_and_is_never_told_to_update() -> None:
    seen: list[str] = []
    client = lan(
        {
            "10.0.0.5": {
                "/shelly": SHELLY_GEN2,
                "/rpc/Shelly.CheckForUpdate": {"stable": {"version": "1.5.0"}},
            },
            "10.0.0.6": {"/shelly": SHELLY_GEN2, "/rpc/Shelly.CheckForUpdate": {}},
            "10.0.0.7": {"/shelly": {**SHELLY_GEN2, "auth_en": True}},
            "10.0.0.8": {
                "/shelly": SHELLY_GEN1,
                "/ota": {"has_update": True, "new_version": "20240101/v1.14.1"},
            },
            "10.0.0.9": {"/shelly": {"name": "some other web server"}},
        },
        seen,
    )
    behind = await probe_shelly(client, "10.0.0.5")
    assert behind == Firmware("Shelly", "1.4.4", "1.5.0", True, "http", "SNSW-001X16EU")
    current = await probe_shelly(client, "10.0.0.6")
    assert current is not None and current.update is False
    locked = await probe_shelly(client, "10.0.0.7")  # password set: version yes, check no
    assert locked is not None and locked.version == "1.4.4" and locked.update is None
    assert "10.0.0.7/rpc/Shelly.CheckForUpdate" not in seen
    gen1 = await probe_shelly(client, "10.0.0.8")
    assert gen1 is not None and gen1.update is True and gen1.model == "SHSW-1"
    assert await probe_shelly(client, "10.0.0.9") is None
    # /ota is only ever fetched bare: with a query string it starts a firmware update.
    assert "10.0.0.8/ota" in seen and not any("?" in url for url in seen)


async def test_latest_versions_are_fetched_once_and_only_when_online() -> None:
    seen: list[str] = []
    latest = LatestVersions(vendors(seen))
    a, b = Firmware("ESPHome", "2026.9.1"), Firmware("ESPHome", "2026.10.2")
    await latest.fill(a)
    await latest.fill(b)
    assert (a.latest, a.update) == ("2026.10.2", True) and b.update is False
    assert seen == ["api.github.com/repos/esphome/esphome/releases/latest"]  # one request

    gen1 = Firmware("Shelly", "20230913-113421/v1.14.0-g", model="SHSW-1")
    await latest.fill(gen1)
    assert gen1.update is True and gen1.latest == "20240101-000000/v1.14.1-gabc"

    decided = Firmware("Shelly", "1.4.4", "1.5.0", True)  # the device already said
    await latest.fill(decided)
    assert decided.latest == "1.5.0"

    offline = Firmware("Home Assistant", "2026.10.1")
    await LatestVersions(None).fill(offline)
    assert offline.update is None and offline.latest is None


async def test_check_finds_stores_and_flags(store: Store, config: Config) -> None:
    ids = network(
        store,
        {
            "10.0.0.2": ("b8:27:eb:00:00:02", [8123]),  # Home Assistant, via mDNS
            "10.0.0.3": ("24:6f:28:00:00:03", []),  # an ESPHome sensor, via mDNS
            "10.0.0.5": ("f0:08:d1:00:00:05", [80]),  # a Shelly
            "10.0.0.6": ("5c:cf:7f:00:00:06", [80]),  # a Tasmota plug
            "10.0.0.9": ("00:11:32:00:00:09", [80, 443]),  # a NAS: none of the known products
            "10.0.0.10": ("3c:22:fb:00:00:10", [22]),  # nothing to ask
        },
    )
    local_seen: list[str] = []
    online_seen: list[str] = []
    devices: dict[str, dict[str, Any]] = {
        "10.0.0.5": {"/shelly": SHELLY_GEN2, "/rpc/Shelly.CheckForUpdate": {}},
        "10.0.0.6": {"/cm": {"StatusFWR": {"Version": "14.3.0(tasmota)"}}},
    }

    async def fake_mdns(service: str, bind_ips: list[str]) -> dict[str, dict[str, str]]:
        return {
            HA_SERVICE: {"10.0.0.2": {"version": "2026.10.1", "location_name": "Home"}},
            ESPHOME_SERVICE: {
                "10.0.0.3": {"version": "2026.10.2", "board": "esp32dev"},
                "10.0.0.99": {"version": "2026.1.0"},  # answers, but is no known device
            },
        }[service]

    results = await check_firmware(
        store,
        ["10.0.0.1"],
        online=True,
        local_client=lan(devices, local_seen),
        online_client=vendors(online_seen),
        mdns=fake_mdns,
    )
    by_ip = {d.ip: fw for d, fw in results}
    assert set(by_ip) == {"10.0.0.2", "10.0.0.3", "10.0.0.5", "10.0.0.6"}
    assert by_ip["10.0.0.2"] == Firmware("Home Assistant", "2026.10.1", "2026.11.0", True, "mdns")
    assert by_ip["10.0.0.3"].update is False and by_ip["10.0.0.3"].model == "esp32dev"
    assert by_ip["10.0.0.5"].update is False  # the Shelly said so itself
    assert by_ip["10.0.0.6"] == Firmware("Tasmota", "14.3.0(tasmota)", "v16.0.0", True, "http")

    # Only devices with the port open were asked, and the one with nothing open not at all.
    assert not any(url.startswith("10.0.0.10") or url.startswith("10.0.0.2/") for url in local_seen)
    assert "10.0.0.9/shelly" in local_seen
    # One vendor request per product that was found; nothing for Jellyfin or Shelly.
    assert sorted(online_seen) == [
        "api.github.com/repos/arendst/Tasmota/releases/latest",
        "api.github.com/repos/esphome/esphome/releases/latest",
        "version.home-assistant.io/stable.json",
    ]

    stored = store.device(ids["10.0.0.2"])
    assert stored is not None and stored.attrs["firmware"]["latest"] == "2026.11.0"
    assert stored.attrs["firmware"]["checked"]

    sid = store.begin_snapshot("firmware", "t")
    store.finish_snapshot(sid, 4)
    ctx = RuleContext(
        store=store, config=config, snapshot_id=sid, previous_snapshot_id=None, is_baseline=False
    )
    Engine(config).run(ctx)
    found = [
        f for f in store.findings(FindingStatus.OPEN) if f.rule_id == "device.firmware-outdated"
    ]
    assert sorted(f.title for f in found) == [
        "h0: Home Assistant 2026.10.1 is behind 2026.11.0",
        "h3: Tasmota 14.3.0(tasmota) is behind v16.0.0",
    ]
    assert all(f.kind is Kind.IMPROVEMENT for f in found)

    # Updated since: the next check clears the finding.
    devices["10.0.0.6"] = {"/cm": {"StatusFWR": {"Version": "16.0.0(tasmota)"}}}
    await check_firmware(
        store,
        ["10.0.0.1"],
        online=True,
        local_client=lan(devices, local_seen),
        online_client=vendors(online_seen),
        mdns=fake_mdns,
    )
    Engine(config).run(ctx)
    found = [
        f for f in store.findings(FindingStatus.OPEN) if f.rule_id == "device.firmware-outdated"
    ]
    assert [f.title for f in found] == ["h0: Home Assistant 2026.10.1 is behind 2026.11.0"]


async def test_without_online_lookups_nothing_leaves_the_network(store: Store) -> None:
    network(store, {"10.0.0.6": ("5c:cf:7f:00:00:06", [80])})
    local_seen: list[str] = []
    devices: dict[str, dict[str, Any]] = {
        "10.0.0.6": {"/cm": {"StatusFWR": {"Version": "14.3.0(tasmota)"}}}
    }

    async def no_mdns(service: str, bind_ips: list[str]) -> dict[str, dict[str, str]]:
        return {}

    results = await check_firmware(
        store, [], online=False, local_client=lan(devices, local_seen), mdns=no_mdns
    )
    ((_, fw),) = results
    assert fw.version == "14.3.0(tasmota)" and fw.latest is None and fw.update is None
    assert all(url.startswith("10.0.0.6") for url in local_seen)
