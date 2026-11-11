from __future__ import annotations

import base64
from pathlib import Path

from fastapi.testclient import TestClient

from lanwatch.collectors.services import parse_nmap_xml_services
from lanwatch.config import Config, WebConfig
from lanwatch.models import HostObservation
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.scheduler import Job, Scheduler
from lanwatch.store import Store
from lanwatch.web.app import create_app
from tests.conftest import fixture_text, snmp_devices


def _seed(config: Config) -> None:
    with Store(config.store_path) as store:
        res = parse_nmap_xml_services(fixture_text("nmap-services.xml"))
        sid = store.begin_snapshot("discovery", "t")
        rec = store.record_hosts(
            sid,
            [
                HostObservation(ip=h.ip, mac=h.mac, hostname="gw" if h.mac else None, source="t")
                for h in res.hosts
            ],
        )
        store.finish_snapshot(sid, len(rec.seen_device_ids))
        inv = store.begin_snapshot("inventory", "t")
        diffs = {}
        for h, did in zip(res.hosts, rec.new_device_ids, strict=True):
            diffs[did] = store.record_services(inv, did, h.ports, res.scanned)
        store.finish_snapshot(inv, len(diffs))
        ctx = RuleContext(
            store=store,
            config=config,
            snapshot_id=inv,
            previous_snapshot_id=None,
            is_baseline=False,
            service_diffs=diffs,
        )
        Engine(config).run(ctx)


def test_pages_and_actions(config: Config, tmp_path: Path) -> None:
    _seed(config)
    client = TestClient(create_app(config))

    r = client.get("/")
    assert r.status_code == 200 and "Dashboard" in r.text and "Open findings" in r.text
    assert "Cleartext remote access" in r.text

    r = client.get("/devices")
    assert r.status_code == 200 and "192.168.1.40" in r.text and "22/tcp ssh" in r.text

    r = client.get("/devices/1")
    assert r.status_code == 200 and "OpenSSH" in r.text and "ssh2-enum-algos" in r.text
    assert client.get("/devices/999").status_code == 404

    r = client.post("/devices/1/name", data={"name": "Router"}, follow_redirects=False)
    assert r.status_code == 303
    assert "Router" in client.get("/devices/1").text
    assert "Router" in config.overview_path.read_text()  # overview regenerated

    findings = client.get("/api/findings").json()
    assert findings and findings[0]["severity"] == "critical"
    fid = findings[-1]["id"]
    r = client.post(f"/findings/{fid}/ack", data={"back": "/findings"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/findings"
    assert fid not in {f["id"] for f in client.get("/api/findings").json()}
    assert fid in {f["id"] for f in client.get("/api/findings?status=acked").json()}
    assert client.post(f"/findings/{fid}/ack", data={"back": "http://evil"}).status_code == 404

    r = client.get("/findings?status=all")
    assert r.status_code == 200 and "acked" in r.text

    r = client.get("/overview")
    assert r.status_code == 200 and "# Network overview" in r.text
    assert client.get("/api/overview.md").text.startswith("# Network overview")
    devices = client.get("/api/devices").json()
    assert devices[0]["services"] and devices[0]["name"] == "Router"
    assert client.get("/api/health").json()["status"] == "ok"


def test_basic_auth_when_password_set(config: Config) -> None:
    config.web = WebConfig(host="0.0.0.0", password="secret")
    client = TestClient(create_app(config))
    assert client.get("/").status_code == 401
    assert client.get("/api/health").status_code == 200  # health is unauthenticated
    ok = base64.b64encode(b"lanwatch:secret").decode()
    assert client.get("/", headers={"Authorization": f"Basic {ok}"}).status_code == 200
    bad = base64.b64encode(b"lanwatch:wrong").decode()
    assert client.get("/", headers={"Authorization": f"Basic {bad}"}).status_code == 401


def test_config_rejects_open_bind_without_password(tmp_path: Path) -> None:
    import pytest

    from lanwatch.config import ConfigError, load_config

    with pytest.raises(ConfigError, match=r"web\.password"):
        load_config(None, {"web": {"host": "0.0.0.0"}}, environ={})
    cfg = load_config(None, {"web": {"host": "0.0.0.0", "password": "x"}}, environ={}).config
    assert cfg.web.port == 8321


async def _noop() -> None:
    return None


def test_device_page_firmware_line_says_up_to_date_or_behind(config: Config) -> None:
    """attrs.firmware is a dict, and `fw.update` in a template is the dict's update method
    (always true): every device read as "behind". The flag must be read as a key."""
    _seed(config)
    with Store(config.store_path) as store:
        current, old = store.devices()[:2]
        store.merge_device_attrs(
            current.id,
            {
                "firmware": {
                    "product": "Tasmota",
                    "version": "16.0.0",
                    "latest": "16.0.0",
                    "update": False,
                }
            },
        )
        store.merge_device_attrs(
            old.id,
            {
                "firmware": {
                    "product": "Tasmota",
                    "version": "14.3.0",
                    "latest": "16.0.0",
                    "update": True,
                }
            },
        )
    client = TestClient(create_app(config))
    page = client.get(f"/devices/{current.id}").text
    assert "up to date" in page and "behind" not in page
    assert "behind" in client.get(f"/devices/{old.id}").text


def test_status_page_without_a_scheduler_is_read_only(config: Config) -> None:
    client = TestClient(create_app(config))
    r = client.get("/status")
    assert r.status_code == 200 and "only serves the web UI" in r.text
    assert "Run now" not in r.text and "Scan privileges" in r.text
    assert "disabled in config" in r.text  # the LLM tile; the fixture turns the LLM off
    assert client.get("/api/status").json() == {"scheduler": False, "running": None}
    assert client.post("/scan/discovery").status_code == 409
    assert 'id="scan-chip"' not in client.get("/").text


def test_status_page_shows_jobs_and_run_now_queues_one(config: Config) -> None:
    import time

    jobs = [Job("discovery", 300, _noop), Job("inventory", 3600, _noop)]
    for j in jobs:
        j.next_due = time.monotonic() + 1000
    jobs[1].running_since = time.time() - 125  # as if an inventory scan were in progress
    jobs[0].last_error = "CommandError: helper socket /run/lanwatch/helper.sock: refused"
    jobs[0].failures = 2
    client = TestClient(create_app(config, Scheduler(jobs)))

    r = client.get("/status")
    assert r.status_code == 200 and "Run now" in r.text
    assert "every 5 min" in r.text and "every 60 min" in r.text
    assert "running" in r.text and "for 2 min" in r.text
    assert "helper socket" in r.text and "2 in a row" in r.text
    assert client.get("/api/status").json()["running"]["job"] == "inventory"
    assert "Scanning: inventory" in client.get("/").text  # the header indicator
    # Lanes run side by side: the indicator names every job in progress, longest first.
    jobs[0].running_since = time.time() - 5
    running = client.get("/api/status").json()["running"]
    assert running["job"] == "inventory, discovery" and running["seconds"] >= 125
    jobs[0].running_since = None

    r = client.post("/scan/discovery", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/status"
    assert jobs[0].next_due <= time.monotonic()  # due now
    assert client.post("/scan/nonsense").status_code == 404


def test_cross_site_posts_are_refused(config: Config) -> None:
    import time

    job = Job("discovery", 300, _noop)
    job.next_due = time.monotonic() + 1000
    client = TestClient(create_app(config, Scheduler([job])))
    # What a browser sends when another site's page submits a form to lanwatch.
    r = client.post("/scan/discovery", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    r = client.post("/scan/discovery", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    assert job.next_due > time.monotonic()  # nothing was triggered
    # The UI's own forms, and clients that are not browsers, still work.
    ok = {"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"}
    assert client.post("/scan/discovery", headers=ok, follow_redirects=False).status_code == 303


def test_device_edit_merge_and_forget(config: Config) -> None:
    _seed(config)
    client = TestClient(create_app(config))

    page = client.get("/devices/1").text
    assert "Merge into this device" in page and "Forget this device" in page
    assert ">private<" in page  # the fixture's aa:bb:cc... addresses are locally administered

    form = {"name": "Router", "kind": "Router", "description": "Gateway in the hall"}
    r = client.post("/devices/1/edit", data={**form, "watch": "true"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/devices/1"
    page = client.get("/devices/1").text
    assert "Gateway in the hall" in page and "set by you" in page and ">router<" in page
    assert ">watched<" in page and ">watched<" in client.get("/devices").text
    client.post("/devices/1/edit", data=form)  # checkbox unticked: no longer watched
    assert ">watched<" not in client.get("/devices/1").text
    assert client.post("/devices/999/edit", data=form).status_code == 404

    assert client.post("/devices/1/merge", data={"other": "1"}).status_code == 404
    r = client.post("/devices/1/merge", data={"other": "2"}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/devices/2").status_code == 404
    assert "also seen as" in client.get("/devices/1").text

    r = client.post("/devices/1/forget", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/devices"
    assert client.get("/devices/1").status_code == 404
    assert client.get("/api/devices").json() == []
    assert client.get("/").status_code == 200  # dashboard copes with unlinked events


def test_accept_with_reason_and_reopen(config: Config) -> None:
    _seed(config)
    client = TestClient(create_app(config))
    fid = client.get("/api/findings").json()[0]["id"]
    assert "Accept for good" in client.get("/findings").text

    form = {"back": "/findings?status=acked", "accept": "true", "note": "Intended: lab VNC"}
    r = client.post(f"/findings/{fid}/ack", data=form, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/findings?status=acked"
    page = client.get("/findings?status=acked").text
    assert "accepted" in page and "Intended: lab VNC" in page and "Reopen" in page
    api = {f["id"]: f for f in client.get("/api/findings?status=acked").json()}
    assert api[fid]["accepted"] is True and api[fid]["note"] == "Intended: lab VNC"

    r = client.post(f"/findings/{fid}/reopen", data={"back": "/findings"}, follow_redirects=False)
    assert r.status_code == 303
    assert fid in {f["id"] for f in client.get("/api/findings").json()}
    assert client.post(f"/findings/{fid}/reopen").status_code == 404  # already open


async def test_status_page_shows_decoy_ports(config: Config) -> None:
    import socket

    from lanwatch.config import DecoyConfig
    from lanwatch.decoy import Decoys

    with socket.socket() as probe:
        probe.bind(("", 0))
        free = int(probe.getsockname()[1])
    holder = socket.socket()
    holder.bind(("", 0))
    holder.listen()
    busy = int(holder.getsockname()[1])
    decoys = Decoys(DecoyConfig(ports=[free, busy]), lambda ip, port: None)
    await decoys.start()
    try:
        page = TestClient(create_app(config, None, decoys)).get("/status").text
        assert "Decoy ports" in page and f">{free}<" in page
        assert f">{busy}<" in page and "in use by another service" in page
    finally:
        await decoys.stop()
        holder.close()
    assert "only with" in TestClient(create_app(config)).get("/status").text


def test_router_on_status_infra_and_device_pages(config: Config) -> None:
    """SNMP off: the status tile says so and the infra page has no router section. On, with
    a read stored: the tile, the table with lease, static and disagreement notes, and the
    line on the device page."""

    from lanwatch.config import SnmpConfig

    _seed(config)
    client = TestClient(create_app(config))
    assert "no device under [snmp.devices] has router = true" in client.get("/status").text
    assert 'id="router"' not in client.get("/infra").text

    config.snmp = snmp_devices(gw={"router": True})
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("infra", "t")
        router_state = {
            "host": "192.168.1.1",
            "role": "router",
            "name": "",
            "last_ok": "2026-11-10T09:00:00+00:00",
            "last_error": "",
            "fails": 0,
            "system": {
                "name": "gw-test",
                "vendor": "Juniper",
                "object_id": "1.3.6.1.4.1.2636.1.1.1.2.133",
                "descr": "Juniper Networks, Inc. srx300 internet router",
                "uptime_s": 3 * 86400,
            },
        }
        store.replace_infra("snmp-target", {"192.168.1.1": router_state}, sid)
        known = store.devices()[0]
        assert known.mac and known.ip
        store.replace_infra(
            "router-arp",
            {
                known.ip: {"ip": known.ip, "mac": known.mac, "interface": "irb.0", "static": False},
                "192.168.1.77": {
                    "ip": "192.168.1.77",
                    "mac": "aa:bb:cc:00:00:77",
                    "interface": "irb.0",
                    "static": False,
                },
                # The ISP's router on the WAN side (a public address; Python counts the
                # documentation ranges as private): never expected to hold a lease.
                "80.0.0.1": {
                    "ip": "80.0.0.1",
                    "mac": "ee:ee:ee:00:00:01",
                    "interface": "ge-0/0/0.0",
                    "static": False,
                },
            },
            sid,
        )
        store.replace_infra(
            "router-dhcp",
            {known.ip: {"ip": known.ip, "mac": known.mac, "since": "2026-11-01 08:00:00 CET"}},
            sid,
        )
        store.replace_infra(
            "router-arp-mismatch",
            {
                "192.168.1.77": {
                    "ip": "192.168.1.77",
                    "router_mac": "aa:bb:cc:00:00:77",
                    "lanwatch_macs": ["aa:bb:cc:00:00:99"],
                    "rounds": 2,
                }
            },
            sid,
        )
        store.merge_device_attrs(
            known.id,
            {
                "router": {
                    "arp_interface": "irb.0",
                    "dhcp_lease": True,
                    "dhcp_lease_since": "2026-11-01 08:00:00 CET",
                }
            },
        )
    client = TestClient(create_app(config))
    status = client.get("/status").text
    assert "gw-test" in status and "Juniper" in status and "3 d" in status
    infra = client.get("/infra").text
    assert 'id="router"' in infra and "Router: gw-test" in infra
    assert "since 2026-11-01 08:00:00 CET" in infra
    assert "2 with a MAC lanwatch has no device for" in infra
    assert "1 where the router and lanwatch disagree" in infra
    assert "lanwatch saw aa:bb:cc:00:00:99" in infra
    wan = infra[infra.index("80.0.0.1") :]
    wan = wan[: wan.index("</tr>")]
    assert "none" not in wan  # no lease is expected outside the LAN
    lan = infra[infra.index("192.168.1.77") :]
    assert "none" in lan[: lan.index("</tr>")]  # a LAN address without a lease says so
    assert infra.index("192.168.1.77") < infra.index("80.0.0.1")  # LAN first
    device = client.get(f"/devices/{known.id}").text
    assert "DHCP lease since 2026-11-01 08:00:00 CET" in device and "irb.0" in device
    # Switched off, the facts stay stored but are not shown: they would only go stale.
    config.snmp = SnmpConfig()
    off = TestClient(create_app(config))
    assert "DHCP lease since" not in off.get(f"/devices/{known.id}").text
    assert 'id="router"' not in off.get("/infra").text
    config.snmp = snmp_devices(gw={"router": True})

    with Store(config.store_path) as store:
        failed = router_state | {"last_error": "Timeout: No Response (no answer: ...)"}
        store.replace_infra("snmp-target", {"192.168.1.1": failed}, sid)
    status = TestClient(create_app(config)).get("/status").text
    assert "failed" in status and "Timeout: No Response" in status and "last good read" in status


def test_snmp_devices_on_infra_status_and_device_pages(config: Config) -> None:
    """Devices under [snmp.devices] get a row in the infra table (read or failed), a count
    on the status tile even without a router, and a line on their device page."""
    _seed(config)
    config.snmp = snmp_devices(ups={"host": "192.0.2.9"}, flaky={"host": "192.0.2.66"})
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(
            sid, [HostObservation(ip="192.0.2.9", mac="aa:bb:cc:00:00:09", source="t")]
        )
        store.finish_snapshot(sid, 1)
        ups = store.device_by_ip("192.0.2.9")
        assert ups is not None
        store.merge_device_attrs(
            ups.id,
            {"snmp": {"name": "apcECDAE3", "vendor": "APC", "descr": "APC Web/SNMP Card"}},
        )
        store.replace_infra(
            "snmp-target",
            {
                "192.0.2.9": {
                    "host": "192.0.2.9",
                    "role": "device",
                    "name": "ups",
                    "system": {"vendor": "APC", "descr": "APC Web/SNMP Card", "uptime_s": 90},
                    "last_ok": "2026-11-10T09:00:00+00:00",
                    "last_error": "",
                    "fails": 0,
                },
                "192.0.2.66": {
                    "host": "192.0.2.66",
                    "role": "device",
                    "name": "flaky",
                    "system": None,
                    "last_ok": None,
                    "last_error": "Timeout: No Response from 192.0.2.66",
                    "fails": 3,
                },
            },
            sid,
        )
    client = TestClient(create_app(config))
    infra = client.get("/infra").text
    assert 'id="snmp"' in infra and f'href="/devices/{ups.id}">ups</a>' in infra
    assert "APC Web/SNMP Card" in infra and "failed 3 times" in infra
    assert 'id="router"' not in infra  # no device is the router
    status = client.get("/status").text
    assert "2 more over SNMPv3" in status and "1 not read" in status
    device = client.get(f"/devices/{ups.id}").text
    assert "<dt>SNMP</dt>" in device and "apcECDAE3" in device
