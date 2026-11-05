from __future__ import annotations

import base64
from pathlib import Path

from fastapi.testclient import TestClient

from lanwatch.collectors.services import parse_nmap_xml_services
from lanwatch.config import Config, WebConfig
from lanwatch.models import HostObservation
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store
from lanwatch.web.app import create_app
from tests.conftest import fixture_text


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
