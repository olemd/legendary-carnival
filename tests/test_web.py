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


async def _noop() -> None:
    return None


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
