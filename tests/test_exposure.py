from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from unittest import mock

import httpx2
from fastapi.testclient import TestClient

from lanwatch import exposure
from lanwatch.config import Config, ExposureConfig
from lanwatch.models import Severity
from lanwatch.pipeline import run_exposure
from lanwatch.rules.base import RuleContext
from lanwatch.rules.infra import InternetExposedRule
from lanwatch.store import Store
from lanwatch.web.app import create_app

PUBLIC = "93.184.216.34"  # a real public address: the TEST-NET ranges are not "global"
ANSWER = {
    "ip": PUBLIC,
    "ports": [22, 443, 8443, 70000, "x"],
    "hostnames": ["home.example.net"],
    "cpes": ["cpe:/a:openbsd:openssh:9.6"],
    "vulns": [],
    "tags": ["self-signed"],
}


def _client(ip_text: str | None, db: Mapping[str, object] | int) -> httpx2.AsyncClient:
    seen: list[str] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        if request.url.host == "api.ipify.org":
            return httpx2.Response(200, text=ip_text or "")
        if request.url.host == "internetdb.shodan.io":
            return (
                httpx2.Response(db) if isinstance(db, int) else httpx2.Response(200, json=dict(db))
            )
        raise AssertionError(f"unexpected request {request.url}")

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(handle))
    client.seen = seen  # type: ignore[attr-defined]
    return client


def test_parse_internetdb_checks_every_item() -> None:
    e = exposure.parse_internetdb(PUBLIC, ANSWER)
    assert e.ports == [22, 443, 8443] and e.hostnames == ["home.example.net"]
    assert e.tags == ["self-signed"] and e.vulns == []
    assert exposure.parse_internetdb(PUBLIC, "garbage").ports == []


async def test_check_looks_up_ip_and_stores_infra(store: Store, config: Config) -> None:
    config.exposure = ExposureConfig(enabled=True)
    client = _client(PUBLIC + "\n", ANSWER)
    e = await exposure.check_exposure(config, store, client)
    assert e is not None and e.ip == PUBLIC and e.ip_source == "lookup"
    rows = store.infra("exposure")
    assert [r.key for r in rows] == [PUBLIC] and rows[0].data["ports"] == [22, 443, 8443]
    assert client.seen == [  # type: ignore[attr-defined]
        "https://api.ipify.org",
        f"https://internetdb.shodan.io/{PUBLIC}",
    ]


async def test_check_prefers_the_gateways_external_ip(store: Store, config: Config) -> None:
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra("upnp", {"192.168.1.1": {"is_igd": True, "external_ip": PUBLIC}}, sid)
    client = _client(None, 404)  # Shodan knows nothing: nothing answers from outside
    e = await exposure.check_exposure(config, store, client)
    assert e is not None and e.ip_source == "upnp" and e.ports == []
    assert client.seen == [f"https://internetdb.shodan.io/{PUBLIC}"]  # type: ignore[attr-defined]


async def test_private_external_ip_is_not_trusted(store: Store, config: Config) -> None:
    """Carrier-grade NAT: the gateway's "external" address is private; look it up instead."""
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra("upnp", {"192.168.1.1": {"is_igd": True, "external_ip": "100.64.0.9"}}, sid)
    client = _client("not an address", 404)
    assert await exposure.check_exposure(config, store, client) is None
    assert store.infra("exposure") == []


def test_rule_severity_follows_vulns(store: Store, config: Config) -> None:
    sid = store.begin_snapshot("exposure", "t")
    clean = exposure.parse_internetdb(PUBLIC, ANSWER).as_dict()
    store.replace_infra("exposure", {PUBLIC: clean}, sid)
    ctx = RuleContext(
        store=store, config=config, snapshot_id=sid, previous_snapshot_id=None, is_baseline=False
    )
    found = InternetExposedRule().evaluate(ctx)
    assert len(found) == 1 and found[0].severity is Severity.HIGH
    assert found[0].title == f"Visible from the internet: 3 ports on {PUBLIC} (22, 443, 8443)"

    bad = {**clean, "vulns": ["CVE-2024-6387"]}
    store.replace_infra("exposure", {PUBLIC: bad}, sid)
    found = InternetExposedRule().evaluate(ctx)
    assert found[0].severity is Severity.CRITICAL and found[0].id == found[0].id
    assert "1 known vulnerabilities" in found[0].title

    store.replace_infra("exposure", {PUBLIC: {**clean, "ports": []}}, sid)
    assert InternetExposedRule().evaluate(ctx) == []


async def test_run_exposure_raises_finding_and_page_shows_it(
    config: Config, tmp_path: Path
) -> None:
    config.exposure = ExposureConfig(enabled=True)
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("infra", "t")
        store.replace_infra("upnp", {"192.168.1.1": {"is_igd": True, "external_ip": PUBLIC}}, sid)
        with mock.patch("lanwatch.exposure.httpx2.AsyncClient", return_value=_client(None, ANSWER)):
            out = await run_exposure(config, store)
        assert out is not None and out.ports == [22, 443, 8443]
        # The UPnP gateway seeded above raises its own finding; the exposure one is new.
        assert "net.internet-exposed" in [f.rule_id for f in store.findings()]
    html = TestClient(create_app(config)).get("/infra").text
    assert "Seen from the internet" in html and "22, 443, 8443" in html
    assert "from the gateway" in html
