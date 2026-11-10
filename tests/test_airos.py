"""airOS radios: parsing, the login and its one-attempt rule, certificate pinning, and the
round that stores the result. No test talks to a real radio."""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import ssl
import subprocess
from pathlib import Path
from typing import Any

import httpx2
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from lanwatch import pipeline
from lanwatch.cli import app
from lanwatch.collectors import airos
from lanwatch.config import AirosConfig, Config
from lanwatch.models import HostObservation
from lanwatch.store import Store
from tests.conftest import FIXTURES

HOST = "192.168.1.5"
PASSWORD = "read-only-Secret1"


def airos_config(**kw: object) -> AirosConfig:
    base: dict[str, object] = {
        "enabled": True,
        "hosts": [HOST],
        "username": "analyst",
        "password": PASSWORD,
    }
    return AirosConfig.model_validate(base | kw)


def _status() -> Any:
    return json.loads((FIXTURES / "airos-status.json").read_text())


def _stations() -> Any:
    return json.loads((FIXTURES / "airos-sta.json").read_text())


class FakeRadio:
    """airOS 6 as seen over HTTP: a login page, the login form, two JSON pages, logout."""

    def __init__(self, accept: bool = True) -> None:
        self.accept = accept
        self.logins: list[dict[str, str]] = []
        self.paths: list[str] = []
        self.logged_in = False

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(f"{request.method} {request.url.path}")
        if request.url.path == "/login.cgi" and request.method == "GET":
            return httpx2.Response(200, text="<html>login</html>")
        if request.url.path == "/login.cgi":
            body = request.content.decode()
            self.logins.append({"body": body})
            if self.accept and PASSWORD in body:
                self.logged_in = True
                return httpx2.Response(302, headers={"Location": "/status.cgi"})
            return httpx2.Response(200, text="<html>Invalid credentials.</html>")
        if not self.logged_in:
            return httpx2.Response(302, headers={"Location": "/login.cgi?uri=/status.cgi"})
        if request.url.path == "/status.cgi":
            return httpx2.Response(200, json=_status())
        if request.url.path == "/sta.cgi":
            # airOS 6 sends this one as JSON under text/html.
            return httpx2.Response(
                200, text=json.dumps(_stations()), headers={"Content-Type": "text/html"}
            )
        if request.url.path == "/logout.cgi":
            self.logged_in = False
            return httpx2.Response(302, headers={"Location": "/login.cgi"})
        return httpx2.Response(404)

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            base_url=f"https://{HOST}", transport=httpx2.MockTransport(self.handle)
        )


def test_parse_status_and_stations() -> None:
    radio = airos.parse_status(HOST, _status(), _stations())
    assert (radio.hostname, radio.model, radio.firmware) == (
        "radio-a",
        "NanoStation loco M2",
        "v6.3.11",
    )
    assert (radio.mode, radio.netrole, radio.frequency_mhz, radio.channel_width_mhz) == (
        "ap",
        "bridge",
        2444,
        20,
    )
    assert radio.ccq == 72  # 718 tenths of a percent in status.cgi
    assert (radio.airmax_quality, radio.airmax_capacity) == (76, 44)
    assert radio.mac == "02:00:00:00:0a:01"  # the bridge, lower-cased
    eth = radio.ethernet
    assert eth is not None and (eth.mac, eth.speed, eth.full_duplex) == (
        "02:00:00:00:0e:01",
        100,
        True,
    )
    assert [i.name for i in radio.interfaces] == ["eth0", "wifi0", "ath0", "br0"]  # no lo
    (st,) = radio.stations
    assert (st.mac, st.ip, st.signal, st.noise, st.ccq) == (
        "02:00:00:00:0b:01",
        "192.168.1.6",
        -67,
        -96,
        70,
    )
    assert (st.remote_hostname, st.remote_signal, st.remote_noise) == ("radio-b", -64, -98)
    with pytest.raises(airos.AirosError, match="not an airOS radio"):
        airos.parse_status(HOST, {"hello": 1}, [])


def test_config_needs_hosts_and_credentials() -> None:
    assert not AirosConfig().enabled
    with pytest.raises(ValidationError, match="hosts"):
        airos_config(hosts=[])
    with pytest.raises(ValidationError, match="required"):
        airos_config(password="")
    with pytest.raises(ValidationError, match="twice"):
        airos_config(hosts=[HOST, HOST])


def test_config_show_redacts_the_password(tmp_path: Path) -> None:
    from lanwatch.config import dump_effective

    text = dump_effective(Config(data_dir=tmp_path, airos=airos_config()))
    assert PASSWORD not in text and 'password = "***"' in text


def test_credentials_tag_remembers_without_the_password() -> None:
    tag = airos.credentials_tag("analyst", PASSWORD)
    assert PASSWORD not in tag
    assert airos.same_credentials(tag, "analyst", PASSWORD)
    assert not airos.same_credentials(tag, "analyst", PASSWORD + "x")
    assert not airos.same_credentials(tag, "admin", PASSWORD)
    assert airos.credentials_tag("analyst", PASSWORD) != tag  # salted
    assert not airos.same_credentials("garbage", "analyst", PASSWORD)


async def test_read_radio_logs_in_reads_and_logs_out() -> None:
    radio = FakeRadio()
    async with radio.client() as client:
        status = await airos.read_radio(airos_config(), client, HOST)
    assert status.hostname == "radio-a" and len(status.stations) == 1
    assert radio.paths == [
        "GET /login.cgi",
        "POST /login.cgi",
        "GET /status.cgi",
        "GET /sta.cgi",
        "GET /logout.cgi",
    ]
    assert len(radio.logins) == 1


async def test_read_radio_treats_anything_but_success_as_rejected() -> None:
    radio = FakeRadio(accept=False)
    async with radio.client() as client:
        with pytest.raises(airos.AirosAuthError, match="Invalid credentials"):
            await airos.read_radio(airos_config(), client, HOST)
    # An unfamiliar answer to the login (here: a server error) is a rejection too.
    async with httpx2.AsyncClient(
        base_url=f"https://{HOST}",
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200 if r.method == "GET" else 500)
        ),
    ) as client:
        with pytest.raises(airos.AirosAuthError, match="HTTP 500"):
            await airos.read_radio(airos_config(), client, HOST)


async def test_read_radio_reports_a_refused_certificate() -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

    async with httpx2.AsyncClient(
        base_url=f"https://{HOST}", transport=httpx2.MockTransport(refuse)
    ) as client:
        with pytest.raises(airos.AirosPinError, match="--accept-cert"):
            await airos.read_radio(airos_config(), client, HOST)


def _self_signed(tmp_path: Path, name: str) -> tuple[Path, Path]:
    key, cert = tmp_path / f"{name}.key", tmp_path / f"{name}.pem"
    subprocess.run(
        [
            *("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2"),
            *("-subj", f"/CN={name}", "-keyout", str(key), "-out", str(cert)),
        ],
        check=True,
        capture_output=True,
    )
    return key, cert


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl command")
async def test_pinning_accepts_exactly_the_pinned_certificate(tmp_path: Path) -> None:
    """A local TLS server with certificate A: first contact reads A; a client pinned to A
    connects, a client pinned to another certificate B is refused before anything is sent."""
    key_a, cert_a = _self_signed(tmp_path, "radio-a")
    _, cert_b = _self_signed(tmp_path, "radio-b")
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(cert_a, key_a)
    received: list[bytes] = []

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(ssl.SSLError, ConnectionError):
            received.append(await reader.read(100))
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    async with server:
        pem = await airos.fetch_certificate("127.0.0.1", 5, port=port)
        assert pem.strip() == cert_a.read_text().strip()
        assert len(airos.fingerprint(pem).split(":")) == 32

        _, writer = await asyncio.open_connection("127.0.0.1", port, ssl=airos.pinned_context(pem))
        writer.write(b"hello")
        await writer.drain()
        writer.close()

        with pytest.raises(ssl.SSLCertVerificationError):
            await asyncio.open_connection(
                "127.0.0.1", port, ssl=airos.pinned_context(cert_b.read_text())
            )
        await asyncio.sleep(0.05)
    assert b"hello" in received  # the refused client never got to send anything


def _patch(monkeypatch: pytest.MonkeyPatch, radio: FakeRadio | None, pin: str = "PEM") -> list[str]:
    """Pinning and the HTTP client replaced: fetch_certificate returns `pin` and counts,
    make_client hands out the fake radio's client."""
    fetched: list[str] = []

    async def fetch(host: str, timeout: float, port: int = 443) -> str:
        fetched.append(host)
        return pin

    monkeypatch.setattr(pipeline, "fetch_certificate", fetch)
    monkeypatch.setattr(pipeline, "fingerprint", lambda pem: "AA:BB")
    if radio is not None:
        monkeypatch.setattr(pipeline, "make_client", lambda host, pem, timeout: radio.client())
    return fetched


async def test_collect_stores_the_radio_and_device_facts(
    monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    config.airos = airos_config()
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, [HostObservation(ip=HOST, mac="02:00:00:00:0a:01", source="t")])
    store.finish_snapshot(sid, 1)
    fetched = _patch(monkeypatch, FakeRadio())

    out = await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
    assert out.errors == {} and out.pinned == {HOST: "AA:BB"}
    assert store.meta_get(f"airos.pin.{HOST}") == "PEM"
    (row,) = store.infra("airos")
    assert row.key == HOST and row.data["hostname"] == "radio-a" and row.data["error"] is None
    d = store.device_by_key("02:00:00:00:0a:01")
    assert d is not None and d.id in out.enriched
    assert d.attrs["airos"]["peer"] == "radio-b" and d.attrs["airos"]["ethernet_mbps"] == 100
    assert d.attrs["firmware"]["product"] == "airOS" and d.attrs["firmware"]["update"] is None

    # The second round uses the pinned certificate; it does not fetch a new one.
    await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
    assert fetched == [HOST]


async def test_rejected_credentials_are_not_tried_again_until_they_change(
    monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    config.airos = airos_config()
    radio = FakeRadio(accept=False)
    _patch(monkeypatch, radio)
    for _ in range(3):  # three rounds would lock the account on airOS 6.3.14+
        out = await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
        assert "not" in out.errors[HOST]
    assert len(radio.logins) == 1
    (row,) = store.infra("airos")
    assert row.data["rejected"] is True  # what airos.login-rejected reports
    tag = store.meta_get(f"airos.rejected.{HOST}")
    assert tag and PASSWORD not in tag

    # A new password in the config is tried, once.
    config.airos = airos_config(password="another-Secret2")
    await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
    assert len(radio.logins) == 2
    # The right one clears the memory of the failure.
    radio.accept = True
    config.airos = airos_config()
    out = await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
    assert out.errors == {} and store.meta_get(f"airos.rejected.{HOST}") is None


async def test_a_changed_certificate_keeps_the_previous_state(
    monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    config.airos = airos_config()
    _patch(monkeypatch, FakeRadio())
    await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))

    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")

    monkeypatch.setattr(
        pipeline,
        "make_client",
        lambda host, pem, timeout: httpx2.AsyncClient(transport=httpx2.MockTransport(refuse)),
    )
    out = await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
    assert out.pin_failed == {HOST}
    (row,) = store.infra("airos")
    assert row.data["pin_failed"] is True and "another TLS certificate" in row.data["error"]
    assert row.data["hostname"] == "radio-a"  # what was read before is kept
    assert store.meta_get(f"airos.rejected.{HOST}") is None  # not a password problem


def test_cli_airos_off(tmp_path: Path) -> None:
    r = CliRunner().invoke(app, ["--data-dir", str(tmp_path), "airos"])
    assert r.exit_code == 1 and "docs/airos.md" in r.output


def test_cli_retry_login_tries_remembered_credentials_once_more(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The account was wrong on the radio, not in the config: once it is fixed there, the
    same credentials have to be tried again, and only when asked."""
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'[airos]\nenabled = true\nhosts = ["{HOST}"]\n'
        f'username = "analyst"\npassword = "{PASSWORD}"\n'
    )
    with Store(Config(data_dir=tmp_path).store_path) as store:
        store.meta_set(f"airos.rejected.{HOST}", airos.credentials_tag("analyst", PASSWORD))
    radio = FakeRadio()
    _patch(monkeypatch, radio)
    base = ["--config", str(cfg), "--data-dir", str(tmp_path), "airos"]

    r = CliRunner().invoke(app, base)
    assert r.exit_code == 1 and f"--retry-login {HOST}" in r.output
    assert radio.logins == []  # a plain run still leaves the radio alone

    r = CliRunner().invoke(app, [*base, "--retry-login", "192.168.1.99"])
    assert r.exit_code == 1 and "not in airos.hosts" in r.output

    r = CliRunner().invoke(app, [*base, "--retry-login", HOST])
    assert r.exit_code == 0 and "radio-a" in r.output
    assert len(radio.logins) == 1
    with Store(Config(data_dir=tmp_path).store_path) as store:
        assert store.meta_get(f"airos.rejected.{HOST}") is None


async def test_wireless_links_on_infra_and_device_pages(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """Off: no section. Read: the radio, its link with SNR from both ends, and the device
    line. A radio that failed shows the error over the state it last had."""
    from fastapi.testclient import TestClient

    from lanwatch.web.app import create_app

    assert 'id="radios"' not in TestClient(create_app(config)).get("/infra").text
    config.airos = airos_config()
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(sid, [HostObservation(ip=HOST, mac="02:00:00:00:0a:01", source="t")])
        store.finish_snapshot(sid, 1)
        _patch(monkeypatch, FakeRadio())
        await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
        device = store.device_by_key("02:00:00:00:0a:01")
        assert device is not None
    client = TestClient(create_app(config))
    infra = client.get("/infra").text
    assert 'id="radios"' in infra and "radio-a" in infra and "access point (bridge)" in infra
    assert "2444 MHz, 20 MHz wide" in infra and "100 Mbit/s" in infra
    assert "29 / 34 dB" in infra  # -67 - -96 here, -64 - -98 there
    assert "76 % / 44 %" in infra and "240 / 162 Mbit/s" in infra
    page = client.get(f"/devices/{device.id}").text
    assert "airOS" in page and "linked with radio-b" in page and "Ethernet 100 Mbit/s" in page
    assert "02:00:00:00:0e:01" in page  # the radio's other MAC address
    # Switched off, the facts stay stored but are not shown: they would only go stale.
    config.airos = AirosConfig()
    page = TestClient(create_app(config)).get(f"/devices/{device.id}").text
    assert "linked with radio-b" not in page and 'id="radios"' not in page
    config.airos = airos_config()

    with Store(config.store_path) as store:
        (row,) = store.infra("airos")
        store.replace_infra(
            "airos",
            {HOST: {**row.data, "error": "login not accepted: HTTP 200"}},
            store.begin_snapshot("infra", "t"),
        )
    infra = TestClient(create_app(config)).get("/infra").text
    assert "last read failed" in infra and "login not accepted" in infra and "radio-a" in infra


def test_station_side_takes_airmax_figures_from_its_own_status() -> None:
    """On a station, sta.cgi lists the AP with airMAX quality and capacity 0; the figures
    for the link are in the station's own status.cgi (polling)."""
    stations = json.loads((FIXTURES / "airos-sta-station.json").read_text())
    status = _status()
    status["wireless"].update(mode="sta", polling={"quality": 86, "capacity": 71})
    (st,) = airos.parse_status(HOST, status, stations).stations
    assert (st.airmax_quality, st.airmax_capacity) == (86, 71)
    # Where the station list has its own figures (the AP side), those are kept.
    (ap_view,) = airos.parse_status(HOST, _status(), _stations()).stations
    assert (ap_view.airmax_quality, ap_view.airmax_capacity) == (76, 44)


UBNT_LATEST = {
    "_embedded": {
        "firmware": [
            {"version": "v6.3.26", "product": "XM", "platform": "airmax", "channel": "release"},
            {"version": "v6.3.2-cs", "product": "XM", "platform": "airmax", "channel": "release"},
        ]
    }
}


def _ubnt(seen: list[str]) -> httpx2.AsyncClient:
    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        return httpx2.Response(200, json=UBNT_LATEST)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handle))


def test_the_radio_names_its_firmware_family() -> None:
    assert airos.parse_status(HOST, _status(), _stations()).platform == "XM"
    odd = _status()
    odd["host"]["fwprefix"] = "XM&x=1"  # anything but a plain family name is dropped
    assert airos.parse_status(HOST, odd, []).platform == ""


async def test_latest_airos_release_from_ubiquiti() -> None:
    from lanwatch.firmware import LatestVersions

    seen: list[str] = []
    async with _ubnt(seen) as client:
        latest = LatestVersions(client)
        assert await latest.airos("XM") == "v6.3.26"  # not the old custom build
        assert await latest.airos("x&y") is None  # never put into the URL
    (url,) = seen
    assert "fw-update.ui.com/api/firmware-latest" in url and "product~~XM" in url
    assert "channel~~release" in url


async def test_firmware_check_flags_an_old_airos(store: Store, config: Config) -> None:
    """The daily check looks up the newest release for a radio read by [airos], and
    device.firmware-outdated reports it; without online lookups nothing is asked."""
    from lanwatch.firmware import check_firmware
    from lanwatch.rules.base import RuleContext
    from lanwatch.rules.engine import Engine

    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, [HostObservation(ip=HOST, mac="02:00:00:00:0a:01", source="t")])
    store.finish_snapshot(sid, 1)
    d = store.device_by_key("02:00:00:00:0a:01")
    assert d is not None
    store.merge_device_attrs(
        d.id,
        {
            "firmware": {
                "product": "airOS",
                "version": "v6.3.11",
                "source": "airos",
                "model": "NanoStation loco M2",
                "platform": "XM",
                "latest": None,
                "update": None,
                "checked": "2026-11-10T12:00:00+00:00",
            }
        },
    )

    async def no_mdns(service: str, bind_ips: list[str]) -> dict[str, dict[str, str]]:
        return {}

    seen: list[str] = []
    offline = await check_firmware(store, [], online=False, mdns=no_mdns)
    assert [fw.update for _, fw in offline] == [None] and seen == []

    results = await check_firmware(store, [], online=True, online_client=_ubnt(seen), mdns=no_mdns)
    ((_, fw),) = results
    assert (fw.version, fw.latest, fw.update) == ("v6.3.11", "v6.3.26", True)
    ctx = RuleContext(store, config, store.begin_snapshot("firmware", "t"), None, False)
    (f,) = [x for x in Engine(config).run(ctx).emitted if x.rule_id == "device.firmware-outdated"]
    assert "airOS v6.3.11 is behind v6.3.26" in f.title


async def test_airos_read_keeps_the_newest_known_release(
    monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    """Every read writes the version it sees; the newest release the daily check found is
    kept, so an upgrade resolves the finding at the next read."""
    config.airos = airos_config()
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, [HostObservation(ip=HOST, mac="02:00:00:00:0a:01", source="t")])
    store.finish_snapshot(sid, 1)
    d = store.device_by_key("02:00:00:00:0a:01")
    assert d is not None
    store.merge_device_attrs(
        d.id, {"firmware": {"product": "airOS", "source": "airos", "latest": "v6.3.26"}}
    )
    _patch(monkeypatch, FakeRadio())  # the fixture radio runs v6.3.11
    await pipeline.collect_airos(config, store, store.begin_snapshot("infra", "t"))
    d = store.device(d.id)
    assert d is not None
    fw = d.attrs["firmware"]
    assert (fw["version"], fw["latest"], fw["update"], fw["platform"]) == (
        "v6.3.11",
        "v6.3.26",
        True,
        "XM",
    )
