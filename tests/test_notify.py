from __future__ import annotations

import json
import smtplib
from pathlib import Path
from typing import Any

import httpx
import pytest

from lanwatch.config import (
    Config,
    ConfigError,
    EmailConfig,
    HomeAssistantConfig,
    LlmConfig,
    NotifyConfig,
    NtfyConfig,
    WebhookConfig,
    load_config,
)
from lanwatch.models import Finding, FindingStatus, Kind, Severity
from lanwatch.notify import channels as ch
from lanwatch.notify import dispatch
from lanwatch.store import Store


class Recorder:
    def __init__(self, fail_paths: set[str] | None = None) -> None:
        self.calls: list[httpx.Request] = []
        self.fail_paths = fail_paths or set()

    def transport(self) -> httpx.MockTransport:
        def handle(req: httpx.Request) -> httpx.Response:
            self.calls.append(req)
            if req.url.path in self.fail_paths:
                return httpx.Response(500, text="boom")
            return httpx.Response(200, json={})

        return httpx.MockTransport(handle)


def _finding(fid: str, sev: Severity, title: str = "t") -> Finding:
    return Finding(id=fid, rule_id="r.x", severity=sev, kind=Kind.SECURITY, title=title)


def _seed_findings(store: Store) -> None:
    store.upsert_findings(
        [
            _finding("hi", Severity.HIGH, "Telnet open: gw"),
            _finding("lo", Severity.LOW, "Cert expiring: nas"),
            _finding("in", Severity.INFO, "IP changed"),
        ],
        {"r.x"},
        set(),
    )
    store.set_explanation("hi", "Telnet sends passwords in cleartext.\n\nImpact.\n\n- Disable it")


def notify_config(tmp_path: Path, **notify: Any) -> Config:
    return Config(data_dir=tmp_path, llm=LlmConfig(enabled=False), notify=NotifyConfig(**notify))


async def test_ntfy_channel_headers() -> None:
    rec = Recorder()
    c = ch.NtfyChannel(
        NtfyConfig(enabled=True, topic="lan", token="tok", url="https://ntfy.example/")
    )
    n = ch.Notification("finding.new", "Title", "Body", Severity.CRITICAL)
    async with httpx.AsyncClient(transport=rec.transport()) as client:
        await c.send(n, client)
    req = rec.calls[0]
    assert str(req.url) == "https://ntfy.example/lan"
    assert req.headers["Title"] == "Title" and req.headers["Priority"] == "5"
    assert req.headers["Authorization"] == "Bearer tok" and req.content == b"Body"


async def test_webhook_payload_and_ha_calls() -> None:
    rec = Recorder()
    f = _finding("f1", Severity.MEDIUM, "x")
    from lanwatch.models import FindingRow

    row = FindingRow(
        id=f.id,
        rule_id=f.rule_id,
        severity=f.severity,
        kind=f.kind,
        title=f.title,
        device_id=3,
        evidence={"port": 23},
        first_seen="2026-11-04T10:00:00+00:00",
        last_seen="2026-11-04T10:00:00+00:00",
        status=FindingStatus.OPEN,
        explanation=None,
    )
    n = ch.Notification("finding.new", "T", "B", Severity.MEDIUM, [row])
    async with httpx.AsyncClient(transport=rec.transport()) as client:
        await ch.WebhookChannel(
            WebhookConfig(enabled=True, url="http://hook/x", headers={"X-A": "1"})
        ).send(n, client)
        ha = ch.HomeAssistantChannel(
            HomeAssistantConfig(
                enabled=True, url="http://ha:8123", token="T", service="notify.mobile_app_phone"
            )
        )
        await ha.send(n, client)
        await ha.publish_state(
            {
                "devices_online": 3,
                "devices_known": 5,
                "open_findings": 2,
                "by_severity": {"high": 1, "medium": 1},
                "last_discovery": "x",
                "last_inventory": None,
            },
            client,
        )
    hook = rec.calls[0]
    body = json.loads(hook.content)
    assert hook.headers["X-A"] == "1" and body["event"] == "finding.new"
    assert body["findings"][0] == {
        "id": "f1",
        "rule_id": "r.x",
        "severity": "medium",
        "title": "x",
        "device_id": 3,
        "evidence": {"port": 23},
    }
    svc = rec.calls[1]
    assert svc.url.path == "/api/services/notify/mobile_app_phone"
    assert svc.headers["Authorization"] == "Bearer T"
    assert json.loads(svc.content)["message"] == "B"
    states = [c.url.path for c in rec.calls[2:]]
    assert states == [
        "/api/states/sensor.lanwatch_devices_online",
        "/api/states/sensor.lanwatch_devices_known",
        "/api/states/sensor.lanwatch_open_findings",
    ]
    attrs = json.loads(rec.calls[4].content)
    assert attrs["state"] == 2 and attrs["attributes"]["open_high"] == 1


async def test_email_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict[str, Any] = {}

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            sent["host"] = (host, port)

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def starttls(self) -> None:
            sent["tls"] = True

        def login(self, u: str, p: str) -> None:
            sent["login"] = (u, p)

        def send_message(self, msg: Any) -> None:
            sent["msg"] = msg

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    c = ch.EmailChannel(
        EmailConfig(enabled=True, smtp_host="mail", username="u", password="p", to=["a@b", "c@d"])
    )
    async with httpx.AsyncClient() as client:
        await c.send(ch.Notification("digest", "Sub", "Hello", None), client)
    assert sent["host"] == ("mail", 587) and sent["tls"] and sent["login"] == ("u", "p")
    assert sent["msg"]["To"] == "a@b, c@d" and sent["msg"]["Subject"] == "Sub"


async def test_dispatch_filters_batches_and_records(
    store: Store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = Recorder(fail_paths={"/x"})
    monkeypatch.setattr(
        dispatch, "_make_client", lambda: httpx.AsyncClient(transport=rec.transport())
    )
    config = notify_config(
        tmp_path,
        ntfy=NtfyConfig(enabled=True, topic="t"),
        webhook=WebhookConfig(enabled=True, url="http://hook/x", min_severity=Severity.HIGH),
    )
    _seed_findings(store)

    await dispatch.after_round(config, store, ["hi", "lo", "in"], [])
    # One batched message; its severity is the highest in the batch (high), so it passes
    # both the default medium threshold and the webhook's own high threshold.
    paths = [c.url.path for c in rec.calls]
    assert paths == ["/t", "/x"]
    body = rec.calls[0].content.decode()
    assert "[high] Telnet open: gw" in body and "cleartext" in body and "[low] Cert" in body
    assert rec.calls[0].headers["Title"] == "lanwatch: 3 new findings (1 high, 1 low, 1 info)"
    log = store.notifications()
    assert [(r.channel, r.ok) for r in log] == [("webhook", False), ("ntfy", True)]
    assert log[0].error and "500" in log[0].error

    # A low-only round does not pass the default medium threshold.
    rec.calls.clear()
    store.upsert_findings([_finding("lo2", Severity.LOW)], {"r.y"}, set())
    await dispatch.after_round(config, store, ["lo2"], [])
    assert rec.calls == []

    # Resolved notifications are off by default, on when configured.
    await dispatch.after_round(config, store, [], ["hi"])
    assert rec.calls == []
    config.notify.resolved = True
    await dispatch.after_round(config, store, [], ["hi"])
    assert rec.calls[0].headers["Title"] == "lanwatch: resolved: Telnet open: gw"

    # Digest and test messages have no severity and go everywhere.
    rec.calls.clear()
    await dispatch.digest(config, store, "# Digest 2026-11-04\n\nAlt vel.\n")
    assert rec.calls[0].headers["Title"] == "lanwatch digest 2026-11-04" and len(rec.calls) == 2
    assert await dispatch.test_message(config, store) == 1  # webhook /x still fails


async def test_ha_sensors_published_every_round(
    store: Store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = Recorder()
    monkeypatch.setattr(
        dispatch, "_make_client", lambda: httpx.AsyncClient(transport=rec.transport())
    )
    config = notify_config(tmp_path, home_assistant=HomeAssistantConfig(enabled=True, token="T"))
    await dispatch.after_round(config, store, [], [])
    assert [c.url.path for c in rec.calls] == [
        "/api/states/sensor.lanwatch_devices_online",
        "/api/states/sensor.lanwatch_devices_known",
        "/api/states/sensor.lanwatch_open_findings",
    ]
    config.notify.home_assistant.publish_sensors = False
    rec.calls.clear()
    await dispatch.after_round(config, store, [], [])
    assert rec.calls == []


def test_notify_config_validation() -> None:
    with pytest.raises(ConfigError, match="topic"):
        load_config(None, {"notify": {"ntfy": {"enabled": True}}}, environ={})
    with pytest.raises(ConfigError, match="token"):
        load_config(None, {"notify": {"home_assistant": {"enabled": True}}}, environ={})
    with pytest.raises(ConfigError, match="url"):
        load_config(None, {"notify": {"webhook": {"enabled": True, "url": "ftp://x"}}}, environ={})
    cfg = load_config(
        None,
        {},
        environ={"LANWATCH_NOTIFY__NTFY__ENABLED": "true", "LANWATCH_NOTIFY__NTFY__TOPIC": "x"},
    ).config
    assert cfg.notify.ntfy.enabled and cfg.notify.ntfy.topic == "x"
    assert cfg.notify.min_severity is Severity.MEDIUM and not cfg.notify.resolved


def test_cli_notify_and_web_page(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient
    from typer.testing import CliRunner

    from lanwatch.cli import app
    from lanwatch.web.app import create_app

    runner = CliRunner()
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "notify"])
    assert r.exit_code == 0 and "no notifications" in r.output
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "notify", "--test"])
    assert r.exit_code == 1 and "no notification channels" in r.output

    config = notify_config(tmp_path)
    with Store(config.store_path) as store:
        store.record_notification("ntfy", "test", "hello", True, None)
        store.record_notification("webhook", "finding.new", "x", False, "HTTPStatusError: 500")
    page = TestClient(create_app(config)).get("/notifications")
    assert page.status_code == 200 and "hello" in page.text and "failed" in page.text
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "notify"])
    assert "ERR webhook" in r.output and "ok  ntfy" in r.output
