from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from lanwatch.collectors.services import PortObservation, PortSet
from lanwatch.config import Config, LlmConfig
from lanwatch.llm import hooks
from lanwatch.llm.client import OllamaClient
from lanwatch.llm.tasks import LlmService, answer_question, build_chat_context
from lanwatch.models import Finding, FindingStatus, HostObservation, Kind, Severity
from lanwatch.store import Store
from lanwatch.web.app import create_app
from tests.fake_ollama import FakeOllama


def _hosts(*ips: str) -> list[HostObservation]:
    return [
        HostObservation(ip=ip, mac=f"aa:bb:cc:00:00:{i + 1:02x}", hostname=f"h{i + 1}", source="t")
        for i, ip in enumerate(ips)
    ]


def _round(store: Store, hosts: list[HostObservation]) -> None:
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, hosts)
    store.finish_snapshot(sid, len(hosts))


def test_events_from_store_changes(store: Store) -> None:
    _round(store, _hosts("10.0.0.1", "10.0.0.2"))
    kinds = [e.kind for e in store.events()]
    assert kinds == ["device.new", "device.new"]

    # Second round: device 2 gone, device 1 changed IP, device 3 new.
    h = _hosts("10.0.0.9", "10.0.0.2", "10.0.0.3")
    _round(store, [h[0], h[2]])
    kinds = [e.kind for e in store.events()]
    assert kinds[:3] == ["presence.offline", "device.new", "device.ip-changed"]
    assert store.events(exclude_prefix="presence.")[0].kind == "device.new"
    # Device 2 returns -> presence.online
    _round(store, h)
    assert store.events(limit=1)[0].kind == "presence.online"

    sid = store.begin_snapshot("inventory", "t")
    scanned = {"tcp": PortSet.from_spec("1-1000")}
    store.record_services(
        sid, 1, [PortObservation(port=22, proto="tcp", state="open", name="ssh")], scanned
    )
    assert store.events(limit=1)[0].kind != "service.opened"  # first scan is silent
    store.record_services(
        sid, 1, [PortObservation(port=80, proto="tcp", state="open", name="http")], scanned
    )
    assert [e.kind for e in store.events(limit=2)] == ["service.closed", "service.opened"]

    f = Finding(
        id="f1", rule_id="r", severity=Severity.HIGH, kind=Kind.SECURITY, title="T", device_id=1
    )
    store.upsert_findings([f], {"r"}, {"r"})
    store.upsert_findings([], {"r"}, {"r"})
    store.upsert_findings([f], {"r"}, {"r"})
    assert store.ack("f1")
    assert [e.kind for e in store.events(limit=4)] == [
        "finding.acked",
        "finding.reopened",
        "finding.resolved",
        "finding.opened",
    ]
    assert store.events(limit=1)[0].finding_id == "f1"

    store.set_device_name(1, "Router")
    store.set_device_classification(1, "router", "Gateway", 0.9)
    store.set_device_classification(1, "router", "Gateway again", 0.95)  # same kind: no event
    assert [e.kind for e in store.events(limit=2)] == ["device.classified", "device.named"]
    assert [e.kind for e in store.events(device_id=1, limit=3)] == [
        "device.classified",
        "device.named",
        "finding.acked",
    ]
    assert "finding.acked" in store.event_kinds()


def test_infra_events(store: Store) -> None:
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra("dhcp", {"eth0/10.0.0.1": {"server": "10.0.0.1", "interface": "eth0"}}, sid)
    store.replace_infra(
        "dhcp",
        {
            "eth0/10.0.0.1": {"server": "10.0.0.1", "interface": "eth0"},
            "eth0/10.0.0.66": {"server": "10.0.0.66", "interface": "eth0"},
        },
        sid,
    )
    store.replace_infra("dhcp", {"eth0/10.0.0.1": {"server": "10.0.0.1", "interface": "eth0"}}, sid)
    assert [e.summary for e in store.events(limit=3)] == [
        "DHCP server gone: 10.0.0.66",
        "DHCP server seen: 10.0.0.66",
        "DHCP server seen: 10.0.0.1",
    ]
    m = {
        "external_port": 443,
        "protocol": "TCP",
        "internal_client": "10.0.0.40",
        "internal_port": 8443,
    }
    store.replace_infra(
        "upnp", {"10.0.0.1": {"friendly_name": "Router", "is_igd": True, "mappings": [m]}}, sid
    )
    store.replace_infra(
        "upnp", {"10.0.0.1": {"friendly_name": "Router", "is_igd": True, "mappings": []}}, sid
    )
    assert [e.summary for e in store.events(limit=2)] == [
        "Port mapping removed on Router: 443/TCP->10.0.0.40:8443",
        "Port mapping added on Router: 443/TCP->10.0.0.40:8443",
    ]


def test_search_and_series(store: Store) -> None:
    _round(store, _hosts("10.0.0.1", "10.0.0.2"))
    _round(store, _hosts("10.0.0.1"))
    sid = store.begin_snapshot("inventory", "t")
    store.record_services(
        sid,
        1,
        [
            PortObservation(
                port=22, proto="tcp", state="open", name="ssh", product="OpenSSH", version="9.2"
            )
        ],
        {"tcp": PortSet.from_spec("1-100")},
    )
    store.upsert_findings(
        [
            Finding(
                id="abc",
                rule_id="ssh.x",
                severity=Severity.LOW,
                kind=Kind.PROBLEM,
                title="Weak ssh",
                device_id=1,
            )
        ],
        {"ssh.x"},
        set(),
    )
    res = store.search("ssh")
    assert [s.port for s in res["services"]] == [22] and [f.id for f in res["findings"]] == ["abc"]
    assert [d.id for d in store.search("h2")["devices"]] == [2]
    assert [s.port for s in store.search("22")["services"]] == [22]
    assert store.search("nothing-here") == {"devices": [], "services": [], "findings": []}
    series = store.snapshot_series("discovery", "2000-01-01T00:00:00+00:00")
    assert [n for _, n in series] == [2, 1]


def test_chat_context_and_answer(store: Store, tmp_path: Path) -> None:
    import asyncio

    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=True, chat_num_ctx=4096))
    _round(store, _hosts("10.0.0.1"))
    store.set_device_classification(1, "router", "Gateway", 0.9)
    sid = store.begin_snapshot("inventory", "t")
    store.record_services(
        sid,
        1,
        [PortObservation(port=22, proto="tcp", state="open", name="ssh")],
        {"tcp": PortSet.from_spec("1-100")},
    )
    store.upsert_findings(
        [
            Finding(
                id="abc",
                rule_id="ssh.x",
                severity=Severity.LOW,
                kind=Kind.PROBLEM,
                title="Weak ssh",
                device_id=1,
            )
        ],
        {"ssh.x"},
        set(),
    )
    store.replace_infra(
        "upnp",
        {
            "10.0.0.1": {
                "friendly_name": "Router",
                "is_igd": True,
                "external_ip": "203.0.113.9",
                "mappings": [],
            }
        },
        sid,
    )
    ctx = build_chat_context(store, config)
    assert "DEVICES (1 known, 1 online)" in ctx and "22/tcp ssh" in ctx and "kind=router" in ctx
    assert "id=abc [low] ssh.x: Weak ssh" in ctx and "UPnP IGD Router" in ctx

    seen: dict[str, Any] = {}

    def handler(system: str, user: str, schema: dict[str, Any]) -> str:
        seen["system"] = system
        seen["user"] = user
        return "Only the router (#1) exposes SSH."

    fake = FakeOllama(handler)
    svc = LlmService(config, store, OllamaClient(config.llm, fake.client()))
    answer = asyncio.run(
        answer_question(
            svc,
            "Which devices expose SSH?",
            [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}],
        )
    )
    assert answer == "Only the router (#1) exposes SSH."
    body = fake.requests[0]
    assert "format" not in body and body["options"]["num_ctx"] == 4096
    assert [m["role"] for m in body["messages"]] == ["system", "user", "assistant", "user"]
    assert (
        "22/tcp ssh" in body["messages"][0]["content"]
        and "Norwegian" in body["messages"][0]["content"]
    )

    # Truncation respects the budget.
    small = Config(data_dir=tmp_path, llm=LlmConfig(enabled=True, chat_num_ctx=2048))
    for i in range(300):
        store.upsert_findings(
            [
                Finding(
                    id=f"x{i}",
                    rule_id="r",
                    severity=Severity.INFO,
                    kind=Kind.PROBLEM,
                    title="t" * 50,
                )
            ],
            {"r"},
            set(),
        )
    text = build_chat_context(store, small)
    assert (
        text.endswith("[... inventory truncated to fit the context window ...]")
        and len(text) < 3000
    )


def test_web_pages_and_chat_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))
    with Store(config.store_path) as store:
        _round(store, _hosts("10.0.0.1", "10.0.0.2"))
        _round(store, _hosts("10.0.0.1"))
        store.set_device_name(1, "Router")
    client = TestClient(create_app(config))
    r = client.get("/timeline")
    assert r.status_code == 200 and "Named Router" in r.text and "went offline" not in r.text
    assert "went offline" in client.get("/timeline?presence=true").text
    assert "Named Router" in client.get("/timeline?kind=device.named").text
    assert "New device" not in client.get("/timeline?kind=device.named").text
    assert "Named Router" in client.get("/timeline?device=1").text
    r = client.get("/search?q=h2")
    assert r.status_code == 200 and "10.0.0.2" in r.text
    assert "No matches" in client.get("/search?q=zzz").text
    assert "Named Router" in client.get("/devices/1").text  # History section
    dash = client.get("/").text
    assert "Recent events" in dash and "Hosts online, last 7 days" in dash and "<polyline" in dash
    assert client.get("/chat").status_code == 200

    assert client.post("/api/chat", json={"question": ""}).status_code == 400
    j = client.post("/api/chat", json={"question": "hi"}).json()
    assert j["answer"] is None and "disabled" in j["error"]

    async def fake_ask(
        cfg: Config, s: Store, q: str, h: list[dict[str, str]] | None = None
    ) -> str | None:
        return f"echo: {q} ({len(h or [])} turns)"

    monkeypatch.setattr(hooks, "ask", fake_ask)
    config.llm.enabled = True
    j = client.post(
        "/api/chat", json={"question": "what?", "history": [{"role": "user", "content": "x"}]}
    ).json()
    assert j == {"answer": "echo: what? (1 turns)"}


def test_cli_timeline_search_ask(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from lanwatch.cli import app

    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))
    with Store(config.store_path) as store:
        _round(store, _hosts("10.0.0.1"))
    runner = CliRunner()
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "timeline"])
    assert r.exit_code == 0 and "device.new" in r.output
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "search", "h1"])
    assert r.exit_code == 0 and "10.0.0.1" in r.output
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "ask", "anything", "here"])
    assert r.exit_code == 1 and "LLM disabled" in r.output
    _ = json, FindingStatus
