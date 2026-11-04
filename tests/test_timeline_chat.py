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
from lanwatch.llm.tasks import ChatAnswer, LlmService, answer_question
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


def _seed_chat(store: Store) -> None:
    _round(store, _hosts("10.0.0.1", "10.0.0.2"))
    store.set_device_classification(1, "router", "Gateway", 0.9)
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


def test_chat_summary_and_tools(store: Store, tmp_path: Path) -> None:
    import asyncio

    from lanwatch.llm.tasks import chat_summary
    from lanwatch.llm.tools import ToolRunner

    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=True, chat_num_ctx=4096))
    _seed_chat(store)
    summary = chat_summary(store)
    assert "devices: 2 known, 2 online" in summary and "id=abc [low] Weak ssh" in summary

    runner = ToolRunner(config, store)
    devs = json.loads(asyncio.run(runner.call("list_devices", {"query": "h1"})))
    assert [d["id"] for d in devs] == [1] and devs[0]["open_ports"] == 1
    dev = json.loads(asyncio.run(runner.call("get_device", {"device_id": 1})))
    assert dev["services"][0]["product"] == "OpenSSH" and dev["open_findings"][0]["id"] == "abc"
    assert "error" in json.loads(asyncio.run(runner.call("get_device", {"device_id": 99})))
    fl = json.loads(asyncio.run(runner.call("list_findings", {"severity": "low"})))
    assert fl[0]["device"] == "h1"
    assert (
        json.loads(asyncio.run(runner.call("get_finding", {"finding_id": "abc"})))["rule_id"]
        == "ssh.x"
    )
    assert json.loads(asyncio.run(runner.call("search", {"query": "ssh"})))["services"]
    assert (
        json.loads(asyncio.run(runner.call("infrastructure", {})))["upnp"][0]["friendly_name"]
        == "Router"
    )
    assert any(
        r["id"] == "ssh.weak-algorithms"
        for r in json.loads(asyncio.run(runner.call("list_rules", {})))
    )
    assert json.loads(asyncio.run(runner.call("timeline", {"limit": 5})))
    assert "error" in json.loads(asyncio.run(runner.call("nope", {})))
    assert "bad arguments" in json.loads(asyncio.run(runner.call("get_device", {"x": 1})))["error"]

    # Actions: executed, recorded as events; refused when actions are disabled.
    assert json.loads(asyncio.run(runner.call("name_device", {"device_id": 2, "name": "Printer"})))[
        "ok"
    ]
    assert json.loads(asyncio.run(runner.call("ack_finding", {"finding_id": "abc"})))["ok"]
    assert (
        "only open"
        in json.loads(asyncio.run(runner.call("ack_finding", {"finding_id": "abc"})))["error"]
    )
    assert store.device(2).name == "Printer"  # type: ignore[union-attr]
    assert [e.kind for e in store.events(limit=4)] == [
        "chat.action",
        "finding.acked",
        "chat.action",
        "device.named",
    ]
    ro = ToolRunner(config, store, allow_actions=False)
    assert (
        "disabled"
        in json.loads(asyncio.run(ro.call("name_device", {"device_id": 2, "name": "X"})))["error"]
    )
    assert len(runner.trace) == 14 and runner.trace[0].name == "list_devices" and runner.trace[0].ok


def test_answer_question_tool_loop(store: Store, tmp_path: Path) -> None:
    import asyncio

    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=True, chat_num_ctx=4096))
    _seed_chat(store)
    fake = FakeOllama(lambda s, u, f: "unused")

    def tool_handler(
        messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> str | dict[str, Any]:
        names = {t["function"]["name"] for t in tools}
        assert {"list_devices", "get_device", "ack_finding", "run_scan"} <= names
        tool_msgs = [m for m in messages if m["role"] == "tool"]
        if not tool_msgs:
            return {"tool_calls": [{"name": "list_devices", "arguments": {"query": "h1"}}]}
        if len(tool_msgs) == 1:
            dev_id = json.loads(tool_msgs[0]["content"])[0]["id"]
            return {
                "tool_calls": [
                    {"name": "get_device", "arguments": json.dumps({"device_id": dev_id})}
                ]
            }
        svc = json.loads(tool_msgs[1]["content"])["services"][0]
        return f"h1 (#1) runs {svc['product']} {svc['version']} on {svc['port']}/{svc['proto']}."

    fake.tool_handler = tool_handler
    svc = LlmService(config, store, OllamaClient(config.llm, fake.client()))
    ans = asyncio.run(
        answer_question(
            svc,
            "What does h1 run?",
            [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}],
        )
    )
    assert ans is not None and ans.text == "h1 (#1) runs OpenSSH 9.2 on 22/tcp."
    assert [t["name"] for t in ans.tools] == ["list_devices", "get_device"] and all(
        t["ok"] for t in ans.tools
    )
    assert ans.tools[1]["arguments"] == {"device_id": 1}  # JSON-string arguments are decoded
    first = fake.requests[0]
    assert "tools" in first and "format" not in first and first["options"]["num_ctx"] == 4096
    assert [m["role"] for m in first["messages"]] == ["system", "user", "assistant", "user"]
    assert (
        "devices: 2 known" in first["messages"][0]["content"]
        and "Norwegian" in first["messages"][0]["content"]
    )
    assert [m["role"] for m in fake.requests[2]["messages"]][-4:] == [
        "assistant",
        "tool",
        "assistant",
        "tool",
    ]
    assert svc.calls == 3

    # Runaway tool loops are cut off.
    fake.tool_handler = lambda m, t: {"tool_calls": [{"name": "list_rules", "arguments": {}}]}
    ans2 = asyncio.run(answer_question(svc, "loop"))
    assert ans2 is not None and "too many tool calls" in ans2.text and len(ans2.tools) == 9


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
        cfg: Config, s: Store, q: str, h: list[dict[str, str]] | None = None, allow: bool = True
    ) -> ChatAnswer | None:
        return ChatAnswer(
            f"echo: {q} ({len(h or [])} turns, actions={allow})",
            [{"name": "x", "arguments": {}, "ok": True, "result": ""}],
        )

    monkeypatch.setattr(hooks, "ask", fake_ask)
    config.llm.enabled = True
    j = client.post(
        "/api/chat",
        json={
            "question": "what?",
            "history": [{"role": "user", "content": "x"}],
            "allow_actions": False,
        },
    ).json()
    assert j["answer"] == "echo: what? (1 turns, actions=False)" and j["tools"][0]["name"] == "x"


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


def test_tools_unsupported_falls_back_to_context(store: Store, tmp_path: Path) -> None:
    import asyncio

    import httpx

    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=True, chat_num_ctx=4096))
    _seed_chat(store)
    seen: list[dict[str, Any]] = []

    def handle(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append(body)
        if "tools" in body:
            return httpx.Response(
                400, json={"error": "registry.ollama.ai/x does not support tools"}
            )
        system = body["messages"][0]["content"]
        if "Full inventory (tools unavailable)" not in system:
            # the client's own retry without tools; answer_question discards this reply
            return httpx.Response(200, json={"message": {"role": "assistant", "content": "plain"}})
        assert "OpenSSH 9.2" in system
        return httpx.Response(
            200, json={"message": {"role": "assistant", "content": "From the list: h1."}}
        )

    client = OllamaClient(config.llm, httpx.AsyncClient(transport=httpx.MockTransport(handle)))
    svc = LlmService(config, store, client)
    ans = asyncio.run(answer_question(svc, "Who runs ssh?"))
    assert ans is not None and ans.text == "From the list: h1." and ans.tools == []
    assert client.tools_supported is False
    # tools: first attempt with tools (400), retry without, then the context-paste call.
    assert [("tools" in b) for b in seen] == [True, False, False]
    ans2 = asyncio.run(answer_question(svc, "again"))
    assert ans2 is not None and len(seen) == 5  # no more attempts with tools


def test_chat_eval_suite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from lanwatch.llm.evaluate import load_chat_cases, run_chat_eval, seed_eval_store

    with Store.memory() as s:
        seed_eval_store(s)
        assert len(s.devices()) == 3 and s.findings()
        assert s.device(1).name == "Router"  # type: ignore[union-attr]

    cases = load_chat_cases(Path("evals/chat.jsonl"))
    assert len(cases) == 8 and cases[4].expect_tools == ["ack_finding"]

    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=True))
    fake = FakeOllama(lambda s, u, f: "unused")

    def tool_handler(
        messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> str | dict[str, Any]:
        q = next(m["content"] for m in reversed(messages) if m["role"] == "user")
        done = [m for m in messages if m["role"] == "tool"]
        if done:
            return "Router (#1) and the NAS; VNC is critical; MySQL 8.0.3 runs there."
        if "SSH" in q:
            return {"tool_calls": [{"name": "list_devices", "arguments": {}}]}
        if "serious" in q:
            return {"tool_calls": [{"name": "list_findings", "arguments": {"status": "open"}}]}
        if "NAS" in q:
            return {"tool_calls": [{"name": "get_device", "arguments": {"device_id": 2}}]}
        if "Acknowledge" in q:
            return {"tool_calls": [{"name": "ack_finding", "arguments": {"finding_id": "bogus"}}]}
        if "UPnP" in q:
            return {"tool_calls": [{"name": "infrastructure", "arguments": {}}]}
        return "I do not have that information."

    fake.tool_handler = tool_handler
    monkeypatch.setattr(
        OllamaClient, "__init__", lambda self, cfg, client=None: _init(self, cfg, fake)
    )
    report = asyncio.run(run_chat_eval(config, Path("evals/chat.jsonl")))
    by = {r.name: r for r in report.results}
    assert by["which-expose-ssh"].ok and by["worst-finding"].ok and by["device-detail"].ok
    assert (
        by["no-action-when-not-asked"].ok
        and by["unknown-device-honest"].ok
        and by["infra-question"].ok
    )
    assert by["ack-when-asked"].ok  # tool was called, even though the id was wrong
    assert not by["name-when-asked"].ok  # handler never calls name_device
    assert report.correct == 7 and report.errors == 0
    assert "chat accuracy: 7/8" in report.render()


def _init(self: OllamaClient, cfg: LlmConfig, fake: FakeOllama) -> None:
    self.cfg = cfg
    self.base_url = cfg.base_url.rstrip("/")
    self._client = fake.client()
    self._think_supported = None
    self.tools_supported = None
