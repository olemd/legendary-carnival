from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from lanwatch.collectors.services import parse_nmap_xml_services
from lanwatch.config import Config, LlmConfig
from lanwatch.llm import hooks
from lanwatch.llm.client import LlmUnavailable, OllamaClient
from lanwatch.llm.evaluate import run_eval
from lanwatch.llm.prompts import load_prompt, render
from lanwatch.llm.tasks import (
    Classification,
    Digest,
    Explanation,
    LlmService,
    classify_devices,
    device_facts,
    explain_findings,
    make_digest,
)
from lanwatch.models import FindingStatus, HostObservation
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store
from tests.conftest import fixture_text
from tests.fake_ollama import FakeOllama


def smart_handler(system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
    title = schema.get("title", "")
    if title == "Classification":
        kind = "router" if "Ubiquiti" in user else ("nas" if "microsoft-ds" in user else "unknown")
        return {"kind": kind, "description": "En enhet.", "vendor_guess": None, "confidence": 0.8}
    if title == "Explanation":
        return {"summary": "Kort.", "impact": "Betydning.", "actions": ["Gjør noe", "Gjør mer"]}
    if title == "Digest":
        ids = [line.split("id=")[1].split()[0] for line in user.splitlines() if "id=" in line]
        return {
            "summary": "Rolig dag.",
            "priorities": [
                {"finding_id": ids[0], "reason": "Viktigst"},
                {"finding_id": "nope", "reason": "x"},
            ],
            "notes": ["Merk."],
        }
    if title == "Suggestions":
        return {
            "items": [
                {
                    "title": "Segmenter IoT",
                    "rationale": "Fordi.",
                    "effort": "medium",
                    "affects": ["nas"],
                }
            ]
        }
    raise AssertionError(title)


def llm_config(tmp_path: Path) -> Config:
    return Config(data_dir=tmp_path, llm=LlmConfig(enabled=True, max_calls_per_round=10))


def seed(store: Store, config: Config) -> tuple[list[int], list[str]]:
    res = parse_nmap_xml_services(fixture_text("nmap-services.xml"))
    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(
        sid,
        [
            HostObservation(ip=h.ip, mac=h.mac, vendor="Ubiquiti" if h.mac else None, source="t")
            for h in res.hosts
        ],
    )
    store.finish_snapshot(sid, 2)
    inv = store.begin_snapshot("inventory", "t")
    diffs = {
        d: store.record_services(inv, d, h.ports, res.scanned)
        for h, d in zip(res.hosts, rec.new_device_ids, strict=True)
    }
    store.finish_snapshot(inv, 2)
    r = Engine(config).run(
        RuleContext(
            store=store,
            config=config,
            snapshot_id=inv,
            previous_snapshot_id=None,
            is_baseline=False,
            service_diffs=diffs,
        )
    )
    return rec.new_device_ids, r.new_ids


def test_prompts_load_and_render() -> None:
    for name in ("classify", "explain", "digest", "suggest"):
        p = load_prompt(name)
        assert p.version == "1" and p.system and p.user_template
    system, user = render(load_prompt("classify"), "nb", facts="{}", kinds=["router"])
    assert "Norwegian" in system and "router" in user
    with pytest.raises(Exception, match="rule_id"):
        render(load_prompt("explain"), "en")  # StrictUndefined: missing variables are errors


async def test_client_status_and_think_fallback() -> None:
    fake = FakeOllama(smart_handler)
    client = OllamaClient(LlmConfig(), fake.client())
    st = await client.status()
    assert st.reachable and st.model_present and st.version == "0.0-fake"
    fake.reject_think = True
    r = await client.chat_json("s", "Ubiquiti", Classification.model_json_schema())
    assert json.loads(r.content)["kind"] == "router"
    assert len(fake.requests) == 2 and "think" not in fake.requests[1]
    r = await client.chat_json("s", "Ubiquiti", Classification.model_json_schema())
    assert len(fake.requests) == 3 and "think" not in fake.requests[2]  # remembered

    missing = OllamaClient(LlmConfig(model="nope:1b"), FakeOllama(smart_handler).client())
    with pytest.raises(LlmUnavailable, match="ollama pull"):
        await missing.chat_json("s", "u", {})


async def test_service_cache_validation_and_unavailable(store: Store, tmp_path: Path) -> None:
    config = llm_config(tmp_path)
    calls = {"n": 0}

    def flaky(system: str, user: str, schema: dict[str, Any]) -> dict[str, Any] | str:
        calls["n"] += 1
        if calls["n"] == 1:
            return {"kind": "spaceship", "description": "x", "confidence": 2}  # invalid
        return smart_handler(system, user, schema)

    fake = FakeOllama(flaky)
    svc = LlmService(config, store, OllamaClient(config.llm, fake.client()))
    out = await svc.ask("classify", {"facts": "Ubiquiti"}, Classification, kinds=["router"])
    assert out is not None and out.kind.value == "router"
    assert (
        calls["n"] == 2
        and "previous answer was invalid" in fake.requests[1]["messages"][1]["content"]
    )
    assert svc.calls == 2  # every inference counts against the budget, valid or not

    again = await svc.ask("classify", {"facts": "Ubiquiti"}, Classification, kinds=["router"])
    assert again == out and calls["n"] == 2 and svc.cache_hits == 1

    down = LlmService(config, store, OllamaClient(LlmConfig(base_url="http://127.0.0.1:1"), None))
    assert await down.ask("classify", {"facts": "new"}, Classification, kinds=["router"]) is None
    assert down.unavailable and "cannot reach" in down.unavailable
    await down.aclose()


async def test_classify_explain_digest(store: Store, tmp_path: Path) -> None:
    config = llm_config(tmp_path)
    device_ids, finding_ids = seed(store, config)
    fake = FakeOllama(smart_handler)
    svc = LlmService(config, store, OllamaClient(config.llm, fake.client()))

    facts = device_facts(store.device(device_ids[0]), store.services(device_ids[0]))  # type: ignore[arg-type]
    assert (
        facts["vendor_from_mac"] == "Ubiquiti"
        and facts["open_ports"][2]["http_title"] == "Router admin"
    )

    assert await classify_devices(svc, device_ids, budget=10) == 2
    d0, d1 = store.device(device_ids[0]), store.device(device_ids[1])
    assert (
        d0 and d0.kind == "router" and d0.description == "En enhet." and d0.kind_confidence == 0.8
    )
    assert d1 and d1.kind == "nas"
    assert await classify_devices(svc, device_ids, budget=10) == 0  # cached, unchanged

    assert await explain_findings(svc, finding_ids, budget=10) == len(finding_ids)
    f = store.finding(finding_ids[0])
    assert f and f.explanation == "Kort.\n\nBetydning.\n\n- Gjør noe\n- Gjør mer"
    assert await explain_findings(svc, finding_ids, budget=10) == 0  # already explained

    # Budget stops work; nothing explodes.
    store.set_explanation(finding_ids[0], "")
    svc.calls = 10
    assert await explain_findings(svc, finding_ids, budget=10) == 0

    text = await make_digest(svc)
    assert text and text.startswith("# Digest ") and "Rolig dag." in text
    assert "Viktigst" in text and "nope" not in text  # invented id dropped
    assert "Open findings: 6" in text


async def test_hooks_write_files_and_degrade(
    store: Store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = llm_config(tmp_path)
    device_ids, finding_ids = seed(store, config)
    fake = FakeOllama(smart_handler)
    monkeypatch.setattr(
        OllamaClient, "__init__", lambda self, cfg, client=None: _init(self, cfg, fake)
    )

    assert await hooks.after_round(config, store, device_ids, finding_ids)
    assert all(store.device(d).kind for d in device_ids)  # type: ignore[union-attr]
    assert not await hooks.after_round(config, store, device_ids, finding_ids)  # nothing new

    text = await hooks.write_digest(config, store)
    assert text and (config.report_dir / f"digest-{text.split()[2]}.md").exists()
    assert store.meta_get("digest.latest")
    sugg = await hooks.write_suggestions(config, store)
    assert sugg and "Segmenter IoT" in sugg and (config.report_dir / "suggestions.md").exists()

    config.llm.enabled = False
    assert not await hooks.after_round(config, store, device_ids, finding_ids)
    assert await hooks.write_digest(config, store) is None


def _init(self: OllamaClient, cfg: LlmConfig, fake: FakeOllama) -> None:
    self.cfg = cfg
    self.base_url = cfg.base_url.rstrip("/")
    self._client = fake.client()
    self._think_supported = None


async def test_eval_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = llm_config(tmp_path)
    fake = FakeOllama(smart_handler)
    monkeypatch.setattr(
        OllamaClient, "__init__", lambda self, cfg, client=None: _init(self, cfg, fake)
    )
    report = await run_eval(config, Path("evals/devices.jsonl"))
    assert len(report.results) == 19 and report.errors == 0
    names = {r.name: r for r in report.results}
    assert names["unifi-gateway"].ok and names["synology-nas"].ok and names["bare-mac-no-info"].ok
    assert not names["hp-printer"].ok
    assert "accuracy:" in report.render()


def test_explanation_and_digest_models() -> None:
    e = Explanation(summary=" a ", impact="b", actions=["x"])
    assert e.as_markdown() == "a\n\nb\n\n- x"
    with pytest.raises(ValidationError):
        Explanation(summary="a", impact="b", actions=[])
    d = Digest(summary="s", priorities=[], notes=[])
    assert d.priorities == []


def test_web_digest_page(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from lanwatch.web.app import create_app

    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))
    with Store(config.store_path) as store:
        seed(store, config)
        store.set_device_classification(1, "router", "Gateway for huset.", 0.9)
    client = TestClient(create_app(config))
    r = client.get("/digest")
    assert r.status_code == 200 and "No digest yet" in r.text
    config.report_dir.mkdir(parents=True)
    (config.report_dir / "digest-2026-11-04.md").write_text("# Digest 2026-11-04\n\nAlt vel.\n")
    r = client.get("/digest")
    assert "Alt vel." in r.text and "2026-11-04" in r.text
    assert "Alt vel." in client.get("/").text
    r = client.get("/devices/1")
    assert "Gateway for huset." in r.text and "90% confidence" in r.text
    assert ">router<" in client.get("/devices").text


def test_llm_disabled_leaves_findings_unexplained(store: Store, tmp_path: Path) -> None:
    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))
    _, finding_ids = seed(store, config)
    assert all(not f.explanation for f in store.findings(FindingStatus.OPEN))
    assert finding_ids
