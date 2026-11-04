"""Golden-set evaluation for device classification. Lets you compare models on the exact
task lanwatch uses them for, before changing llm.model."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from lanwatch.config import Config
from lanwatch.llm.client import LlmError, OllamaClient
from lanwatch.llm.prompts import load_prompt, render
from lanwatch.llm.tasks import Classification, DeviceKind
from lanwatch.store import Store


@dataclass(slots=True)
class EvalCase:
    name: str
    facts: dict[str, Any]
    expected: str
    accept: set[str]


@dataclass(slots=True)
class EvalResult:
    name: str
    expected: str
    got: str | None
    ok: bool
    seconds: float
    error: str | None = None


@dataclass(slots=True)
class EvalReport:
    model: str
    results: list[EvalResult] = field(default_factory=list)

    @property
    def correct(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.error)

    def render(self) -> str:
        n = len(self.results)
        lines = [f"model: {self.model}"]
        for r in self.results:
            mark = "ok " if r.ok else ("ERR" if r.error else "   ")
            err = f"  {r.error}" if r.error else ""
            lines.append(
                f"  {mark} {r.name:<28} expected {r.expected:<16} got {r.got or '-':<16}"
                f" {r.seconds:5.1f}s{err}"
            )
        if n:
            secs = sum(r.seconds for r in self.results)
            lines.append(
                f"accuracy: {self.correct}/{n} ({self.correct / n:.0%}), errors: {self.errors}, "
                f"avg {secs / n:.1f}s, total {secs:.0f}s"
            )
        return "\n".join(lines)


def load_cases(path: Path) -> list[EvalCase]:
    cases: list[EvalCase] = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        d = json.loads(line)
        accept = set(d.get("accept", [])) | {d["expected"]}
        cases.append(EvalCase(d["name"], d["facts"], d["expected"], accept))
    return cases


@dataclass(slots=True)
class ChatCase:
    name: str
    question: str
    expect_tools: list[str]
    expect_text: list[str]
    forbid_tools: list[str]


@dataclass(slots=True)
class ChatResultRow:
    name: str
    tools_called: list[str]
    ok: bool
    seconds: float
    answer: str
    error: str | None = None


@dataclass(slots=True)
class ChatReport:
    model: str
    results: list[ChatResultRow] = field(default_factory=list)

    @property
    def correct(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.error)

    def render(self) -> str:
        n = len(self.results)
        lines = [f"chat suite, model: {self.model}"]
        for r in self.results:
            mark = "ok " if r.ok else ("ERR" if r.error else "   ")
            tools = ",".join(r.tools_called) or "-"
            lines.append(f"  {mark} {r.name:<28} tools={tools:<40} {r.seconds:5.1f}s")
            if not r.ok:
                lines.append(
                    f"      answer: {r.answer[:160]!r}" + (f"  error: {r.error}" if r.error else "")
                )
        if n:
            secs = sum(r.seconds for r in self.results)
            lines.append(
                f"chat accuracy: {self.correct}/{n} ({self.correct / n:.0%}),"
                f" errors: {self.errors}, avg {secs / n:.1f}s"
            )
        return "\n".join(lines)


def load_chat_cases(path: Path) -> list[ChatCase]:
    cases: list[ChatCase] = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        d = json.loads(line)
        cases.append(
            ChatCase(
                d["name"],
                d["question"],
                d.get("expect_tools", []),
                d.get("expect_text", []),
                d.get("forbid_tools", []),
            )
        )
    return cases


def seed_eval_store(store: Store) -> None:
    """A small, fixed network for the chat suite, built from the test fixture."""
    from lanwatch.collectors.services import parse_nmap_xml_services
    from lanwatch.models import HostObservation
    from lanwatch.rules.base import RuleContext
    from lanwatch.rules.engine import Engine

    fixture = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "nmap-services.xml"
    if not fixture.exists():
        fixture = Path("/app/evals/nmap-services.xml")
    res = parse_nmap_xml_services(fixture.read_text())
    sid = store.begin_snapshot("discovery", "eval")
    hosts = [
        HostObservation(
            ip=h.ip,
            mac=h.mac,
            vendor="Ubiquiti" if h.mac else None,
            hostname="gateway.lan" if h.mac else "nas",
            source="eval",
        )
        for h in res.hosts
    ]
    hosts.append(
        HostObservation(
            ip="192.168.1.77",
            mac="aa:bb:cc:00:00:77",
            vendor="Apple",
            hostname="iPhone",
            source="eval",
        )
    )
    rec = store.record_hosts(sid, hosts)
    store.finish_snapshot(sid, len(hosts))
    inv = store.begin_snapshot("inventory", "eval")
    diffs = {
        d: store.record_services(inv, d, h.ports, res.scanned)
        for h, d in zip(res.hosts, rec.new_device_ids, strict=False)
    }
    store.finish_snapshot(inv, len(diffs))
    store.set_device_name(rec.new_device_ids[0], "Router")
    cfg = Config(data_dir=Path("/nonexistent"))
    Engine(cfg).run(
        RuleContext(
            store=store,
            config=cfg,
            snapshot_id=inv,
            previous_snapshot_id=None,
            is_baseline=False,
            service_diffs=diffs,
        )
    )


async def run_chat_eval(config: Config, path: Path) -> ChatReport:
    from lanwatch.llm.tasks import LlmService, answer_question
    from lanwatch.store import Store

    cases = load_chat_cases(path)
    report = ChatReport(model=config.llm.model)
    for c in cases:
        store = Store.memory()
        seed_eval_store(store)
        svc = LlmService(config, store)
        t0 = time.monotonic()
        try:
            ans = await answer_question(svc, c.question, allow_actions=True)
            err = None if ans is not None else (svc.unavailable or "no answer")
        except Exception as e:
            ans, err = None, str(e)[:120]
        finally:
            await svc.aclose()
            store.close()
        called = [t["name"] for t in ans.tools] if ans else []
        text = ans.text if ans else ""
        ok = (
            ans is not None
            and all(t in called for t in c.expect_tools)
            and not any(t in called for t in c.forbid_tools)
            and all(s.lower() in text.lower() for s in c.expect_text)
        )
        report.results.append(ChatResultRow(c.name, called, ok, time.monotonic() - t0, text, err))
    return report


async def run_eval(config: Config, path: Path) -> EvalReport:
    cases = load_cases(path)
    client = OllamaClient(config.llm)
    prompt = load_prompt("classify")
    schema = Classification.model_json_schema()
    report = EvalReport(model=config.llm.model)
    try:
        for c in cases:
            system, user = render(
                prompt,
                config.llm.language,
                facts=json.dumps(c.facts, ensure_ascii=False, indent=1),
                kinds=[k.value for k in DeviceKind],
            )
            t0 = time.monotonic()
            try:
                res = await client.chat_json(system, user, schema)
                parsed = Classification.model_validate_json(res.content)
                got: str | None = parsed.kind.value
                err = None
            except (LlmError, ValidationError) as e:
                got, err = None, str(e)[:120]
            report.results.append(
                EvalResult(c.name, c.expected, got, got in c.accept, time.monotonic() - t0, err)
            )
    finally:
        await client.aclose()
    return report
