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
