"""LLM tasks. Each has a pydantic output model (also used as the JSON schema Ollama enforces),
a prompt file, and a cache key derived from model + prompt version + input. The LLM never
produces findings or severities; it classifies, explains, summarises and suggests."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta
from enum import StrEnum
from typing import Any, TypeVar

from pydantic import BaseModel, Field, ValidationError

from lanwatch.config import Config
from lanwatch.llm.client import LlmError, LlmUnavailable, OllamaClient
from lanwatch.llm.prompts import load_prompt, render
from lanwatch.models import Device, FindingRow, FindingStatus, ServiceRow, iso, local_str, now_utc
from lanwatch.rules.engine import all_rules
from lanwatch.store import Store

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class DeviceKind(StrEnum):
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    NAS = "nas"
    SERVER = "server"
    VIRTUAL_MACHINE = "virtual_machine"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    PHONE = "phone"
    TABLET = "tablet"
    PRINTER = "printer"
    CAMERA = "camera"
    MEDIA = "media"
    SMART_HOME_HUB = "smart_home_hub"
    IOT = "iot"
    GAME_CONSOLE = "game_console"
    UNKNOWN = "unknown"


class Classification(BaseModel):
    kind: DeviceKind
    description: str = Field(max_length=300)
    vendor_guess: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class Explanation(BaseModel):
    summary: str = Field(max_length=600)
    impact: str = Field(max_length=800)
    actions: list[str] = Field(min_length=1, max_length=6)

    def as_markdown(self) -> str:
        lines = [self.summary.strip(), "", self.impact.strip(), ""]
        lines += [f"- {a.strip()}" for a in self.actions]
        return "\n".join(lines).strip()


class Priority(BaseModel):
    finding_id: str
    reason: str = Field(max_length=300)


class Digest(BaseModel):
    summary: str = Field(max_length=1500)
    priorities: list[Priority] = Field(max_length=5)
    notes: list[str] = Field(max_length=5)


class Suggestion(BaseModel):
    title: str = Field(max_length=120)
    rationale: str = Field(max_length=600)
    effort: str = Field(pattern="^(low|medium|high)$")
    affects: list[str] = Field(max_length=10)


class Suggestions(BaseModel):
    items: list[Suggestion] = Field(min_length=1, max_length=7)


class LlmService:
    """Cache + validation + graceful degradation around the client."""

    def __init__(self, config: Config, store: Store, client: OllamaClient | None = None) -> None:
        self.config = config
        self.store = store
        self.client = client or OllamaClient(config.llm)
        self.calls = 0
        self.cache_hits = 0
        self.unavailable: str | None = None

    async def aclose(self) -> None:
        await self.client.aclose()

    def cache_key(self, prompt_name: str, version: str, payload: dict[str, Any]) -> str:
        raw = json.dumps(
            {
                "m": self.config.llm.model,
                "p": prompt_name,
                "v": version,
                "l": self.config.llm.language,
                "i": payload,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    async def ask(
        self,
        prompt_name: str,
        payload: dict[str, Any],
        model_cls: type[T],
        use_cache: bool = True,
        **render_ctx: Any,
    ) -> T | None:
        """Returns a validated model, or None when the LLM is unavailable or kept failing."""
        if self.unavailable:
            return None
        prompt = load_prompt(prompt_name)
        key = self.cache_key(prompt_name, prompt.version, payload)
        if use_cache:
            cached = self.store.llm_cache_get(key)
            if cached is not None:
                self.cache_hits += 1
                try:
                    return model_cls.model_validate_json(cached)
                except ValidationError:
                    pass  # schema changed; re-ask
        system, user = render(prompt, self.config.llm.language, **payload, **render_ctx)
        schema = model_cls.model_json_schema()
        last_error = ""
        for attempt in range(2):
            try:
                result = await self.client.chat_json(system, user, schema)
            except LlmUnavailable as e:
                self.unavailable = str(e)
                log.warning("LLM unavailable, skipping LLM tasks this round: %s", e)
                return None
            except LlmError as e:
                last_error = str(e)
                log.warning("LLM call failed (%s, attempt %d): %s", prompt_name, attempt + 1, e)
                continue
            self.calls += 1
            try:
                parsed = model_cls.model_validate_json(result.content)
            except ValidationError as e:
                last_error = f"invalid output: {e.errors()[0]['msg'] if e.errors() else e}"
                log.warning("LLM output failed validation (%s): %s", prompt_name, last_error)
                user = user + f"\n\nYour previous answer was invalid ({last_error}). Answer again."
                continue
            self.store.llm_cache_put(key, self.config.llm.model, parsed.model_dump_json())
            log.debug(
                "LLM %s: %d+%d tokens, %.1fs",
                prompt_name,
                result.prompt_tokens,
                result.output_tokens,
                result.duration_s,
            )
            return parsed
        log.warning("giving up on %s: %s", prompt_name, last_error)
        return None


# -- device classification ------------------------------------------------------


def device_facts(d: Device, services: list[ServiceRow]) -> dict[str, Any]:
    """The fingerprint the LLM sees. Also the cache key input, so re-classification happens
    exactly when the facts change."""
    ports = []
    for s in services:
        entry: dict[str, Any] = {"port": f"{s.port}/{s.proto}", "service": s.name}
        if s.product:
            entry["product"] = " ".join(p for p in (s.product, s.version) if p)
        title = s.script("http-title")
        if isinstance(title, dict) and title.get("title"):
            entry["http_title"] = str(title["title"])[:80]
        ports.append(entry)
    return {
        "vendor_from_mac": d.vendor,
        "hostname": d.hostname,
        "mac_prefix": d.mac[:8] if d.mac else None,
        "open_ports": ports,
    }


async def classify_devices(svc: LlmService, device_ids: list[int], budget: int) -> int:
    """Classify devices; returns number of devices updated. Cached inputs cost nothing."""
    updated = 0
    for did in device_ids:
        if svc.calls >= budget:
            log.info("LLM budget for this round reached (%d calls)", budget)
            break
        d = svc.store.device(did)
        if d is None:
            continue
        facts = device_facts(d, svc.store.services(did))
        if not facts["vendor_from_mac"] and not facts["hostname"] and not facts["open_ports"]:
            continue  # nothing to go on
        before = svc.calls
        result = await svc.ask(
            "classify",
            {"facts": json.dumps(facts, ensure_ascii=False, indent=1)},
            Classification,
            kinds=[k.value for k in DeviceKind],
        )
        if result is None:
            if svc.unavailable:
                break
            continue
        changed = svc.store.set_device_classification(
            did, result.kind.value, result.description, result.confidence
        )
        if changed or svc.calls > before:
            updated += 1
    return updated


# -- finding explanations ------------------------------------------------------


def _rule_descriptions() -> dict[str, str]:
    return {r.id: r.description for r in all_rules()}


async def explain_findings(svc: LlmService, finding_ids: list[str], budget: int) -> int:
    rules = _rule_descriptions()
    done = 0
    for fid in finding_ids:
        if svc.calls >= budget:
            log.info("LLM budget for this round reached (%d calls)", budget)
            break
        f = svc.store.finding(fid)
        if f is None or f.explanation:
            continue
        dev = svc.store.device(f.device_id) if f.device_id is not None else None
        payload = {
            "rule_id": f.rule_id,
            "rule_description": rules.get(f.rule_id, ""),
            "title": f.title,
            "severity": f.severity.value,
            "device": _device_line(dev) if dev else "-",
            "evidence": json.dumps(f.evidence, ensure_ascii=False, indent=1),
        }
        result = await svc.ask("explain", payload, Explanation)
        if result is None:
            if svc.unavailable:
                break
            continue
        svc.store.set_explanation(fid, result.as_markdown())
        done += 1
    return done


def _device_line(d: Device) -> str:
    bits = [d.label, d.ip or "", d.vendor or "", d.kind or ""]
    return " ".join(b for b in bits if b)


# -- daily digest --------------------------------------------------------------


async def make_digest(svc: LlmService) -> str | None:
    """Returns the digest as markdown, or None when the LLM is unavailable."""
    store = svc.store
    now = now_utc()
    since = iso(now - timedelta(hours=24))
    devices = store.devices()
    open_f = store.findings(FindingStatus.OPEN)
    acked = store.findings(FindingStatus.ACKED)
    new_devices = store.devices_first_seen_since(since)
    resolved = [f for f in store.findings(FindingStatus.RESOLVED) if f.last_seen >= since]
    new_findings = [f for f in open_f if f.first_seen >= since]
    changes: list[str] = []
    changes += [f"new device: {_device_line(d)}" for d in new_devices]
    changes += [f"new finding: id={f.id} [{f.severity.value}] {f.title}" for f in new_findings]
    changes += [f"resolved: {f.title}" for f in resolved]
    payload = {
        "date": now.astimezone().strftime("%Y-%m-%d"),
        "devices_total": len(devices),
        "devices_online": sum(1 for d in devices if d.online),
        "changes": "\n".join(f"- {c}" for c in changes) or "- nothing changed",
        "findings": [
            {
                "id": f.id,
                "severity": f.severity.value,
                "title": f.title,
                "since": local_str(f.first_seen),
                "acked": f.status is FindingStatus.ACKED,
            }
            for f in [*open_f, *acked]
        ],
    }
    result = await svc.ask("digest", payload, Digest, use_cache=False)
    if result is None:
        return None
    known = {f.id for f in open_f} | {f.id for f in acked}
    by_id = {f.id: f for f in [*open_f, *acked]}
    lines = [f"# Digest {payload['date']}", "", result.summary.strip(), ""]
    prios = [p for p in result.priorities if p.finding_id in known]  # drop invented ids
    if prios:
        lines.append("## Prioritised")
        lines.append("")
        for p in prios:
            f = by_id[p.finding_id]
            lines.append(f"- [{f.severity.value}] {f.title}: {p.reason.strip()} (`{f.id}`)")
        lines.append("")
    if result.notes:
        lines.append("## Notes")
        lines.append("")
        lines += [f"- {n.strip()}" for n in result.notes]
        lines.append("")
    lines.append(f"Devices: {payload['devices_total']} known, {payload['devices_online']} online. ")
    lines.append(f"Open findings: {len(open_f)}, acknowledged: {len(acked)}.")
    return "\n".join(lines)


# -- improvement suggestions ---------------------------------------------------


async def make_suggestions(svc: LlmService) -> Suggestions | None:
    store = svc.store
    services = store.open_services()
    devices = []
    for d in store.devices():
        ports = ", ".join(
            f"{s.port}/{s.proto} {s.name or ''}".strip() for s in services.get(d.id, [])
        )
        devices.append(
            f"{d.label} ip={d.ip or '-'} vendor={d.vendor or '-'} kind={d.kind or '-'}"
            f" {'online' if d.online else 'offline'} ports=[{ports}]"
        )
    by_rule: dict[str, int] = {}
    for f in store.findings(FindingStatus.OPEN):
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    payload = {"devices": devices, "findings_by_rule": json.dumps(by_rule, sort_keys=True)}
    return await svc.ask("suggest", payload, Suggestions, use_cache=True)


def suggestions_markdown(s: Suggestions, date: str) -> str:
    lines = [f"# Improvement suggestions {date}", ""]
    for i, item in enumerate(s.items, 1):
        lines.append(f"## {i}. {item.title.strip()}  (effort: {item.effort})")
        lines.append("")
        lines.append(item.rationale.strip())
        if item.affects:
            lines.append("")
            lines.append("Affects: " + ", ".join(a.strip() for a in item.affects))
        lines.append("")
    return "\n".join(lines)


def describe_finding_row(f: FindingRow) -> str:
    return f"[{f.severity.value}] {f.title}"
