"""Where the pipeline hands work to the LLM. Everything here is best-effort: when Ollama is
down the scan results are unaffected and the LLM catches up on the next round."""

from __future__ import annotations

import logging
import time
from datetime import datetime

from lanwatch.config import Config
from lanwatch.llm.tasks import (
    LlmService,
    answer_question,
    classify_devices,
    explain_findings,
    make_digest,
    make_suggestions,
    suggestions_markdown,
)
from lanwatch.store import Store

log = logging.getLogger(__name__)
_last_unavailable_log = 0.0


def _note_unavailable(svc: LlmService) -> None:
    global _last_unavailable_log
    if svc.unavailable and time.monotonic() - _last_unavailable_log > 3600:
        _last_unavailable_log = time.monotonic()
        log.warning("LLM features paused: %s", svc.unavailable)


async def after_round(
    config: Config, store: Store, device_ids: list[int], finding_ids: list[str]
) -> bool:
    """Classify the given devices and explain the given findings. Returns True if the
    store changed (so the overview should be regenerated)."""
    if not config.llm.enabled or (not device_ids and not finding_ids):
        return False
    svc = LlmService(config, store)
    try:
        budget = config.llm.max_calls_per_round
        n_dev = await classify_devices(svc, device_ids, budget)
        n_exp = await explain_findings(svc, finding_ids, budget)
        _note_unavailable(svc)
        if svc.calls or n_dev or n_exp:
            log.info(
                "LLM: %d devices classified, %d findings explained (%d calls, %d cache hits)",
                n_dev,
                n_exp,
                svc.calls,
                svc.cache_hits,
            )
        return bool(n_dev or n_exp)
    except Exception:
        log.exception("LLM step failed; continuing without it")
        return False
    finally:
        await svc.aclose()


async def catch_up(config: Config, store: Store) -> bool:
    """Explain open findings and classify devices that have none yet (budget-limited)."""
    if not config.llm.enabled:
        return False
    unexplained = [
        f.id for f in store.findings(None) if not f.explanation and f.status.value != "resolved"
    ]
    unclassified = [d.id for d in store.devices() if not d.kind]
    return await after_round(config, store, unclassified, unexplained)


async def write_digest(config: Config, store: Store, when: datetime | None = None) -> str | None:
    if not config.llm.enabled:
        return None
    svc = LlmService(config, store)
    try:
        text = await make_digest(svc)
        _note_unavailable(svc)
        if text is None:
            return None
        day = (when or datetime.now()).astimezone().strftime("%Y-%m-%d")
        path = config.report_dir / f"digest-{day}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")
        store.meta_set("digest.latest", str(path))
        log.info("digest written: %s", path)
        return text
    finally:
        await svc.aclose()


async def ask(
    config: Config, store: Store, question: str, history: list[dict[str, str]] | None = None
) -> str | None:
    if not config.llm.enabled:
        return None
    svc = LlmService(config, store)
    try:
        answer = await answer_question(svc, question, history)
        _note_unavailable(svc)
        return answer
    finally:
        await svc.aclose()


async def write_suggestions(config: Config, store: Store) -> str | None:
    if not config.llm.enabled:
        return None
    svc = LlmService(config, store)
    try:
        result = await make_suggestions(svc)
        _note_unavailable(svc)
        if result is None:
            return None
        day = datetime.now().astimezone().strftime("%Y-%m-%d")
        text = suggestions_markdown(result, day)
        path = config.report_dir / "suggestions.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")
        store.meta_set("suggestions.latest", str(path))
        return text
    finally:
        await svc.aclose()
