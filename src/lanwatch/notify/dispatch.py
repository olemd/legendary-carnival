"""Builds notifications from scan results and fans them out to enabled channels.

Rules: a finding notifies once when it opens (and again if it reopens after being
resolved). Findings from one round are batched into one message. Severity threshold
per channel, default from notify.min_severity. Every attempt is recorded."""

from __future__ import annotations

import logging
from typing import Any

import httpx2

from lanwatch.config import Config
from lanwatch.models import FindingRow, FindingStatus, Severity, local_str
from lanwatch.notify.channels import (
    Channel,
    EmailChannel,
    HomeAssistantChannel,
    Notification,
    NtfyChannel,
    WebhookChannel,
)
from lanwatch.store import Store

log = logging.getLogger(__name__)


def _make_client() -> httpx2.AsyncClient:
    return httpx2.AsyncClient(timeout=15)


def channels(config: Config) -> list[Channel]:
    n = config.notify
    out: list[Channel] = []
    if n.ntfy.enabled:
        out.append(NtfyChannel(n.ntfy))
    if n.webhook.enabled:
        out.append(WebhookChannel(n.webhook))
    if n.home_assistant.enabled:
        out.append(HomeAssistantChannel(n.home_assistant))
    if n.email.enabled:
        out.append(EmailChannel(n.email))
    return out


def _passes(ch: Channel, config: Config, n: Notification) -> bool:
    if n.severity is None:
        return True  # digest, test
    threshold = ch.min_severity or config.notify.min_severity
    return n.severity.rank <= threshold.rank


async def dispatch(config: Config, store: Store, n: Notification) -> int:
    """Send to every enabled channel that accepts the severity. Returns number delivered."""
    chans = channels(config)
    if not chans:
        return 0
    delivered = 0
    async with _make_client() as client:
        for ch in chans:
            if not _passes(ch, config, n):
                continue
            try:
                await ch.send(n, client)
                store.record_notification(ch.name, n.kind, n.title, True, None)
                delivered += 1
            except Exception as e:
                err = f"{type(e).__name__}: {str(e)[:200]}"
                log.warning("notify via %s failed: %s", ch.name, err)
                store.record_notification(ch.name, n.kind, n.title, False, err)
    return delivered


# -- builders -------------------------------------------------------------------


def _summary_line(f: FindingRow) -> str:
    first = (f.explanation or "").split("\n\n", 1)[0].strip()
    line = f"[{f.severity.value}] {f.title}"
    return f"{line}\n  {first}" if first else line


def findings_notification(findings: list[FindingRow], kind: str = "finding.new") -> Notification:
    top = min(f.severity.rank for f in findings)
    severity = list(Severity)[top]
    if kind == "finding.resolved":
        title = (
            f"lanwatch: resolved: {findings[0].title}"
            if len(findings) == 1
            else f"lanwatch: {len(findings)} findings resolved"
        )
        body = "\n".join(f"[{f.severity.value}] {f.title}" for f in findings)
    else:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        if len(findings) == 1:
            title = f"lanwatch [{severity.value}]: {findings[0].title}"
        else:
            detail = ", ".join(f"{v} {k}" for k, v in counts.items())
            title = f"lanwatch: {len(findings)} new findings ({detail})"
        body = "\n".join(_summary_line(f) for f in findings)
    return Notification(kind=kind, title=title, body=body, severity=severity, findings=findings)


def _by_severity(findings: list[FindingRow]) -> list[FindingRow]:
    return sorted(findings, key=lambda f: f.severity.rank)


async def after_round(
    config: Config, store: Store, new_ids: list[str], resolved_ids: list[str]
) -> None:
    """Called at the end of every discovery/inventory round."""
    try:
        if new_ids:
            rows = [f for fid in new_ids if (f := store.finding(fid)) is not None]
            rows = [f for f in rows if f.status is FindingStatus.OPEN]
            if rows:
                await dispatch(config, store, findings_notification(_by_severity(rows)))
        if resolved_ids and config.notify.resolved:
            rows = [f for fid in resolved_ids if (f := store.finding(fid)) is not None]
            if rows:
                await dispatch(
                    config, store, findings_notification(_by_severity(rows), "finding.resolved")
                )
        await publish_state(config, store)
    except Exception:
        log.exception("notification step failed; continuing")


async def publish_state(config: Config, store: Store) -> None:
    """Home Assistant sensors, updated every round regardless of findings."""
    ha = config.notify.home_assistant
    if not (ha.enabled and ha.publish_sensors):
        return
    summary = state_summary(store)
    async with _make_client() as client:
        try:
            await HomeAssistantChannel(ha).publish_state(summary, client)
        except Exception as e:
            log.warning(
                "home assistant sensor update failed: %s: %s", type(e).__name__, str(e)[:200]
            )


def state_summary(store: Store) -> dict[str, Any]:
    devices = store.devices()
    open_f = store.findings(FindingStatus.OPEN)
    by_sev = {s.value: sum(1 for f in open_f if f.severity is s) for s in Severity}
    disc = store.latest_snapshot("discovery")
    inv = store.latest_snapshot("inventory")
    return {
        "devices_online": sum(1 for d in devices if d.online),
        "devices_known": len(devices),
        "open_findings": len(open_f),
        "by_severity": by_sev,
        "last_discovery": local_str(disc.finished_at) if disc else None,
        "last_inventory": local_str(inv.finished_at) if inv else None,
    }


async def digest(config: Config, store: Store, text: str) -> None:
    if not config.notify.digest:
        return
    day = text.split("\n", 1)[0].removeprefix("# Digest ").strip()
    body = text.split("\n", 1)[1].strip() if "\n" in text else text
    try:
        await dispatch(config, store, Notification("digest", f"lanwatch digest {day}", body))
    except Exception:
        log.exception("digest notification failed")


async def test_message(config: Config, store: Store) -> int:
    n = Notification(
        "test",
        "lanwatch: test notification",
        "If you can read this, the channel works. Nothing is wrong with your network.",
    )
    return await dispatch(config, store, n)
