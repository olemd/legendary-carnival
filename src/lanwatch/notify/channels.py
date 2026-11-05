"""Notification channels. Each one turns a Notification into one outbound call. Failures
raise; the dispatcher logs and records them, scanning is never affected."""

from __future__ import annotations

import asyncio
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Protocol

import httpx2

from lanwatch.config import (
    EmailConfig,
    HomeAssistantConfig,
    NtfyConfig,
    WebhookConfig,
)
from lanwatch.models import FindingRow, Severity, iso, now_utc


@dataclass(slots=True)
class Notification:
    kind: str  # finding.new | finding.resolved | digest | test
    title: str
    body: str
    severity: Severity | None = None
    findings: list[FindingRow] = field(default_factory=list)

    def payload(self) -> dict[str, Any]:
        return {
            "event": self.kind,
            "title": self.title,
            "text": self.body,
            "severity": self.severity.value if self.severity else None,
            "ts": iso(now_utc()),
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "device_id": f.device_id,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }


class Channel(Protocol):
    name: str
    min_severity: Severity | None

    async def send(self, n: Notification, client: httpx2.AsyncClient) -> None: ...


NTFY_PRIORITY = {
    Severity.CRITICAL: "5",
    Severity.HIGH: "4",
    Severity.MEDIUM: "3",
    Severity.LOW: "2",
    Severity.INFO: "1",
}


class NtfyChannel:
    name = "ntfy"

    def __init__(self, cfg: NtfyConfig) -> None:
        self.cfg = cfg
        self.min_severity = cfg.min_severity

    async def send(self, n: Notification, client: httpx2.AsyncClient) -> None:
        headers = {
            "Title": n.title,
            "Priority": NTFY_PRIORITY.get(n.severity, "3") if n.severity else "3",
            "Tags": "warning" if n.kind == "finding.new" else "page_facing_up",
        }
        if self.cfg.token:
            headers["Authorization"] = f"Bearer {self.cfg.token}"
        r = await client.post(
            f"{self.cfg.url.rstrip('/')}/{self.cfg.topic}", content=n.body.encode(), headers=headers
        )
        r.raise_for_status()


class WebhookChannel:
    name = "webhook"

    def __init__(self, cfg: WebhookConfig) -> None:
        self.cfg = cfg
        self.min_severity = cfg.min_severity

    async def send(self, n: Notification, client: httpx2.AsyncClient) -> None:
        r = await client.post(self.cfg.url, json=n.payload(), headers=self.cfg.headers)
        r.raise_for_status()


class HomeAssistantChannel:
    """Calls a notify service, and optionally publishes lanwatch counters as sensors."""

    name = "home_assistant"

    def __init__(self, cfg: HomeAssistantConfig) -> None:
        self.cfg = cfg
        self.min_severity = cfg.min_severity

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.cfg.token}", "Content-Type": "application/json"}

    async def send(self, n: Notification, client: httpx2.AsyncClient) -> None:
        domain, _, service = self.cfg.service.partition(".")
        r = await client.post(
            f"{self.cfg.url.rstrip('/')}/api/services/{domain}/{service}",
            json={"title": n.title, "message": n.body, "data": {"lanwatch": n.payload()}},
            headers=self._headers(),
        )
        r.raise_for_status()

    async def publish_state(self, summary: dict[str, Any], client: httpx2.AsyncClient) -> None:
        """sensor.lanwatch_* entities via the states API (dashboard-friendly, not persisted
        across HA restarts; HA re-creates them on the next update)."""
        base = f"{self.cfg.url.rstrip('/')}/api/states/"
        entities = {
            "sensor.lanwatch_devices_online": (
                summary["devices_online"],
                {"friendly_name": "lanwatch devices online", "icon": "mdi:lan"},
            ),
            "sensor.lanwatch_devices_known": (
                summary["devices_known"],
                {"friendly_name": "lanwatch devices known", "icon": "mdi:lan"},
            ),
            "sensor.lanwatch_open_findings": (
                summary["open_findings"],
                {
                    "friendly_name": "lanwatch open findings",
                    "icon": "mdi:shield-alert",
                    **{f"open_{k}": v for k, v in summary["by_severity"].items()},
                    "last_discovery": summary.get("last_discovery"),
                    "last_inventory": summary.get("last_inventory"),
                },
            ),
        }
        for entity, (state, attrs) in entities.items():
            r = await client.post(
                base + entity, json={"state": state, "attributes": attrs}, headers=self._headers()
            )
            r.raise_for_status()


class EmailChannel:
    name = "email"

    def __init__(self, cfg: EmailConfig) -> None:
        self.cfg = cfg
        self.min_severity = cfg.min_severity

    def _send_sync(self, n: Notification) -> None:
        msg = EmailMessage()
        msg["Subject"] = n.title
        msg["From"] = self.cfg.sender
        msg["To"] = ", ".join(self.cfg.to)
        msg.set_content(n.body)
        with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=20) as s:
            if self.cfg.starttls:
                s.starttls()
            if self.cfg.username:
                s.login(self.cfg.username, self.cfg.password or "")
            s.send_message(msg)

    async def send(self, n: Notification, client: httpx2.AsyncClient) -> None:
        await asyncio.to_thread(self._send_sync, n)
