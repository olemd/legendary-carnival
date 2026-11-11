"""Typed observations and findings shared across collectors, store, rules and output."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Kind(StrEnum):
    SECURITY = "security"
    PROBLEM = "problem"
    IMPROVEMENT = "improvement"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKED = "acked"
    RESOLVED = "resolved"


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat()


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def local_str(s: str | None) -> str:
    """ISO UTC string -> local time, 24h clock, minute resolution."""
    if not s:
        return "-"
    return parse_iso(s).astimezone().strftime("%Y-%m-%d %H:%M")


def is_private_mac(mac: str | None) -> bool:
    """True when the locally-administered bit of the first octet is set (x2, x6, xA, xE)."""
    try:
        return mac is not None and bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = mac.strip().lower().replace("-", ":")
    if len(cleaned) == 12 and ":" not in cleaned:
        cleaned = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    parts = cleaned.split(":")
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        return None
    return cleaned


class HostObservation(BaseModel):
    """One host seen by a discovery backend."""

    model_config = ConfigDict(frozen=True)

    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    source: str

    @field_validator("mac", mode="before")
    @classmethod
    def _norm_mac(cls, v: str | None) -> str | None:
        return normalize_mac(v)

    @field_validator("hostname", "vendor", mode="before")
    @classmethod
    def _empty_to_none(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None

    @property
    def key(self) -> str:
        """Stable device identity: MAC when known, else the IP."""
        return self.mac if self.mac else f"ip:{self.ip}"


class Finding(BaseModel):
    """Output of a rule. Severity is set by the rule, never by the LLM."""

    id: str
    rule_id: str
    severity: Severity
    kind: Kind
    title: str
    device_id: int | None = None
    evidence: dict[str, Any] = {}

    @staticmethod
    def make_id(rule_id: str, *parts: str) -> str:
        h = hashlib.sha256("\x1f".join([rule_id, *parts]).encode()).hexdigest()
        return h[:16]


@dataclass(slots=True)
class Device:
    id: int
    key: str
    mac: str | None
    ip: str | None
    hostname: str | None
    vendor: str | None
    name: str | None
    kind: str | None
    description: str | None
    kind_confidence: float | None
    first_seen: str
    last_seen: str
    online: bool
    attrs: dict[str, Any] = field(default_factory=dict)
    # Kind and description were set by a person; the LLM classification leaves them alone.
    kind_manual: bool = False
    # A person asked to be told when this device drops off the network.
    watch: bool = False

    @property
    def label(self) -> str:
        return self.name or self.hostname or self.vendor or self.key

    @property
    def private_mac(self) -> bool:
        """A locally administered ("randomised") MAC address: phones and laptops make one up
        per network, and may change it, so such a device can reappear as a new one."""
        return is_private_mac(self.mac)


@dataclass(slots=True)
class FindingRow:
    id: str
    rule_id: str
    severity: Severity
    kind: Kind
    title: str
    device_id: int | None
    evidence: dict[str, Any]
    first_seen: str
    last_seen: str
    status: FindingStatus
    explanation: str | None
    # Accepted: a person decided this is intended and said why. It then stays acknowledged
    # for good, also if the condition goes away and comes back.
    accepted: bool = False
    note: str | None = None


@dataclass(slots=True)
class ServiceRow:
    id: int
    device_id: int
    port: int
    proto: str
    state: str
    name: str | None
    product: str | None
    version: str | None
    extrainfo: str | None
    tunnel: str | None
    details: dict[str, Any]
    first_seen: str
    last_seen: str

    @property
    def label(self) -> str:
        bits = [p for p in (self.product, self.version) if p]
        base = f"{self.port}/{self.proto}"
        if self.name:
            base += f" {self.name}"
        return base + (f" ({' '.join(bits)})" if bits else "")

    def script(self, script_id: str) -> Any:
        s = self.details.get(script_id)
        return s.get("data") if isinstance(s, dict) else None


@dataclass(slots=True)
class ServiceDiff:
    device_id: int
    first_scan: bool
    opened: list[tuple[int, str]] = field(default_factory=list)
    closed: list[tuple[int, str]] = field(default_factory=list)


@dataclass(slots=True)
class EventRow:
    id: int
    ts: str
    kind: str
    device_id: int | None
    finding_id: str | None
    summary: str
    data: dict[str, Any]


@dataclass(slots=True)
class InfraRow:
    kind: str
    key: str
    data: dict[str, Any]
    first_seen: str
    last_seen: str


@dataclass(slots=True)
class NotificationRow:
    id: int
    ts: str
    channel: str
    kind: str
    title: str
    ok: bool
    error: str | None


@dataclass(slots=True)
class Snapshot:
    id: int
    kind: str
    source: str
    started_at: str
    finished_at: str | None
    host_count: int


@dataclass(slots=True)
class LinkRow:
    """Two devices that belong together without being one: `a` manages, hangs off or is
    powered by `b`, depending on `kind`. A dismissed row is a suggestion someone turned
    down, or a link someone removed; it is kept so the suggestion does not come back."""

    id: int
    a_id: int
    b_id: int
    kind: str
    source: str
    created: str
    dismissed: bool
