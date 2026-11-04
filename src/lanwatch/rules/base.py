"""Rule interface. Rules are deterministic Python. The LLM never produces findings."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from lanwatch.config import Config
from lanwatch.models import Finding, Kind, Severity
from lanwatch.store import Store


@dataclass(slots=True)
class RuleContext:
    store: Store
    config: Config
    snapshot_id: int
    previous_snapshot_id: int | None
    # True on the very first discovery round: everything is new, nothing is a finding.
    is_baseline: bool
    new_device_ids: list[int] = field(default_factory=list)
    ip_changes: list[tuple[int, str, str]] = field(default_factory=list)


class Rule(ABC):
    id: str
    kind: Kind
    default_severity: Severity
    # Event-like findings (a device appeared) are not auto-resolved on the next round;
    # they are closed by `ack`. State-like findings (a port is open) auto-resolve.
    auto_resolve: bool = True
    description: str = ""

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> list[Finding]: ...

    def finding(
        self,
        ctx: RuleContext,
        *,
        title: str,
        key_parts: list[str],
        device_id: int | None = None,
        evidence: dict[str, object] | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            id=Finding.make_id(self.id, *key_parts),
            rule_id=self.id,
            severity=severity or self.default_severity,
            kind=self.kind,
            title=title,
            device_id=device_id,
            evidence=evidence or {},
        )
