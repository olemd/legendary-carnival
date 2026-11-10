"""Checks that work on any device read over SNMP (see docs/snmp.md): its clock, and
whether it can be read at all. They read the target rows the infra round stores (infra
kind snmp-target); with no SNMP targets configured there are no rows and nothing fires."""

from __future__ import annotations

from typing import Any

from lanwatch.models import Finding, Kind, Severity
from lanwatch.rules.base import Rule, RuleContext

SKEW_LOW_S = 120
SKEW_MEDIUM_S = 3600
UNREACHABLE_AFTER = 3


def _dict(v: object) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _targets(ctx: RuleContext) -> list[dict[str, Any]]:
    return [r.data for r in ctx.store.infra("snmp-target") if r.data.get("host")]


def _label(ctx: RuleContext, t: dict[str, Any]) -> tuple[str, int | None]:
    host = str(t.get("host"))
    d = ctx.store.device_by_ip(host)
    system = _dict(t.get("system"))
    name = t.get("name") or system.get("name") or (d.label if d else "")
    return (f"{name} ({host})" if name and name != host else host), (d.id if d else None)


def _duration(seconds: float) -> str:
    s = abs(seconds)
    if s < 3600:
        return f"{s / 60:.0f} min"
    if s < 86400:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} days"


def classify_skew(offset_s: float, has_offset: bool) -> tuple[Severity, bool] | None:
    """None when the clock is close enough; else (severity, whole_hours). whole_hours: a
    time without a zone that is off by whole hours (within the tolerance), which is a time
    zone or DST setting rather than a wrong clock."""
    off = abs(offset_s)
    if off <= SKEW_LOW_S:
        return None
    if not has_offset:
        rest = off % 3600
        if min(rest, 3600 - rest) <= SKEW_LOW_S:
            return Severity.LOW, True
    return (Severity.MEDIUM if off > SKEW_MEDIUM_S else Severity.LOW), False


class SnmpClockSkewRule(Rule):
    id = "snmp.clock-skew"
    kind = Kind.PROBLEM
    default_severity = Severity.LOW
    description = (
        "A device read over SNMP keeps a clock more than 2 minutes off lanwatch's own "
        "(medium beyond an hour). A wrong clock makes its logs hard to line up with "
        "anything else and can break certificate checks; point it at an NTP server. A "
        "device that gives local time without a zone and is off by whole hours has a time "
        "zone or summer time setting wrong instead."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for t in _targets(ctx):
            if int(t.get("fails") or 0) > 0:
                continue  # stale: the unreachable rule speaks for it
            facts = _dict(t.get("facts"))
            clock = _dict(facts.get("clock"))
            if not isinstance(clock.get("offset_s"), int | float):
                continue
            offset = float(clock["offset_s"])
            verdict = classify_skew(offset, bool(clock.get("has_offset")))
            if verdict is None:
                continue
            severity, whole_hours = verdict
            label, device_id = _label(ctx, t)
            way = "ahead" if offset > 0 else "behind"
            if whole_hours:
                hours = round(abs(offset) / 3600)
                title = f"{label}: clock {hours} h {way}, a time zone or summer time setting"
            else:
                title = f"{label}: clock {_duration(offset)} {way}"
            out.append(
                self.finding(
                    ctx,
                    title=title,
                    key_parts=[str(t["host"])],
                    device_id=device_id,
                    severity=severity,
                    evidence={
                        "host": t["host"],
                        "offset_s": offset,
                        "device_time": clock.get("device_time"),
                        "read_at": clock.get("read_at"),
                        "source": clock.get("source"),
                    },
                )
            )
        return out


class SnmpUnreachableRule(Rule):
    id = "snmp.unreachable"
    kind = Kind.PROBLEM
    default_severity = Severity.LOW
    description = (
        "A device configured for SNMP ([snmp.devices]) could not be read "
        f"{UNREACHABLE_AFTER} rounds in a row; medium for the router. One never read at all "
        "usually has a login or access-list problem; docs/snmp.md has the usual causes."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for t in _targets(ctx):
            fails = int(t.get("fails") or 0)
            if fails < UNREACHABLE_AFTER:
                continue
            label, device_id = _label(ctx, t)
            never = not t.get("last_ok")
            title = (
                f"SNMP: {label} never read"
                if never
                else f"SNMP: {label} not read for {fails} rounds"
            )
            out.append(
                self.finding(
                    ctx,
                    title=title,
                    key_parts=[str(t["host"])],
                    device_id=device_id,
                    severity=Severity.MEDIUM if t.get("role") == "router" else Severity.LOW,
                    evidence={
                        "host": t["host"],
                        "role": t.get("role"),
                        "failed_reads": fails,
                        "last_error": t.get("last_error"),
                        "last_good_read": t.get("last_ok"),
                        "help": "docs/snmp.md, Troubleshooting",
                    },
                )
            )
        return out


RULES: list[Rule] = [SnmpClockSkewRule(), SnmpUnreachableRule()]
