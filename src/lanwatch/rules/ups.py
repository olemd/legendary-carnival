"""UPS rules, from what the `ups` SNMP reader (collectors/snmp_ups.py) stored on each
target. Only targets whose last read succeeded count: a UPS that cannot be read is
the unreachable rule's business, and its old values must not pass for current ones.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from lanwatch.models import Finding, Kind, Severity
from lanwatch.rules.base import Rule, RuleContext

# Minutes of runtime left below which the battery counts as low.
LOW_RUNTIME_MIN = 10
# A self-test older than this many times its schedule is overdue.
SELF_TEST_GRACE = 2
# Alarms with a rule of their own; ups.alarm reports the others.
COVERED_ALARMS = {
    "on battery",
    "low battery",
    "depleted battery",
    "battery bad",
    "test in progress",
    "communications lost",
}


def ups_targets(ctx: RuleContext) -> list[tuple[dict[str, Any], dict[str, Any], int | None]]:
    """(target row, ups facts, device id) for every configured target that was read this
    time and is a UPS."""
    hosts = {t.host for t in ctx.config.snmp.targets()}
    out: list[tuple[dict[str, Any], dict[str, Any], int | None]] = []
    for r in ctx.store.infra("snmp-target"):
        data = r.data
        if data.get("role") == "device" and data.get("host") not in hosts:
            continue
        if data.get("last_error"):
            continue
        facts = (data.get("facts") or {}).get("ups")
        if not isinstance(facts, dict) or not facts:
            continue
        host = str(data.get("host") or r.key)
        d = ctx.store.device_by_ip(host)
        out.append((data, facts, d.id if d else None))
    return out


def label(data: dict[str, Any], facts: dict[str, Any]) -> str:
    name = data.get("name") or facts.get("name") or facts.get("model") or "UPS"
    return f"{name} ({data.get('host')})"


def _reads_ups(facts: dict[str, Any]) -> bool:
    """False when the card says it has lost the UPS: its values are then stale."""
    return facts.get("communication_ok") is not False


class UpsNoCommunicationRule(Rule):
    id = "ups.no-communication"
    kind = Kind.PROBLEM
    default_severity = Severity.HIGH
    description = (
        "The UPS card has lost the UPS. It answers, but says it cannot talk to the UPS "
        "itself (PowerNet upsCommStatus); nothing it reports about power or battery is "
        "current, so the other UPS rules stay quiet until it can."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        return [
            self.finding(
                ctx,
                title=f"{label(data, facts)}: the card has lost contact with the UPS",
                key_parts=[str(data.get("host"))],
                device_id=did,
                evidence={"host": data.get("host"), "model": facts.get("model")},
            )
            for data, facts, did in ups_targets(ctx)
            if facts.get("communication_ok") is False
        ]


class UpsOnBatteryRule(Rule):
    id = "ups.on-battery"
    kind = Kind.PROBLEM
    default_severity = Severity.HIGH
    description = "UPS on battery. Mains power is gone or out of range."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for data, facts, did in ups_targets(ctx):
            if not _reads_ups(facts) or facts.get("on_battery") is not True:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{label(data, facts)} is on battery"
                    + (
                        f", {facts['runtime_min']} min left"
                        if facts.get("runtime_min") is not None
                        else ""
                    ),
                    key_parts=[str(data.get("host"))],
                    device_id=did,
                    evidence=_power_evidence(facts),
                )
            )
        return out


class UpsBatteryLowRule(Rule):
    id = "ups.battery-low"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        f"UPS battery low. The battery is low or depleted, or the runtime the UPS "
        f"estimates is under {LOW_RUNTIME_MIN} minutes. Critical while on battery: the load "
        f"will go down soon."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for data, facts, did in ups_targets(ctx):
            if not _reads_ups(facts):
                continue
            status = facts.get("battery_status")
            runtime = facts.get("runtime_min")
            low_runtime = isinstance(runtime, int) and runtime < LOW_RUNTIME_MIN
            if status not in ("low", "depleted") and not low_runtime:
                continue
            why = f"battery {status}" if status in ("low", "depleted") else f"{runtime} min left"
            out.append(
                self.finding(
                    ctx,
                    title=f"{label(data, facts)}: {why}",
                    key_parts=[str(data.get("host"))],
                    device_id=did,
                    evidence=_power_evidence(facts),
                    severity=Severity.CRITICAL if facts.get("on_battery") else None,
                )
            )
        return out


class UpsBatteryReplaceRule(Rule):
    id = "ups.battery-replace"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "UPS battery due. The UPS says its battery needs replacing (the replace-battery "
        "indicator, or a battery-bad alarm), or the replacement date it recommends has "
        "passed."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        today = datetime.now(UTC).date().isoformat()
        out: list[Finding] = []
        for data, facts, did in ups_targets(ctx):
            if not _reads_ups(facts):
                continue
            reasons: list[str] = []
            if facts.get("battery_replace") is True:
                reasons.append("the UPS says the battery needs replacing")
            if "battery bad" in (facts.get("alarms") or []):
                reasons.append("battery-bad alarm")
            due = facts.get("battery_replace_by")
            if isinstance(due, str) and due <= today:
                reasons.append(f"recommended replacement date {due} has passed")
            if not reasons:
                continue
            cartridge = facts.get("battery_cartridge")
            out.append(
                self.finding(
                    ctx,
                    title=f"{label(data, facts)}: replace the battery"
                    + (f" ({cartridge})" if cartridge else ""),
                    key_parts=[str(data.get("host"))],
                    device_id=did,
                    evidence={
                        "reasons": reasons,
                        "cartridge": cartridge,
                        "last_replaced": facts.get("battery_last_replaced"),
                        "replace_by": due,
                    },
                )
            )
        return out


class UpsAlarmRule(Rule):
    id = "ups.alarm"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "UPS alarm. An alarm in the UPS-MIB alarm table other than the ones with a rule "
        "of their own (on battery, low battery, battery bad)."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for data, facts, did in ups_targets(ctx):
            if not _reads_ups(facts):
                continue
            alarms = [a for a in facts.get("alarms") or [] if a not in COVERED_ALARMS]
            if not alarms:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{label(data, facts)}: {', '.join(alarms)}",
                    key_parts=[str(data.get("host"))],
                    device_id=did,
                    evidence={"alarms": alarms},
                )
            )
        return out


class UpsSelfTestRule(Rule):
    id = "ups.self-test-stale"
    kind = Kind.IMPROVEMENT
    default_severity = Severity.LOW
    description = (
        "UPS self-test failed or overdue. Failed is medium; older than twice the UPS's "
        "own test schedule is low: a battery that has not been tested may not hold when "
        "needed."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        today = datetime.now(UTC).date()
        out: list[Finding] = []
        for data, facts, did in ups_targets(ctx):
            if not _reads_ups(facts):
                continue
            result = facts.get("self_test_result")
            tested = facts.get("self_test_date")
            every = facts.get("self_test_every_days")
            evidence = {"result": result, "date": tested, "schedule_days": every}
            key = [str(data.get("host"))]
            if result == "failed":
                out.append(
                    self.finding(
                        ctx,
                        title=f"{label(data, facts)}: the last self-test failed"
                        + (f" ({tested})" if tested else ""),
                        key_parts=key,
                        device_id=did,
                        evidence=evidence,
                        severity=Severity.MEDIUM,
                    )
                )
                continue
            if not isinstance(tested, str) or not isinstance(every, int):
                continue
            age = (today - datetime.fromisoformat(tested).date()).days
            if age > SELF_TEST_GRACE * every:
                out.append(
                    self.finding(
                        ctx,
                        title=f"{label(data, facts)}: last self-test {age} days ago, "
                        f"scheduled every {every}",
                        key_parts=key,
                        device_id=did,
                        evidence=evidence | {"age_days": age},
                    )
                )
        return out


class UpsPowerEventRule(Rule):
    id = "ups.power-event"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    # An event: it stays after the power is back, until acknowledged.
    auto_resolve = False
    description = (
        "UPS outage. Unlike ups.on-battery this stays after the power is "
        "back, as a record of the outage, until acknowledged. Seen when a read falls "
        "inside the outage: one shorter than the infra interval can be missed."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for data, facts, did in ups_targets(ctx):
            if not _reads_ups(facts) or facts.get("on_battery") is not True:
                continue
            read_at = data.get("last_ok")
            seconds = facts.get("seconds_on_battery")
            if not isinstance(read_at, str):
                continue
            start = datetime.fromisoformat(read_at) - timedelta(
                seconds=seconds if isinstance(seconds, int) else 0
            )
            # Rounded to 10 minutes so every read during one outage names the same event.
            bucket = start.replace(minute=start.minute - start.minute % 10, second=0, microsecond=0)
            cause = facts.get("last_transfer_cause")
            out.append(
                self.finding(
                    ctx,
                    title=f"{label(data, facts)} went on battery at "
                    f"{start.astimezone().strftime('%Y-%m-%d %H:%M')}"
                    + (f" ({cause})" if cause and cause != "no transfer" else ""),
                    key_parts=[str(data.get("host")), bucket.isoformat()],
                    device_id=did,
                    evidence={
                        "started": start.isoformat(timespec="seconds"),
                        "seconds_on_battery": seconds,
                        "cause": cause,
                        "runtime_min": facts.get("runtime_min"),
                    },
                )
            )
        return out


def _power_evidence(facts: dict[str, Any]) -> dict[str, object]:
    return {
        k: facts.get(k)
        for k in (
            "output_status",
            "battery_status",
            "charge_pct",
            "runtime_min",
            "seconds_on_battery",
            "load_pct",
            "input_v",
            "last_transfer_cause",
        )
    }


RULES: list[Rule] = [
    UpsNoCommunicationRule(),
    UpsOnBatteryRule(),
    UpsBatteryLowRule(),
    UpsBatteryReplaceRule(),
    UpsAlarmRule(),
    UpsSelfTestRule(),
    UpsPowerEventRule(),
]
