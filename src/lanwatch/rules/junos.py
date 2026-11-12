"""Rules over the Junos extras (lanwatch/collectors/snmp_junos.py): chassis alarms, health,
sessions, config changes, the rescue config, and DHCP declines.

A bonus: they only ever see facts from devices that answered as Juniper, and a fact the
device did not report means "nothing to say", never a finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from lanwatch.models import Finding, Kind, Severity, iso, now_utc
from lanwatch.rules.base import Rule, RuleContext

STORAGE_FULL_PCT = 90
SESSIONS_FULL = 0.8
# How long a configuration commit stays a finding (junos.config-changed).
CONFIG_CHANGE_RECENT = timedelta(days=7)
# FRU states that mean the part is not doing its job. empty (a free slot), present, ready
# and standby are normal.
FRU_BAD = {"offline": Severity.MEDIUM, "announce offline": Severity.MEDIUM, "fault": Severity.HIGH}


@dataclass(slots=True)
class JunosRow:
    host: str
    name: str
    role: str
    facts: dict[str, Any]
    last_ok: str | None
    first_seen: str


def _configured_hosts(ctx: RuleContext) -> tuple[bool, set[str]]:
    targets = ctx.config.snmp.targets()
    router = any(t.role == "router" for t in targets)
    return router, {t.host for t in targets if t.role == "device" and t.host}


def junos_rows(ctx: RuleContext) -> list[JunosRow]:
    """Targets still in config whose Junos reader found something."""
    router, devices = _configured_hosts(ctx)
    out: list[JunosRow] = []
    for r in ctx.store.infra("snmp-target"):
        d = r.data
        role = str(d.get("role") or "")
        if not ((role == "router" and router) or (role == "device" and r.key in devices)):
            continue
        all_facts = d.get("facts")
        facts = all_facts.get("junos") if isinstance(all_facts, dict) else None
        if not isinstance(facts, dict) or not facts:
            continue
        raw_system = d.get("system")
        system: dict[str, Any] = raw_system if isinstance(raw_system, dict) else {}
        out.append(
            JunosRow(
                host=str(d.get("host") or r.key),
                name=str(d.get("name") or system.get("name") or d.get("host") or r.key),
                role=role,
                facts=facts,
                last_ok=d.get("last_ok"),
                first_seen=r.first_seen,
            )
        )
    return out


def _device_id(ctx: RuleContext, row: JunosRow) -> int | None:
    d = ctx.store.device_by_ip(row.host)
    return d.id if d else None


class ChassisAlarmRule(Rule):
    id = "junos.chassis-alarm"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "A Juniper chassis alarm is on. Red is major and yellow minor: a power supply, fan, "
        "temperature, licence or hardware problem the device itself reports. "
        "`show chassis alarms` on the device says which."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for row in junos_rows(ctx):
            for colour, alarm in (row.facts.get("alarms") or {}).items():
                if not isinstance(alarm, dict) or not alarm.get("on"):
                    continue
                out.append(
                    self.finding(
                        ctx,
                        title=f"{row.name}: {colour} chassis alarm on",
                        key_parts=[row.host, colour],
                        device_id=_device_id(ctx, row),
                        severity=Severity.HIGH if colour == "red" else Severity.MEDIUM,
                        evidence={"host": row.host, "alarm": colour, "count": alarm.get("count")},
                    )
                )
        return out


class StorageFullRule(Rule):
    id = "junos.storage-full"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        f"A Juniper flash partition is over {STORAGE_FULL_PCT} % full. A "
        "full /var stops logs and commits; `request system storage cleanup` frees space. "
        "Virtual file systems and the read-only Junos image always read 100 % and are "
        "left out."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for row in junos_rows(ctx):
            for part in row.facts.get("storage") or []:
                used = part.get("used_pct")
                if not isinstance(used, int) or used <= STORAGE_FULL_PCT:
                    continue
                out.append(
                    self.finding(
                        ctx,
                        title=f"{row.name}: {part.get('mount')} is {used} % full",
                        key_parts=[row.host, str(part.get("device"))],
                        device_id=_device_id(ctx, row),
                        evidence={"host": row.host, **part},
                    )
                )
        return out


class FruNotOnlineRule(Rule):
    id = "junos.fru-not-online"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "A Juniper part is offline or faulty. That is a replaceable part: power supply, "
        "line card, PIC or routing engine. An empty slot is not a finding."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for row in junos_rows(ctx):
            for fru in row.facts.get("frus") or []:
                state = str(fru.get("state"))
                if state not in FRU_BAD:
                    continue
                out.append(
                    self.finding(
                        ctx,
                        title=f"{row.name}: {fru.get('name')} is {state}",
                        key_parts=[row.host, str(fru.get("index"))],
                        device_id=_device_id(ctx, row),
                        severity=FRU_BAD[state],
                        evidence={"host": row.host, **fru},
                    )
                )
        return out


class SessionTableFullRule(Rule):
    id = "junos.session-table-full"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        f"A Juniper session table is over {SESSIONS_FULL:.0%} full. When it "
        "is full, new connections are dropped; a flood, a scan or a leaking client is the "
        "usual cause."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for row in junos_rows(ctx):
            for node in row.facts.get("sessions") or []:
                now, top = node.get("current"), node.get("max")
                if not isinstance(now, int) or not isinstance(top, int) or top <= 0:
                    continue
                if now / top <= SESSIONS_FULL:
                    continue
                out.append(
                    self.finding(
                        ctx,
                        title=f"{row.name}: session table {now / top:.0%} full",
                        key_parts=[row.host, str(node.get("node"))],
                        device_id=_device_id(ctx, row),
                        evidence={"host": row.host, **node},
                    )
                )
        return out


class ConfigChangedRule(Rule):
    id = "junos.config-changed"
    kind = Kind.SECURITY
    default_severity = Severity.INFO
    # A commit is a finding for a week, then resolves by itself: an admin who commits daily
    # should not have to acknowledge each one. The timeline keeps every one of them.
    description = (
        "A configuration commit on a Juniper device in the last 7 days. Who, how (CLI, "
        "NETCONF, ...) and when come from the device's own change log. One finding per "
        "commit, which resolves by itself after a week; the timeline keeps them. Commits from "
        "before lanwatch first read the device are not reported."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        recent = iso(now_utc() - CONFIG_CHANGE_RECENT)
        for row in junos_rows(ctx):
            for ev in (row.facts.get("config") or {}).get("events") or []:
                at = str(ev.get("at") or "")
                if not at or at <= row.first_seen or at < recent:
                    continue
                user = ev.get("user") or "?"
                out.append(
                    self.finding(
                        ctx,
                        title=f"{row.name}: configuration changed by {user} ({ev.get('source')})",
                        key_parts=[row.host, at, str(ev.get("index"))],
                        device_id=_device_id(ctx, row),
                        evidence={"host": row.host, **ev},
                    )
                )
        return out


class NoRescueConfigRule(Rule):
    id = "junos.no-rescue-config"
    kind = Kind.IMPROVEMENT
    default_severity = Severity.LOW
    description = (
        "A Juniper device has no rescue configuration. That is a known-good config to fall "
        "back to from the console when a commit locks you out. `request system configuration "
        "rescue save` stores the current one."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for row in junos_rows(ctx):
            rescue = row.facts.get("rescue")
            if not isinstance(rescue, dict) or rescue.get("saved") is not False:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{row.name}: no rescue configuration saved",
                    key_parts=[row.host],
                    device_id=_device_id(ctx, row),
                    evidence={"host": row.host},
                )
            )
        return out


class DhcpDeclinesRisingRule(Rule):
    id = "dhcp.declines-rising"
    kind = Kind.PROBLEM
    default_severity = Severity.LOW
    description = (
        "A Juniper DHCP server got new DHCPDECLINE messages. A client was offered an "
        "address that something else already uses. "
        "Usually a device with a static address inside the DHCP pool. The finding stays "
        "while the count keeps growing."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for row in junos_rows(ctx):
            value = row.facts.get("dhcp_declines")
            if not isinstance(value, int) or not row.last_ok:
                continue
            delta, prev = _declines_delta(ctx, row.host, row.last_ok, value)
            if delta is None or delta <= 0:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{row.name}: {delta} DHCP decline{'s' if delta != 1 else ''} "
                    "since the previous read",
                    key_parts=[row.host],
                    device_id=_device_id(ctx, row),
                    evidence={"host": row.host, "new": delta, "total": value, "before": prev},
                )
            )
        return out


def _declines_delta(
    ctx: RuleContext, host: str, read_at: str, value: int
) -> tuple[int | None, int | None]:
    """The growth of the decline counter between the two newest reads of a device. The
    reader cannot see its previous facts, so the last two reads are remembered here, keyed
    by the read's time: rules run more often than the device is read, and a read must
    only be counted once. A counter that went down (a reboot) is no growth."""
    key = f"junos.dhcp_declines.{host}"
    try:
        memo = json.loads(ctx.store.meta_get(key) or "{}")
    except ValueError:
        memo = {}
    if memo.get("read_at") != read_at:
        memo = {"read_at": read_at, "value": value, "before": memo.get("value")}
        ctx.store.meta_set(key, json.dumps(memo))
    before = memo.get("before")
    if not isinstance(before, int):
        return None, None
    return int(memo["value"]) - before, before


RULES: list[Rule] = [
    ChassisAlarmRule(),
    StorageFullRule(),
    FruNotOnlineRule(),
    SessionTableFullRule(),
    ConfigChangedRule(),
    NoRescueConfigRule(),
    DhcpDeclinesRisingRule(),
]
