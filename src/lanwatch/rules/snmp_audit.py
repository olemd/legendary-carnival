"""Findings from the SNMP audit probe (collectors/audit_snmp.py): devices that answer SNMP
with well-known default credentials."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from lanwatch.collectors.audit_snmp import identity
from lanwatch.models import Device, Finding, Kind, Severity, iso, now_utc
from lanwatch.rules.base import Rule, RuleContext

# The probe runs with the deep scan (weekly by default). A result older than this many
# deep intervals says nothing about now (the device may be gone, or the probe switched off),
# and the finding then resolves. Three, not one: a device that is off on the day of one
# deep scan goes two intervals between probes, and its finding must not resolve and reopen.
MAX_AGE_INTERVALS = 3


def max_age(ctx: RuleContext) -> timedelta:
    return timedelta(seconds=MAX_AGE_INTERVALS * ctx.config.schedule.deep_interval_s)


def _fresh_audits(ctx: RuleContext) -> list[tuple[Device, dict[str, Any]]]:
    if not ctx.config.snmp_audit.enabled:
        return []
    fresh = iso(now_utc() - max_age(ctx))
    out: list[tuple[Device, dict[str, Any]]] = []
    for d in ctx.store.devices():
        a = d.attrs.get("snmp_audit")
        if isinstance(a, dict) and str(a.get("checked") or "") >= fresh:
            out.append((d, a))
    return out


def _versions(vs: list[str]) -> str:
    return ", ".join("v" + v for v in vs)


def _where(d: Device, a: dict[str, Any]) -> str:
    """The device in a title: its label and address, and what it says it is."""
    what = identity(a, d.label)
    return f"{d.label} ({d.ip}{', ' + what if what else ''})"


def _says(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "sys_name": a.get("sys_name") or None,
        "sys_descr": a.get("sys_descr") or None,
        "sys_object_id": a.get("sys_object_id") or None,
    }


class DefaultCommunityRule(Rule):
    id = "snmp.default-community"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = (
        "A device answers SNMPv1 or v2c with the default community `public` (high) or "
        "`private` (critical; usually a write community). Anyone on the LAN can read it, "
        "and v1/v2c send the community in clear text. Found by the SNMP audit probe "
        "([snmp_audit]), which reads what the device says it is and nothing more. Switch "
        "SNMPv1/v2c off, or set a community nobody can guess and restrict who may ask; "
        "better, use SNMPv3."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for d, a in _fresh_audits(ctx):
            communities = a.get("communities")
            if not isinstance(communities, dict):
                continue
            for community, versions in sorted(communities.items()):
                vs = [str(v) for v in versions or []]
                if not vs:
                    continue
                out.append(
                    self.finding(
                        ctx,
                        title=f"SNMP answers on the default community '{community}' "
                        f"({_versions(vs)}): {_where(d, a)}",
                        key_parts=[d.key, community],
                        device_id=d.id,
                        severity=Severity.CRITICAL if community == "private" else None,
                        evidence={
                            "community": community,
                            "versions": ["v" + v for v in vs],
                            **_says(a),
                            "checked": a.get("checked"),
                            "note": "read with GET of sysDescr, sysName and sysObjectID "
                            "only; whether the community can write was not tested",
                        },
                    )
                )
        return out


class DefaultV3UserRule(Rule):
    id = "snmp.default-v3-user"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = (
        "A device accepts a vendor's documented default SNMPv3 user and passphrases. "
        "Found by the SNMP audit probe ([snmp_audit]), from a short list of defaults with "
        "a cited source each. Change the passphrases or remove the user."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for d, a in _fresh_audits(ctx):
            for login in a.get("v3_defaults") or []:
                out.append(
                    self.finding(
                        ctx,
                        title=f"SNMPv3 default login works ({login}): {_where(d, a)}",
                        key_parts=[d.key, str(login)],
                        device_id=d.id,
                        evidence={
                            "login": login,
                            **_says(a),
                            "checked": a.get("checked"),
                        },
                    )
                )
        return out


# Registered through services.RULES (they are about a service a device exposes), not as
# a RULES list of this module: that keeps the shared list in engine.py untouched.
AUDIT_RULES: list[Rule] = [DefaultCommunityRule(), DefaultV3UserRule()]
