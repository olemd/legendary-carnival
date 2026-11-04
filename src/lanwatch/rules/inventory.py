"""Inventory rules: changes in which devices exist on the network."""

from __future__ import annotations

from lanwatch.models import Finding, Kind, Severity
from lanwatch.rules.base import Rule, RuleContext


class NewDeviceRule(Rule):
    id = "inventory.new-device"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    auto_resolve = False
    description = "A device with an identity not seen before appeared on the network."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        if ctx.is_baseline:
            return []
        out: list[Finding] = []
        for device_id in ctx.new_device_ids:
            d = ctx.store.device(device_id)
            if d is None:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"New device: {d.label} ({d.ip})",
                    key_parts=[d.key],
                    device_id=d.id,
                    evidence={
                        "ip": d.ip,
                        "mac": d.mac,
                        "vendor": d.vendor,
                        "hostname": d.hostname,
                        "first_seen": d.first_seen,
                    },
                )
            )
        return out


class IpChangedRule(Rule):
    id = "inventory.ip-changed"
    kind = Kind.PROBLEM
    default_severity = Severity.INFO
    auto_resolve = False
    description = "A known device changed IP address. Noise with DHCP, signal with static leases."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for device_id, old, new in ctx.ip_changes:
            d = ctx.store.device(device_id)
            if d is None:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"IP changed: {d.label} {old} -> {new}",
                    key_parts=[d.key, old, new],
                    device_id=d.id,
                    evidence={"old_ip": old, "new_ip": new, "mac": d.mac},
                )
            )
        return out


RULES: list[Rule] = [NewDeviceRule(), IpChangedRule()]
