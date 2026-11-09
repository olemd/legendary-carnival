"""Inventory rules: changes in which devices exist on the network."""

from __future__ import annotations

from lanwatch import oui
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
            # A randomised address is most likely a phone or laptop already known under
            # another address, so it gets the attention of a note, not of an alarm.
            private = d.private_mac
            out.append(
                self.finding(
                    ctx,
                    title=f"New device: {d.label} ({d.ip})",
                    key_parts=[d.key],
                    device_id=d.id,
                    severity=Severity.LOW if private else None,
                    evidence={
                        "ip": d.ip,
                        "mac": d.mac,
                        "vendor": d.vendor,
                        "hostname": d.hostname,
                        "first_seen": d.first_seen,
                        "private_mac": private,
                    },
                )
            )
        return out


class PrivateMacRule(Rule):
    id = "inventory.private-mac"
    kind = Kind.IMPROVEMENT
    default_severity = Severity.LOW
    description = (
        "The device uses a randomised (locally administered) MAC address, as phones and "
        "laptops do by default on each Wi-Fi network. Nothing is wrong, but the address may "
        "change, and the device then shows up as a new one with no history. Turn the private "
        "address off for your own network in the device's Wi-Fi settings if you want a stable "
        "record, or merge the entries when it happens."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        return [
            self.finding(
                ctx,
                title=f"Randomised MAC address: {d.label}",
                key_parts=[d.key],
                device_id=d.id,
                evidence={"mac": d.mac, "ip": d.ip, "hostname": d.hostname},
            )
            for d in ctx.store.devices()
            if d.private_mac
        ]


class UnregisteredMacRule(Rule):
    id = "inventory.unregistered-mac"
    kind = Kind.SECURITY
    default_severity = Severity.LOW
    description = (
        "The first half of the device's MAC address is not assigned to any manufacturer in "
        "the IEEE registry, and it is not a randomised address either. Real hardware always "
        "carries a registered prefix, so this one was typed in by hand: a virtual machine "
        "with a made-up address, or a device pretending to be another."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        registry = oui.load(ctx.config.data_dir)
        if not registry:
            return []  # no registry at hand: nothing to compare with
        out: list[Finding] = []
        for d in ctx.store.devices():
            if not d.mac or d.private_mac or registry.lookup(d.mac) is not None:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"MAC prefix not in the IEEE registry: {d.label} ({d.mac})",
                    key_parts=[d.key],
                    device_id=d.id,
                    evidence={"mac": d.mac, "ip": d.ip, "hostname": d.hostname},
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


class WatchedOfflineRule(Rule):
    id = "inventory.watched-offline"
    kind = Kind.PROBLEM
    default_severity = Severity.HIGH
    description = (
        "A device you asked to be told about has stopped answering discovery. Set per device "
        "on its page; resolves by itself when the device is back."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        threshold = ctx.config.network.watch_offline_rounds
        out: list[Finding] = []
        for d in ctx.store.devices():
            if not d.watch:
                continue
            missed = ctx.store.missed_rounds(d.id)
            if missed < threshold:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"Watched device offline: {d.label}",
                    key_parts=[d.key],
                    device_id=d.id,
                    evidence={
                        "ip": d.ip,
                        "mac": d.mac,
                        "last_seen": d.last_seen,
                        "missed_rounds": missed,
                    },
                )
            )
        return out


RULES: list[Rule] = [
    NewDeviceRule(),
    IpChangedRule(),
    WatchedOfflineRule(),
    PrivateMacRule(),
    UnregisteredMacRule(),
]
