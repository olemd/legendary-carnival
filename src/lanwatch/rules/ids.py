"""Intrusion-detection rules: signs that something on the LAN is actively looking around or
impersonating others. They read what the decoys and probes recorded in the store."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from lanwatch.decoy import port_label
from lanwatch.models import Finding, Kind, Severity, iso, now_utc
from lanwatch.rules.base import Rule, RuleContext


class DecoyTouchedRule(Rule):
    id = "ids.decoy-touched"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    # An event, not a state: it stays until someone has looked at it.
    auto_resolve = False
    description = (
        "A device connected to a decoy port: a port lanwatch listens on only because nothing "
        "has a reason to use it. Whatever connects is scanning the network, on purpose or "
        "because it is infected. One finding per source and day; accept it for a scanner "
        "of your own, or list the address under [decoy] ignore."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        since = iso(now_utc() - timedelta(days=7))
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for e in reversed(ctx.store.events(kinds=["decoy.touched"], since=since, limit=2000)):
            ip, port = e.data.get("ip"), e.data.get("port")
            if not isinstance(ip, str) or not isinstance(port, int):
                continue
            g = groups.setdefault(
                (ip, e.ts[:10]),
                {"ports": set(), "count": 0, "first": e.ts, "device_id": e.device_id},
            )
            g["ports"].add(port)
            g["count"] += 1
            g["last"] = e.ts
        out: list[Finding] = []
        for (ip, day), g in groups.items():
            device = ctx.store.device(g["device_id"]) if g["device_id"] is not None else None
            who = f"{device.label} ({ip})" if device is not None else ip
            ports = sorted(g["ports"])
            out.append(
                self.finding(
                    ctx,
                    title=f"{who} probed decoy port{'s' if len(ports) != 1 else ''} "
                    + ", ".join(port_label(p) for p in ports),
                    key_parts=[ip, day],
                    device_id=device.id if device is not None else None,
                    evidence={
                        "source": ip,
                        "ports": ports,
                        "connections": g["count"],
                        "first": g["first"],
                        "last": g["last"],
                    },
                )
            )
        return out


class NamePoisoningRule(Rule):
    id = "ids.name-poisoning"
    kind = Kind.SECURITY
    default_severity = Severity.CRITICAL
    description = (
        "A device answered a lookup for a host name that does not exist. lanwatch asks the "
        "local segment for a random name over LLMNR, mDNS and NetBIOS; nothing legitimate "
        "answers. A machine that does is running a poisoning tool (Responder and the like) "
        "that answers every lookup with its own address to capture credentials."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for r in ctx.store.infra("name-poisoning"):
            ip = str(r.data.get("responder") or r.key)
            protocols = sorted(str(p) for p in r.data.get("protocols") or [])
            device = ctx.store.device_by_ip(ip)
            who = f"{device.label} ({ip})" if device is not None else ip
            out.append(
                self.finding(
                    ctx,
                    title=f"{who} answers lookups for names that do not exist "
                    f"({', '.join(protocols)})",
                    key_parts=[ip],
                    device_id=device.id if device is not None else None,
                    evidence={
                        "responder": ip,
                        "protocols": protocols,
                        "asked_for": r.data.get("name"),
                        "first_seen": r.first_seen,
                    },
                )
            )
        return out


class ArpSweepRule(Rule):
    id = "ids.arp-sweep"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    # Asking for this many addresses that no known device has is not ordinary traffic. A
    # router looking for its own clients asks for addresses that exist.
    UNUSED_TARGETS = 20
    description = (
        "A device sent ARP requests for many addresses that no known device has: it is "
        "mapping the network. Heard by the passive ARP listener between scans. Accept the "
        "finding for a scanner of your own (a second lanwatch, a network controller)."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        used = {d.ip for d in ctx.store.devices() if d.ip}
        out: list[Finding] = []
        for r in ctx.store.infra("arp-sweep"):
            targets = [str(t) for t in r.data.get("targets") or []]
            unused = [t for t in targets if t not in used]
            if len(unused) < self.UNUSED_TARGETS:
                continue
            mac = str(r.data.get("mac") or r.key)
            device = ctx.store.device_by_key(mac)
            who = f"{device.label} ({mac})" if device is not None else mac
            out.append(
                self.finding(
                    ctx,
                    title=f"{who} is sweeping the network: ARP requests for {len(targets)} "
                    f"addresses, {len(unused)} of them unused",
                    key_parts=[mac],
                    device_id=device.id if device is not None else None,
                    evidence={
                        "mac": mac,
                        "ip": r.data.get("ip") or None,
                        "addresses_asked_for": len(targets),
                        "unused": len(unused),
                        "sample": unused[:10],
                    },
                )
            )
        return out


RULES: list[Rule] = [DecoyTouchedRule(), NamePoisoningRule(), ArpSweepRule()]
