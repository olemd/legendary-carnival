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


RULES: list[Rule] = [DecoyTouchedRule()]
