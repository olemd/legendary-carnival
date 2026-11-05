"""Infrastructure rules: DHCP, UPnP, IPv6, and segmentation. They read the current infra
observations and device attributes from the store."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from lanwatch.models import Device, Finding, Kind, Severity
from lanwatch.rules.base import Rule, RuleContext
from lanwatch.store import Store, dhcp_settings

IOT_KINDS = {"iot", "camera", "media", "smart_home_hub", "printer", "game_console"}
TRUSTED_KINDS = {"workstation", "laptop", "server", "nas", "virtual_machine"}


class RogueDhcpRule(Rule):
    id = "net.rogue-dhcp"
    kind = Kind.SECURITY
    default_severity = Severity.CRITICAL
    description = (
        "More than one DHCP server answers on the segment. Clients may get a wrong gateway or DNS."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        rows = ctx.store.infra("dhcp")
        by_iface: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            by_iface.setdefault(str(r.data.get("interface", "?")), []).append(r.data)
        out: list[Finding] = []
        for iface, offers in by_iface.items():
            servers = sorted({str(o["server"]) for o in offers})
            if len(servers) < 2:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"Multiple DHCP servers on {iface}: {', '.join(servers)}",
                    key_parts=[iface, *servers],
                    evidence={"interface": iface, "servers": servers, "offers": offers},
                )
            )
        return out


class UpnpIgdRule(Rule):
    id = "router.upnp-igd"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    description = (
        "The router accepts UPnP IGD requests: any LAN device can open ports from the internet "
        "to itself without asking."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for r in ctx.store.infra("upnp"):
            if not r.data.get("is_igd"):
                continue
            dev = ctx.store.device_by_ip(r.key)
            out.append(
                self.finding(
                    ctx,
                    title=f"UPnP IGD enabled on {dev.label if dev else r.key} ({r.key})",
                    key_parts=[r.key],
                    device_id=dev.id if dev else None,
                    evidence={
                        "address": r.key,
                        "friendly_name": r.data.get("friendly_name"),
                        "model": r.data.get("model"),
                        "external_ip": r.data.get("external_ip"),
                        "mapping_count": len(r.data.get("mappings", [])),
                    },
                )
            )
        return out


class UpnpMappingsRule(Rule):
    id = "router.upnp-mappings"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = (
        "Active port forwards exist on the router (via UPnP). Each one is internet exposure."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for r in ctx.store.infra("upnp"):
            mappings = [m for m in r.data.get("mappings", []) if m.get("enabled", True)]
            if not mappings:
                continue
            for m in mappings:
                client = str(m.get("internal_client", ""))
                dev = ctx.store.device_by_ip(client)
                target = f"{dev.label} ({client})" if dev else client
                out.append(
                    self.finding(
                        ctx,
                        title=(
                            f"Port forward {m.get('external_port')}/{m.get('protocol')} -> "
                            f"{target}:{m.get('internal_port')}"
                            + (f" [{m['description']}]" if m.get("description") else "")
                        ),
                        key_parts=[
                            r.key,
                            str(m.get("external_port")),
                            str(m.get("protocol")),
                            client,
                        ],
                        device_id=dev.id if dev else None,
                        evidence={"router": r.key, **m},
                    )
                )
        return out


class Ipv6ExposedRule(Rule):
    id = "net.ipv6-global-exposed"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    description = (
        "Device has a globally routable IPv6 address with open services. Unless the router "
        "firewalls inbound IPv6, these are reachable from the internet."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for d in ctx.store.devices():
            open_by_addr = d.attrs.get("ipv6_open") or {}
            if not isinstance(open_by_addr, dict) or not open_by_addr:
                continue
            ports = sorted({p for ps in open_by_addr.values() for p in ps})
            out.append(
                self.finding(
                    ctx,
                    title=f"IPv6-reachable services on {d.label}: {', '.join(ports[:6])}",
                    key_parts=[d.key],
                    device_id=d.id,
                    evidence={"addresses": sorted(open_by_addr), "open_ports": ports},
                )
            )
        return out


class FlatNetworkRule(Rule):
    id = "improvement.flat-network"
    kind = Kind.IMPROVEMENT
    default_severity = Severity.INFO
    description = (
        "IoT-class devices share a subnet with workstations or servers. A separate VLAN "
        "limits what a compromised gadget can reach."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        groups: dict[str, dict[str, list[Device]]] = {}
        for d in ctx.store.devices():
            if not d.ip or not d.kind:
                continue
            try:
                net = str(ipaddress.ip_network(f"{d.ip}/24", strict=False))
            except ValueError:
                continue
            bucket = (
                "iot" if d.kind in IOT_KINDS else "trusted" if d.kind in TRUSTED_KINDS else None
            )
            if bucket:
                groups.setdefault(net, {}).setdefault(bucket, []).append(d)
        out: list[Finding] = []
        for net, buckets in groups.items():
            iot, trusted = buckets.get("iot", []), buckets.get("trusted", [])
            if not iot or not trusted:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{len(iot)} IoT-class and {len(trusted)} trusted devices share {net}",
                    key_parts=[net],
                    evidence={
                        "subnet": net,
                        "iot": [f"{d.label} ({d.ip})" for d in iot][:20],
                        "trusted": [f"{d.label} ({d.ip})" for d in trusted][:20],
                    },
                )
            )
        return out


def infrastructure_ips(store: Store) -> dict[str, str]:
    """The addresses every other device depends on, with their role: this host's default
    gateways (recorded by discovery) and the router, DHCP server and DNS servers that DHCP
    announces (recorded by the infra probes). Whoever answers for one of these can read or
    redirect the whole network's traffic."""
    roles: dict[str, str] = {}

    def add(value: object, role: str) -> None:
        for ip in str(value or "").replace(",", " ").split():
            try:
                roles.setdefault(str(ipaddress.IPv4Address(ip)), role)
            except ValueError:
                continue

    try:
        for ip in json.loads(store.meta_get("net.gateways") or "[]"):
            add(ip, "Gateway")
    except ValueError:
        pass
    for r in store.infra("dhcp"):
        add(r.data.get("router"), "Gateway")
        add(r.data.get("server"), "DHCP server")
        for dns in r.data.get("dns") or []:
            add(dns, "DNS server")
    return roles


def _who(ctx: RuleContext, device_id: int, mac: str | None) -> str:
    d = ctx.store.device(device_id)
    return f"{mac or '?'} ({d.label})" if d is not None and d.label != mac else str(mac or "?")


class IpConflictRule(Rule):
    id = "net.ip-conflict"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = (
        "Two devices answered for the same IP address in one discovery round. Either an "
        "address conflict (a static address inside the DHCP range) or one device "
        "impersonating the other (ARP spoofing). Critical when the address is the gateway, "
        "the DHCP server or a DNS server."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        infra = infrastructure_ips(ctx.store)
        out: list[Finding] = []
        for ip, answers in ctx.store.ip_holders().items():
            # Only answers that came with a MAC address can show two different devices; a
            # host seen without one (a ping sweep, a routed subnet) proves nothing.
            holders = [(did, mac) for did, mac in answers if mac]
            if len({mac for _, mac in holders}) < 2:
                continue
            role = infra.get(ip)
            who = [_who(ctx, did, mac) for did, mac in holders]
            out.append(
                self.finding(
                    ctx,
                    title=f"Two devices answer for {ip}"
                    + (f" ({role.lower()})" if role else "")
                    + f": {', '.join(who)}",
                    key_parts=[ip, *sorted(str(mac) for _, mac in holders)],
                    severity=Severity.CRITICAL if role else None,
                    evidence={"ip": ip, "role": role, "answered": who},
                )
            )
        return out


class InfraMacChangedRule(Rule):
    id = "net.infrastructure-mac-changed"
    kind = Kind.SECURITY
    default_severity = Severity.CRITICAL
    description = (
        "The gateway, DHCP server or a DNS server now answers from a different MAC address "
        "than when lanwatch first saw it. Expected once after replacing the router (accept "
        "the finding); otherwise the classic sign of ARP spoofing, where another device "
        "puts itself between the network and its gateway."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        holders = ctx.store.ip_holders()
        out: list[Finding] = []
        for ip, role in infrastructure_ips(ctx.store).items():
            pinned = ctx.store.meta_get(f"net.pin.{ip}")
            now = sorted({mac for _, mac in holders.get(ip, []) if mac})
            if pinned is None or not now or pinned in now:
                continue  # never seen, not answering this round, or still the same device
            who = [_who(ctx, did, mac) for did, mac in holders[ip] if mac]
            out.append(
                self.finding(
                    ctx,
                    title=f"{role} {ip} now answers from {', '.join(who)}, was {pinned}",
                    key_parts=[ip, pinned, *now],
                    device_id=holders[ip][0][0],
                    severity=None if role == "Gateway" else Severity.HIGH,
                    evidence={"ip": ip, "role": role, "first_seen_mac": pinned, "now": who},
                )
            )
        return out


class Ipv6RouterNewRule(Rule):
    id = "net.ipv6-router-new"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = (
        "An IPv6 router is announcing itself that was not there when lanwatch first looked. "
        "Any device can send router advertisements, and clients prefer IPv6, so a rogue "
        "one takes over traffic and DNS even on a network that only uses IPv4. Accept the "
        "finding if you or your provider turned IPv6 on."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        raw = ctx.store.meta_get("net.ipv6-routers")
        try:
            known = set(json.loads(raw)) if raw is not None else None
        except ValueError:
            known = None
        if known is None:
            return []  # the infra probes have not run yet; nothing to compare with
        out: list[Finding] = []
        for r in ctx.store.infra("ipv6-router"):
            mac, gateway = str(r.data.get("mac") or ""), str(r.data.get("gateway") or "")
            identity = mac or gateway
            if identity in known:
                continue
            device = ctx.store.device_by_key(mac) if mac else None
            who = f"{device.label} ({mac})" if device is not None else (mac or gateway)
            out.append(
                self.finding(
                    ctx,
                    title=f"New IPv6 router on {r.data.get('dev')}: {who}",
                    key_parts=[identity],
                    device_id=device.id if device is not None else None,
                    evidence={
                        "gateway": gateway,
                        "mac": mac or None,
                        "interface": r.data.get("dev"),
                        "known_routers": sorted(known),
                    },
                )
            )
        return out


class DhcpSettingsChangedRule(Rule):
    id = "net.dhcp-settings-changed"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = (
        "A DHCP server announces a different router, DNS server, NTP server or domain than "
        "when lanwatch first saw it. Every client follows these settings, so changing the "
        "DNS server is how a compromised router redirects a whole network. Accept the "
        "finding if you changed it yourself (for example to a filtering resolver)."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        labels = {"router": "router", "dns": "DNS", "ntp": "NTP", "domain": "domain"}
        out: list[Finding] = []
        for r in ctx.store.infra("dhcp"):
            raw = ctx.store.meta_get(f"net.dhcp.{r.key}")
            try:
                first = json.loads(raw) if raw else None
            except ValueError:
                first = None
            if not isinstance(first, dict):
                continue
            now = dhcp_settings(r.data)
            for field, label in labels.items():
                was, is_ = list(first.get(field) or []), now[field]
                if was == is_:
                    continue
                out.append(
                    self.finding(
                        ctx,
                        title=f"DHCP server {r.data.get('server')} now announces {label} "
                        f"{', '.join(is_) or 'nothing'}, was {', '.join(was) or 'nothing'}",
                        key_parts=[r.key, field, *was, "->", *is_],
                        # Router and DNS redirect traffic; NTP and domain are lesser levers.
                        severity=None if field in ("router", "dns") else Severity.MEDIUM,
                        evidence={
                            "interface": r.data.get("interface"),
                            "server": r.data.get("server"),
                            "setting": field,
                            "first_seen": was,
                            "now": is_,
                        },
                    )
                )
        return out


RULES: list[Rule] = [
    RogueDhcpRule(),
    UpnpIgdRule(),
    UpnpMappingsRule(),
    Ipv6ExposedRule(),
    FlatNetworkRule(),
    IpConflictRule(),
    InfraMacChangedRule(),
    DhcpSettingsChangedRule(),
    Ipv6RouterNewRule(),
]
