"""Rules on what the UniFi controller reports (see lanwatch.collectors.unifi): segmentation
as the controller defines it, clients only the controller sees, and UniFi gear that is down.
They read the infra rows and device attributes the infra round stored; with [unifi] off
there are no rows and nothing fires."""

from __future__ import annotations

from lanwatch.collectors.unifi import OFFLINE_STATES
from lanwatch.models import Finding, Kind, Severity
from lanwatch.rules.base import Rule, RuleContext
from lanwatch.rules.infra import IOT_KINDS


class IotOnMainNetworkRule(Rule):
    id = "net.iot-on-main-network"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    description = (
        "An IoT-class device (camera, smart plug, media box, printer) is on the default "
        "network although the controller has a separate network, or an IoT-optimised SSID, "
        "to put such devices on. Move it there: on its own network a compromised gadget "
        "reaches nothing that matters. On a flat network this rule is silent; the "
        "flat-network note then says why segmenting would help."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        networks = [r.data for r in ctx.store.infra("unifi-network")]
        default = next((n for n in networks if n.get("default")), None)
        if default is None:
            return []
        others = sorted(
            str(n.get("name"))
            for n in networks
            if not n.get("default") and n.get("enabled") and n.get("management") != "UNMANAGED"
        )
        iot_ssids = sorted(
            str(r.data.get("name"))
            for r in ctx.store.infra("unifi-ssid")
            if r.data.get("type") == "IOT_OPTIMIZED" and r.data.get("enabled")
        )
        if not others and not iot_ssids:
            return []  # nowhere else to put them: a flat network, by choice
        out: list[Finding] = []
        for d in ctx.store.devices():
            u = d.attrs.get("unifi")
            net = u.get("network") if isinstance(u, dict) else None
            if d.kind not in IOT_KINDS or not isinstance(net, dict):
                continue
            if net.get("id") != default.get("id"):
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{d.label} ({d.kind}) is on the main network {default.get('name')} "
                    f"while {len(others) or len(iot_ssids)} other "
                    f"{'networks' if others else 'IoT SSIDs'} exist",
                    key_parts=[d.key],
                    device_id=d.id,
                    evidence={
                        "network": default.get("name"),
                        "vlan": default.get("vlan"),
                        "ip": d.ip,
                        "kind": d.kind,
                        "wired": u.get("wired") if isinstance(u, dict) else None,
                        "other_networks": others,
                        "iot_ssids": iot_ssids,
                    },
                )
            )
        return out


class UnifiOnlyClientRule(Rule):
    id = "inventory.unifi-only"
    kind = Kind.PROBLEM
    default_severity = Severity.INFO
    description = (
        "The controller lists a connected client that lanwatch's own discovery has never "
        "seen. Usually it sits on another network or VLAN than the one lanwatch scans, is a "
        "guest with client isolation, or is behind wireless client isolation. If it should "
        "be visible, lanwatch is not on the right segment; if not, accept the finding."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for r in ctx.store.infra("unifi-client"):
            if ctx.store.device_by_key(r.key) is not None:
                continue
            who = r.data.get("name") or r.key
            where = r.data.get("network_name")
            out.append(
                self.finding(
                    ctx,
                    title=f"Only the controller sees {who} ({r.data.get('ip') or 'no address'}"
                    + (f", {where})" if where else ")"),
                    key_parts=[r.key],
                    evidence={
                        "name": r.data.get("name"),
                        "mac": r.key,
                        "ip": r.data.get("ip"),
                        "type": r.data.get("type"),
                        "network": where,
                        "vlan": r.data.get("vlan"),
                        "uplink": r.data.get("uplink_name"),
                        "guest": r.data.get("guest"),
                        "connected_at": r.data.get("connected_at"),
                    },
                )
            )
        return out


class UnifiDeviceOfflineRule(Rule):
    id = "net.unifi-device-offline"
    kind = Kind.PROBLEM
    default_severity = Severity.HIGH
    description = (
        "The controller reports one of its adopted devices (access point, switch, gateway) "
        "as offline, isolated or with its connection interrupted. Clients on it have lost "
        "their link or roamed. Resolves by itself when the device is back."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for r in ctx.store.infra("unifi-device"):
            state = str(r.data.get("state") or "")
            if state not in OFFLINE_STATES:
                continue
            d = ctx.store.device_by_key(r.key)
            name = r.data.get("name") or r.data.get("model") or r.key
            how = state.lower().replace("_", " ")
            out.append(
                self.finding(
                    ctx,
                    title=f"UniFi {r.data.get('model')} {name} is {how}",
                    key_parts=[r.key],
                    device_id=d.id if d else None,
                    evidence={
                        "name": r.data.get("name"),
                        "model": r.data.get("model"),
                        "state": state,
                        "ip": r.data.get("ip"),
                        "mac": r.key,
                        "firmware_version": r.data.get("firmware_version"),
                        "uplink": (r.data.get("uplink") or {}).get("name"),
                        "clients": r.data.get("clients"),
                    },
                )
            )
        return out


RULES: list[Rule] = [IotOnMainNetworkRule(), UnifiOnlyClientRule(), UnifiDeviceOfflineRule()]
