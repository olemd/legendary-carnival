"""Rules on what the UniFi controller reports (see lanwatch.collectors.unifi): segmentation
as the controller defines it, clients only the controller sees, and UniFi gear that is down.
They read the infra rows and device attributes the infra round stored; with [unifi] off
there are no rows and nothing fires."""

from __future__ import annotations

from datetime import timedelta

from lanwatch.collectors.unifi import OFFLINE_STATES
from lanwatch.models import Finding, Kind, Severity, iso, now_utc
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


def _name_and_model(name: str, model: object) -> str:
    """ "stue (AC Pro)", or just the model for a device nobody renamed (the controller then
    uses the model as its name)."""
    if not model or str(model).lower() == name.lower():
        return name
    return f"{name} ({model})"


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
                    title=f"UniFi {_name_and_model(name, r.data.get('model'))} is {how}",
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


class UnifiSlowLinkRule(Rule):
    id = "net.unifi-slow-link"
    kind = Kind.PROBLEM
    default_severity = Severity.INFO
    description = (
        "A port on a UniFi device that can do 1 Gbit/s or more has a link at 100 Mbit/s or "
        "less. Either what is plugged in is a 10/100 device (many TVs, printers and smart "
        "home hubs are), or the cable or a connector has a broken pair: gigabit needs all "
        "four pairs, and a link with fewer falls back to 100 Mbit/s. The controller does not "
        "say what is on the port. If it is an access point, a switch or a computer, try "
        "another cable; if it is a 10/100 device, accept the finding."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for r in ctx.store.infra("unifi-device"):
            d = ctx.store.device_by_key(r.key)
            name = r.data.get("name") or r.data.get("model") or r.key
            for p in r.data.get("port_list") or []:
                if not p.get("slow"):
                    continue
                out.append(
                    self.finding(
                        ctx,
                        title=f"Port {p.get('idx')} on UniFi "
                        f"{_name_and_model(name, r.data.get('model'))} runs at "
                        f"{p.get('speed')} Mbit/s, the port can do {p.get('max_speed')}",
                        key_parts=[r.key, str(p.get("idx"))],
                        device_id=d.id if d else None,
                        evidence={
                            "name": r.data.get("name"),
                            "model": r.data.get("model"),
                            "mac": r.key,
                            "port": p.get("idx"),
                            "connector": p.get("connector"),
                            "speed_mbps": p.get("speed"),
                            "max_speed_mbps": p.get("max_speed"),
                            "poe": p.get("poe"),
                        },
                    )
                )
        return out


class UnifiPendingDeviceRule(Rule):
    id = "inventory.unifi-pending-device"
    kind = Kind.PROBLEM
    default_severity = Severity.LOW
    description = (
        "The controller sees UniFi gear on the network that nobody has adopted. It is new "
        "out of the box, it has been factory reset (and then no longer does its job), or it "
        "is not yours. Adopt it in the controller if it is yours; if you do not recognise "
        "it, find where it is plugged in. Resolves when it is adopted or gone."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for r in ctx.store.infra("unifi-pending"):
            d = ctx.store.device_by_key(r.key)
            what = r.data.get("model") or "device"
            out.append(
                self.finding(
                    ctx,
                    title=f"UniFi {what} ({r.data.get('ip') or r.key}) is waiting to be adopted",
                    key_parts=[r.key],
                    device_id=d.id if d else None,
                    evidence={
                        "model": r.data.get("model"),
                        "mac": r.key,
                        "ip": r.data.get("ip"),
                        "state": r.data.get("state"),
                        "firmware_version": r.data.get("firmware_version"),
                        "known_to_lanwatch": d is not None,
                    },
                )
            )
        return out


# net.unifi-radio-retries looks at this many infra rounds and needs a reading from at least
# MIN_RETRY_READS of them, all at or above the threshold: one bad sample is just a busy
# moment.
RETRY_ROUNDS = 4
MIN_RETRY_READS = 3


class UnifiRadioRetriesRule(Rule):
    id = "net.unifi-radio-retries"
    kind = Kind.PROBLEM
    default_severity = Severity.LOW
    description = (
        "A radio on a UniFi access point has had to resend a large share of what it "
        "transmitted (unifi.tx_retries_warn_pct, 30 % by default) at every read for about "
        "an hour. Clients on that band get a slow and uneven connection. The usual causes "
        "are a crowded channel (neighbours' networks, or your own access points on the "
        "same one), interference, or clients at the edge of its range. Try another channel "
        "or a narrower channel width, or move the access point. Resolves when a read is "
        "below the threshold."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        threshold = ctx.config.unifi.tx_retries_warn_pct
        window = timedelta(seconds=RETRY_ROUNDS * ctx.config.schedule.infra_interval_s)
        since = iso(now_utc() - window)
        out: list[Finding] = []
        for r in ctx.store.infra("unifi-device"):
            channels = {x.get("band"): x for x in r.data.get("radios") or []}
            for radio in (r.data.get("stats") or {}).get("radios") or []:
                band = radio.get("band")
                if not isinstance(band, int | float) or radio.get("tx_retries_pct") is None:
                    continue
                reads = [
                    v
                    for _, v in ctx.store.snmp_series(
                        r.key, f"unifi.tx_retries_pct.{band:g}", since
                    )
                ]
                if len(reads) < MIN_RETRY_READS or min(reads) < threshold:
                    continue
                d = ctx.store.device_by_key(r.key)
                name = r.data.get("name") or r.data.get("model") or r.key
                out.append(
                    self.finding(
                        ctx,
                        title=f"UniFi {_name_and_model(name, r.data.get('model'))} resends "
                        f"{reads[-1]:g} % of what it transmits on {band:g} GHz",
                        key_parts=[r.key, f"{band:g}"],
                        device_id=d.id if d else None,
                        evidence={
                            "name": r.data.get("name"),
                            "model": r.data.get("model"),
                            "mac": r.key,
                            "band_ghz": band,
                            "channel": channels.get(band, {}).get("channel"),
                            "channel_width_mhz": channels.get(band, {}).get("width"),
                            "tx_retries_pct": reads,
                            "threshold_pct": threshold,
                            "clients": r.data.get("clients"),
                        },
                    )
                )
        return out


RULES: list[Rule] = [
    IotOnMainNetworkRule(),
    UnifiOnlyClientRule(),
    UnifiDeviceOfflineRule(),
    UnifiSlowLinkRule(),
    UnifiRadioRetriesRule(),
    UnifiPendingDeviceRule(),
]
