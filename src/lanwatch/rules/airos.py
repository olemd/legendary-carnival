"""Rules over the airMAX radios read by the [airos] link (lanwatch/collectors/airos.py).

A point-to-point link shows up twice, once from each end. Link rules report it once,
under the pair of radios, with the worse end's figures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lanwatch.models import Finding, Kind, Severity
from lanwatch.rules.base import Rule, RuleContext

# Reads in a row (one per infra round) before a state counts.
LINK_DOWN_READS = 2
DEGRADED_READS = 2
POOR_READS = 4

# Channel advice only for a link that suffers: the worse end's CCQ below this. A link that
# shares spectrum but gets its frames through has nothing to gain from a move.
CHANNEL_ADVICE_CCQ = 80

# 2.4 GHz Wi-Fi channels that do not overlap each other, and the centre frequencies.
COMMON_CHANNELS = {1: 2412, 6: 2437, 11: 2462}
WIFI_WIDTH_MHZ = 20


def _rows(ctx: RuleContext) -> list[dict[str, Any]]:
    if not ctx.config.airos.enabled:
        return []
    return [r.data for r in ctx.store.infra("airos") if r.key in ctx.config.airos.hosts]


def _as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _name(row: dict[str, Any]) -> str:
    return str(row.get("hostname") or row.get("host") or "?")


def _device_id(ctx: RuleContext, row: dict[str, Any]) -> int | None:
    d = ctx.store.device_by_key(str(row["mac"])) if row.get("mac") else None
    if d is None and row.get("host"):
        d = ctx.store.device_by_ip(str(row["host"]))
    return d.id if d else None


@dataclass(slots=True)
class LinkView:
    """One end's view of a link: the radio, the station it sees, and its counters."""

    row: dict[str, Any]
    station: dict[str, Any]
    track: dict[str, Any]

    @property
    def pair(self) -> tuple[str, str]:
        a, b = str(self.row.get("mac") or self.row.get("host")), str(self.station.get("mac"))
        return (a, b) if a <= b else (b, a)

    @property
    def title(self) -> str:
        names = sorted(
            [_name(self.row), str(self.station.get("remote_hostname") or self.station.get("name"))]
        )
        return f"{names[0]} ↔ {names[1]}"


def _links(ctx: RuleContext) -> dict[tuple[str, str], list[LinkView]]:
    """Every link with the views of it that were read, keyed by the pair of MACs."""
    out: dict[tuple[str, str], list[LinkView]] = {}
    for row in _rows(ctx):
        if row.get("error") or not row.get("read_at"):
            continue  # a radio that was not read this time says nothing new
        tracks = _as_dict(row.get("links"))
        for st in row.get("stations") or []:
            if not isinstance(st, dict) or not st.get("mac"):
                continue
            track = _as_dict(tracks.get(st["mac"]))
            view = LinkView(row, st, track)
            out.setdefault(view.pair, []).append(view)
    return out


class AirosLinkDownRule(Rule):
    id = "airos.link-down"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "An airMAX radio answers lanwatch but is linked with no other radio, in two reads "
        "in a row: whatever is behind the link is cut off. A short gap while the far end "
        "restarts is not reported."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for row in _rows(ctx):
            if row.get("error") or int(row.get("no_link_reads") or 0) < LINK_DOWN_READS:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{_name(row)}: radio link down",
                    key_parts=[str(row.get("host"))],
                    device_id=_device_id(ctx, row),
                    evidence={
                        "host": row.get("host"),
                        "mode": row.get("mode"),
                        "frequency_mhz": row.get("frequency_mhz"),
                        "hears_dbm": row.get("signal"),
                        "noise_dbm": row.get("noise"),
                        "reads_without_link": row.get("no_link_reads"),
                    },
                )
            )
        return out


class AirosLinkPoorRule(Rule):
    id = "airos.link-poor"
    kind = Kind.PROBLEM
    default_severity = Severity.LOW
    description = (
        "An airMAX link has had a CCQ below 60% for an hour: many frames have to be sent "
        "again. The usual causes are other networks on the same frequencies (see "
        "airos.channel-overlap), alignment, or something in the path."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for pair, views in _links(ctx).items():
            poor = [v for v in views if int(v.track.get("poor_reads") or 0) >= POOR_READS]
            if not poor:
                continue
            worst = min(poor, key=lambda v: int(v.station.get("ccq") or 0))
            out.append(
                self.finding(
                    ctx,
                    title=f"Radio link {worst.title} resends many frames: CCQ "
                    f"{worst.station.get('ccq')}% at {_name(worst.row)}",
                    key_parts=list(pair),
                    device_id=_device_id(ctx, worst.row),
                    evidence={
                        "ccq": {_name(v.row): v.station.get("ccq") for v in views},
                        "signal_dbm": {_name(v.row): v.station.get("signal") for v in views},
                        "noise_dbm": {_name(v.row): v.station.get("noise") for v in views},
                        "frequency_mhz": worst.row.get("frequency_mhz"),
                    },
                )
            )
        return out


class AirosLinkDegradedRule(Rule):
    id = "airos.link-degraded"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "An airMAX link is clearly worse than its own normal, in two reads in a row: the "
        "signal 6 dB or more below it, or the CCQ 20 points or more below it. The normal is "
        "learned from the link itself over the first half day and then kept up to date, "
        "so a link that was always weak is not reported, and one that got worse is."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for pair, views in _links(ctx).items():
            bad = [v for v in views if int(v.track.get("degraded_reads") or 0) >= DEGRADED_READS]
            if not bad:
                continue
            v = bad[0]
            signal_n = float(v.track.get("normal_signal") or 0)
            ccq_n = float(v.track.get("normal_ccq") or 0)
            out.append(
                self.finding(
                    ctx,
                    title=f"Radio link {v.title} is worse than normal at {_name(v.row)}: "
                    f"signal {v.station.get('signal')} dBm (normally {signal_n:.0f}), "
                    f"CCQ {v.station.get('ccq')}% (normally {ccq_n:.0f}%)",
                    key_parts=list(pair),
                    device_id=_device_id(ctx, v.row),
                    evidence={
                        "signal_dbm": v.station.get("signal"),
                        "normal_signal_dbm": round(signal_n, 1),
                        "ccq": v.station.get("ccq"),
                        "normal_ccq": round(ccq_n, 1),
                        "noise_dbm": v.station.get("noise"),
                        "reads_below_normal": v.track.get("degraded_reads"),
                    },
                )
            )
        return out


def _own_ap_channels(ctx: RuleContext) -> dict[int, list[str]]:
    """2.4 GHz channel -> names of the user's own UniFi access points on it."""
    out: dict[int, list[str]] = {}
    if not ctx.config.unifi.enabled:
        return out
    for r in ctx.store.infra("unifi-device"):
        for radio in r.data.get("radios") or []:
            if not isinstance(radio, dict) or not radio.get("channel"):
                continue
            try:
                band = float(radio.get("band") or 0)
            except (TypeError, ValueError):
                continue
            if 2.3 < band < 2.6:
                name = str(r.data.get("name") or r.data.get("model") or r.key)
                out.setdefault(int(radio["channel"]), []).append(name)
    return out


class AirosChannelOverlapRule(Rule):
    id = "airos.channel-overlap"
    kind = Kind.IMPROVEMENT
    default_severity = Severity.LOW
    description = (
        "A 2.4 GHz airMAX link that resends many frames (CCQ below 80% at one end) sits "
        "partly on top of the common Wi-Fi channels 1, 6 or 11, or on the same channel as "
        "your own access points (from [unifi]). Partial overlap is the worst case: neither "
        "side can hear the other well enough to take turns, so each is only noise to the "
        "other. lanwatch knows your own access points, not the neighbours': the suggestion is "
        "the one of 1, 6 and 11 yours use least; the radio's Site Survey shows the rest."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        own = _own_ap_channels(ctx)
        out: list[Finding] = []
        for pair, views in _links(ctx).items():
            # The AP end sets the channel; both ends report the same one.
            row = next((v.row for v in views if str(v.row.get("mode")).startswith("ap")), None)
            row = row or views[0].row
            f = row.get("frequency_mhz")
            if not isinstance(f, int) or not 2400 <= f <= 2500:
                continue
            width = int(row.get("channel_width_mhz") or WIFI_WIDTH_MHZ)
            reach = width / 2 + WIFI_WIDTH_MHZ / 2
            aligned = [c for c, fc in COMMON_CHANNELS.items() if abs(f - fc) <= 2]
            partial = [c for c, fc in COMMON_CHANNELS.items() if 2 < abs(f - fc) < reach]
            shared = [c for c in aligned if own.get(c)]
            if not partial and not shared:
                continue
            ccqs = [int(v.station["ccq"]) for v in views if v.station.get("ccq") is not None]
            if not ccqs or min(ccqs) >= CHANNEL_ADVICE_CCQ:
                continue  # it shares spectrum but gets its frames through
            best = min(COMMON_CHANNELS, key=lambda c: (len(own.get(c, [])), c))
            if partial:
                what = "overlaps Wi-Fi channel" + ("s " if len(partial) > 1 else " ")
                what += " and ".join(str(c) for c in partial) + " partly"
            else:
                what = f"shares Wi-Fi channel {shared[0]} with your access points"
            aps = sorted({name for c in partial + shared for name in own.get(c, [])})
            if own:
                n = len(own.get(best, []))
                advice = (
                    f"channel {best} ({COMMON_CHANNELS[best]} MHz) is used by {n} of your "
                    "access points; check the radio's Site Survey for the neighbours"
                )
            else:
                advice = (
                    "move it to exactly channel 1, 6 or 11 (2412, 2437 or 2462 MHz), "
                    "whichever is quietest"
                )
            out.append(
                self.finding(
                    ctx,
                    title=f"Radio link {views[0].title} (CCQ {min(ccqs)}%) on {f} MHz {what}"
                    + (f" ({', '.join(aps)})" if aps else "")
                    + f"; {advice}",
                    key_parts=list(pair),
                    device_id=_device_id(ctx, row),
                    evidence={
                        "frequency_mhz": f,
                        "width_mhz": width,
                        "partial_overlap": partial,
                        "same_channel_as_own_aps": shared,
                        "own_aps_by_channel": {str(c): own.get(c, []) for c in COMMON_CHANNELS},
                        "suggested_channel": best,
                        "suggested_mhz": COMMON_CHANNELS[best],
                        "ccq": {_name(v.row): v.station.get("ccq") for v in views},
                    },
                )
            )
        return out


class AirosCertificateChangedRule(Rule):
    id = "airos.certificate-changed"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = (
        "An airMAX radio presents another TLS certificate than the one lanwatch pinned the "
        "first time, so lanwatch no longer sends it the password. Expected after a factory "
        "reset or a replaced radio (then run `lanwatch airos --accept-cert HOST`); otherwise "
        "something may be sitting between lanwatch and the radio. A firmware upgrade keeps "
        "the certificate."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        return [
            self.finding(
                ctx,
                title=f"{_name(row)} ({row.get('host')}) presents another TLS certificate "
                "than the one lanwatch pinned",
                key_parts=[str(row.get("host"))],
                device_id=_device_id(ctx, row),
                evidence={"host": row.get("host"), "error": row.get("error")},
            )
            for row in _rows(ctx)
            if row.get("pin_failed")
        ]


class AirosLoginRejectedRule(Rule):
    id = "airos.login-rejected"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "An airMAX radio rejected lanwatch's read-only login. lanwatch does not try those "
        "credentials on it again (airOS locks the account after three failures), so the "
        "radio is no longer read until airos.username or airos.password changes. Check the "
        "read-only account on the radio (enabled, and applied)."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        return [
            self.finding(
                ctx,
                title=f"{_name(row)} ({row.get('host')}) rejected lanwatch's read-only login;"
                " it is no longer read",
                key_parts=[str(row.get("host"))],
                device_id=_device_id(ctx, row),
                evidence={"host": row.get("host"), "error": row.get("error")},
            )
            for row in _rows(ctx)
            if row.get("rejected")
        ]


RULES: list[Rule] = [
    AirosLinkDownRule(),
    AirosLinkPoorRule(),
    AirosLinkDegradedRule(),
    AirosChannelOverlapRule(),
    AirosCertificateChangedRule(),
    AirosLoginRejectedRule(),
]
