"""Version-based rules.

`service.legacy-version` matches reported product versions against a small curated table
of thresholds below which a service is out of upstream support and has well-known public
issues. It is deliberately conservative and ships with the code, so it needs no network
and cannot hallucinate. Distributions backport fixes, so a hit means "check", not "owned".

`service.known-cves` reads the output of nmap's `vulners` script (opt-in, talks to
vulners.com) and reports entries at or above scan.vulners_min_cvss. Same caveat, louder.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from lanwatch.models import Device, Finding, Kind, ServiceRow, Severity, iso, now_utc
from lanwatch.rules.base import Rule, RuleContext
from lanwatch.rules.services import ServiceRule

# product substring (as nmap reports it) -> (minimum version, why)
LEGACY_VERSIONS: list[tuple[str, str, str]] = [
    (
        "OpenSSH",
        "7.4",
        "releases before 7.4 (2016) are unsupported upstream and predate several fixes",
    ),
    ("Dropbear", "2019.78", "releases before 2019.78 have known auth and parsing issues"),
    ("dnsmasq", "2.83", "releases before 2.83 are affected by the DNSpooq cache-poisoning issues"),
    ("Samba", "4.10", "4.9 and older are out of security support"),
    ("ProFTPD", "1.3.6", "older releases have well-known remote issues"),
    ("vsftpd", "3.0.3", "older releases are unsupported"),
    ("nginx", "1.18", "older releases are out of support"),
    ("Apache httpd", "2.4.41", "older 2.4 releases carry multiple fixed issues"),
    ("lighttpd", "1.4.54", "older releases are out of support"),
    ("MiniUPnP", "2.1", "older miniupnpd releases have known issues in SOAP handling"),
    ("Exim", "4.94", "older releases are affected by the 21nails issues"),
    ("MySQL", "5.7", "5.6 and older are end of life"),
    ("PostgreSQL", "12", "11 and older are end of life"),
]

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def version_tuple(text: str | None) -> tuple[int, ...] | None:
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _older(found: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    n = max(len(found), len(minimum))
    return found + (0,) * (n - len(found)) < minimum + (0,) * (n - len(minimum))


class LegacyVersionRule(ServiceRule):
    id = "service.legacy-version"
    kind = Kind.PROBLEM
    default_severity = Severity.MEDIUM
    description = (
        "Service reports a version below the curated support threshold (check for backports)."
    )

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        if not s.product:
            return None
        found = version_tuple(s.version)
        if found is None:
            return None
        for product, minimum, why in LEGACY_VERSIONS:
            if product.lower() in s.product.lower():
                min_t = version_tuple(minimum)
                if min_t and _older(found, min_t):
                    return (
                        f"Legacy {s.product} {s.version}",
                        {"minimum": minimum, "why": why},
                    )
                return None
        return None


class KnownCvesRule(ServiceRule):
    id = "service.known-cves"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    description = (
        "nmap vulners matched the reported version to published CVEs (opt-in, online; "
        "version matching ignores distro backports)."
    )

    def __init__(self, min_cvss: float = 7.0) -> None:
        self.min_cvss = min_cvss

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        self.min_cvss = ctx.config.scan.vulners_min_cvss
        return super().evaluate(ctx)

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        data = s.script("vulners")
        if not isinstance(data, dict):
            return None
        hits: list[dict[str, Any]] = []
        for cpe, entries in data.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if not isinstance(e, dict):
                    continue
                try:
                    cvss = float(e.get("cvss", 0))
                except (TypeError, ValueError):
                    continue
                if cvss >= self.min_cvss and str(e.get("type", "cve")) == "cve":
                    hits.append({"id": str(e.get("id")), "cvss": cvss, "cpe": cpe})
        if not hits:
            return None
        hits.sort(key=lambda h: -h["cvss"])
        top = hits[0]
        product = f"{s.product} {s.version or ''}".strip()
        return (
            f"{len(hits)} published CVEs (max CVSS {top['cvss']:.1f}) for {product}",
            {"cves": hits[:10], "total": len(hits), "max_cvss": top["cvss"]},
        )


class FirmwareOutdatedRule(Rule):
    id = "device.firmware-outdated"
    kind = Kind.IMPROVEMENT
    default_severity = Severity.LOW
    # A check older than this says nothing about now (the device may be off, or the check
    # switched off); the finding then resolves rather than lingering.
    MAX_AGE = timedelta(days=3)
    description = (
        "A device runs an older firmware or software version than the latest release. Found "
        "by the daily firmware check ([firmware] in the config) for the products it knows: "
        "Home Assistant, ESPHome, Shelly, Tasmota, Pi-hole, Jellyfin, for UniFi gear "
        "through the controller ([unifi]), and for airMAX radios through [airos]. Raise the "
        "severity under [rules] if you want to be notified."
    )

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        fresh = iso(now_utc() - self.MAX_AGE)
        out: list[Finding] = []
        for d in ctx.store.devices():
            fw = d.attrs.get("firmware")
            if not isinstance(fw, dict) or fw.get("update") is not True:
                continue
            if str(fw.get("checked") or "") < fresh:
                continue
            out.append(
                self.finding(
                    ctx,
                    title=f"{d.label}: {fw.get('product')} {fw.get('version')} "
                    + (
                        f"is behind {fw.get('latest')}"
                        if fw.get("latest")
                        else "has an update available"
                    ),
                    key_parts=[d.key, str(fw.get("product"))],
                    device_id=d.id,
                    evidence={
                        "product": fw.get("product"),
                        "model": fw.get("model") or None,
                        "running": fw.get("version"),
                        "latest": fw.get("latest"),
                        "read_via": fw.get("source"),
                        "checked": fw.get("checked"),
                    },
                )
            )
        return out


RULES: list[Rule] = [LegacyVersionRule(), KnownCvesRule(), FirmwareOutdatedRule()]
