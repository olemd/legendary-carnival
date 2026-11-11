"""Devices that belong together without being one device.

A BMC (HPE iLO, Dell iDRAC, a Supermicro IPMI card) is its own device with its own
address, firmware and findings, but it controls the power, console and virtual media of
one server. Links record such relations. They are made by hand, or suggested here and
confirmed by a person: a wrong link is worse than none, so nothing is applied silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from lanwatch.models import Device, LinkRow, ServiceRow

# kind -> (how `a` relates to `b`, how `b` relates to `a`)
KINDS: dict[str, tuple[str, str]] = {
    "manages": ("manages", "managed by"),
    "uplink": ("hangs off", "uplink of"),
    "powered-by": ("powered by", "powers"),
}

# Choices for the device page's "link to another device" form: (value, label). The value
# is "<kind>:<direction>", where "out" makes this device `a` and "in" makes it `b`.
RELATIONS: list[tuple[str, str]] = [
    (f"{kind}:{d}", phrases[0] if d == "out" else phrases[1])
    for kind, phrases in KINDS.items()
    for d in ("out", "in")
]


def parse_relation(value: str) -> tuple[str, bool] | None:
    """ "manages:out" -> ("manages", True): the kind, and whether this device is `a`."""
    kind, _, direction = value.partition(":")
    if kind not in KINDS or direction not in ("out", "in"):
        return None
    return kind, direction == "out"


def phrase(link: LinkRow, device_id: int) -> str:
    """How the device relates to the other end of the link, seen from `device_id`."""
    forward, backward = KINDS.get(link.kind, (link.kind, f"{link.kind} (reverse)"))
    return forward if link.a_id == device_id else backward


def other_end(link: LinkRow, device_id: int) -> int:
    return link.b_id if link.a_id == device_id else link.a_id


# -- recognising a BMC ---------------------------------------------------------

# Free text (service banners, page titles, certificate fields) that names a BMC.
_BMC_TEXT: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"integrated lights[- ]out|\bilo ?[2-7]?\b|\bhpe? ilo", re.I), "iLO"),
    (re.compile(r"\bidrac\d*\b|dell remote access", re.I), "iDRAC"),
    (re.compile(r"\bimm2?\b|integrated management module|\bxclarity controller", re.I), "IMM"),
    (re.compile(r"\bipmi\b|\bbmc\b|megarac|supermicro.*(?:ipmi|bmc)", re.I), "BMC"),
]
# Words in a host name that mark it as a BMC's name: "hydra-ilo", "ilo-hydra", "hydra-ipmi".
_BMC_WORDS: dict[str, str] = {
    "ilo": "iLO",
    "ilo2": "iLO",
    "ilo3": "iLO",
    "ilo4": "iLO",
    "ilo5": "iLO",
    "ilo6": "iLO",
    "idrac": "iDRAC",
    "drac": "iDRAC",
    "imm": "IMM",
    "xcc": "IMM",
    "ipmi": "BMC",
    "bmc": "BMC",
}
# HPE's factory iLO host name: "ILO" and the server's serial number.
_ILO_DEFAULT = re.compile(r"^ilo[a-z0-9]{8,}$", re.I)
# HPE Insight Management agents (iLO) answer SNMP with an object ID under this.
_HPE_ILO_OID = "1.3.6.1.4.1.232.9"


def _label(name: str | None) -> str:
    """First DNS label, lower case: "hydra-ilo.example.net" -> "hydra-ilo"."""
    return (name or "").strip().lower().split(".", 1)[0]


def _words(label: str) -> list[str]:
    return [w for w in re.split(r"[-_\s]+", label) if w]


def _texts(d: Device, services: list[ServiceRow]) -> list[str]:
    out: list[str] = []
    for s in services:
        out += [x for x in (s.product, s.extrainfo) if x]
        title = s.script("http-title")
        if isinstance(title, dict) and title.get("title"):
            out.append(str(title["title"]))
        cert = s.script("ssl-cert")
        if isinstance(cert, dict):
            for part in ("subject", "issuer"):
                fields = cert.get(part)
                if isinstance(fields, dict):
                    out += [str(v) for v in fields.values() if isinstance(v, str)]
    upnp = d.attrs.get("upnp")
    if isinstance(upnp, dict):
        out += [str(v) for v in upnp.values() if isinstance(v, str)]
    audit = d.attrs.get("snmp_audit")
    if isinstance(audit, dict) and audit.get("sys_descr"):
        out.append(str(audit["sys_descr"]))
    return out


def bmc_type(d: Device, services: list[ServiceRow]) -> str | None:
    """ "iLO", "iDRAC", "IMM" or "BMC" when the device looks like a server's management
    card, else None."""
    for name in (d.hostname, d.name):
        label = _label(name)
        if _ILO_DEFAULT.match(label):
            return "iLO"
        for w in _words(label):
            if w in _BMC_WORDS:
                return _BMC_WORDS[w]
    audit = d.attrs.get("snmp_audit")
    if isinstance(audit, dict):
        oid = str(audit.get("sys_object_id") or "").lstrip(".")
        if oid == _HPE_ILO_OID or oid.startswith(_HPE_ILO_OID + "."):
            return "iLO"
    for text in _texts(d, services):
        for pattern, kind in _BMC_TEXT:
            if pattern.search(text):
                return kind
    return None


def managed_names(d: Device, services: list[ServiceRow]) -> set[str]:
    """Host names (first labels, lower case) the server behind a BMC may go by.

    "hydra-ilo" and "ilo-hydra" give "hydra". A name without a BMC word is taken as it
    is: these iLOs report their server's name ("hydra.example.net") as their own."""
    names: list[str] = [d.hostname or "", d.name or ""]
    audit = d.attrs.get("snmp_audit")
    if isinstance(audit, dict):
        names.append(str(audit.get("sys_name") or ""))
    for s in services:
        cert = s.script("ssl-cert")
        subject = cert.get("subject") if isinstance(cert, dict) else None
        if isinstance(subject, dict) and isinstance(subject.get("commonName"), str):
            names.append(subject["commonName"])
    out: set[str] = set()
    for name in names:
        label = _label(name)
        if not label or _ILO_DEFAULT.match(label) or not re.fullmatch(r"[a-z0-9_ -]+", label):
            continue
        rest = [w for w in _words(label) if w not in _BMC_WORDS and w not in ("mgmt", "oob")]
        if rest:
            out.add("-".join(rest))  # "Hydra iLO" -> "hydra", "ilo-db-1" -> "db-1"
    return out


@dataclass(frozen=True, slots=True)
class Suggestion:
    a_id: int
    b_id: int
    kind: str
    source: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "a_id": self.a_id,
            "b_id": self.b_id,
            "kind": self.kind,
            "source": self.source,
            "reason": self.reason,
        }


def suggest(
    devices: list[Device],
    services: dict[int, list[ServiceRow]],
    known: set[tuple[int, int, str]],
) -> list[Suggestion]:
    """Links worth asking about: each BMC with the server its name points at.

    `known` holds (a, b, kind) of links that exist or were turned down; neither is
    suggested again. A name that matches several servers suggests nothing: guessing
    between them is exactly the wrong link this is meant to avoid."""
    bmcs = {d.id: t for d in devices if (t := bmc_type(d, services.get(d.id, [])))}
    by_name: dict[str, list[Device]] = {}
    for d in devices:
        if d.id in bmcs:
            continue
        for label in {_label(d.hostname), _label(d.name)} - {""}:
            by_name.setdefault(label, []).append(d)
    out: list[Suggestion] = []
    for d in devices:
        if d.id not in bmcs:
            continue
        hosts: dict[int, tuple[Device, str]] = {}
        for name in sorted(managed_names(d, services.get(d.id, []))):
            for h in by_name.get(name, []):
                hosts.setdefault(h.id, (h, name))
        if len(hosts) != 1:
            continue
        h, name = next(iter(hosts.values()))
        if (d.id, h.id, "manages") in known or (h.id, d.id, "manages") in known:
            continue
        out.append(
            Suggestion(
                a_id=d.id,
                b_id=h.id,
                kind="manages",
                source="name-match",
                reason=f"{bmcs[d.id]} {d.label} goes by the name {name}, like {h.label}",
            )
        )
    return out


def managing_bmc(device_id: int, links: list[LinkRow], devices: dict[int, Device]) -> Device | None:
    """The online BMC that manages this device, if there is one: a server that does not
    answer while its BMC does is most likely powered off, not gone."""
    for link in links:
        if link.kind == "manages" and link.b_id == device_id:
            bmc = devices.get(link.a_id)
            if bmc is not None and bmc.online:
                return bmc
    return None
