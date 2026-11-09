"""What the internet sees of this network: a daily lookup of the public address in Shodan's
InternetDB (https://internetdb.shodan.io, free, no key).

Shodan scans the whole internet continuously. Its answer for our public address is the
outside view that no scan from inside can give: which ports actually answer from the
internet, what the service there is known as, and whether it matches published
vulnerabilities. It complements the UPnP mapping rule (what the router *says* it forwards)
with what *is* reachable, including forwards made by hand on the router.

This sends the public address to Shodan and, to learn that address when no UPnP gateway
tells us, one request to a "what is my IP" service. Both are off until [exposure] enabled
is set to true: it is the only place lanwatch tells a third party anything about this
network.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx2

from lanwatch import __version__
from lanwatch.config import Config
from lanwatch.models import iso, now_utc
from lanwatch.store import Store

log = logging.getLogger(__name__)

INTERNETDB = "https://internetdb.shodan.io/{ip}"
HEADERS = {"User-Agent": f"lanwatch/{__version__}", "Accept": "application/json"}
INFRA_KIND = "exposure"


@dataclass(slots=True)
class Exposure:
    ip: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Where the public address came from: "upnp" (the gateway said so) or "lookup".
    ip_source: str = "lookup"

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "ports": sorted(self.ports),
            "hostnames": sorted(self.hostnames),
            "vulns": sorted(self.vulns),
            "cpes": sorted(self.cpes),
            "tags": sorted(self.tags),
            "ip_source": self.ip_source,
            "checked": iso(now_utc()),
        }


def parse_internetdb(ip: str, data: Any) -> Exposure:
    """InternetDB's JSON -> Exposure. Lists are checked item by item: the answer is data
    from a third party, and the rules and templates trust what is stored."""
    if not isinstance(data, dict):
        return Exposure(ip=ip)

    def strs(key: str) -> list[str]:
        v = data.get(key)
        return [str(x) for x in v if isinstance(x, str | int)] if isinstance(v, list) else []

    ports = data.get("ports")
    return Exposure(
        ip=ip,
        ports=[int(p) for p in ports if isinstance(p, int) and 0 < p < 65536]
        if isinstance(ports, list)
        else [],
        hostnames=strs("hostnames"),
        vulns=strs("vulns"),
        cpes=strs("cpes"),
        tags=strs("tags"),
    )


def public_ip_from_upnp(store: Store) -> str | None:
    """The external address an Internet Gateway Device reported, if any and if it is really
    a public one (a gateway behind carrier-grade NAT reports a private address)."""
    for r in store.infra("upnp"):
        ext = r.data.get("external_ip")
        if isinstance(ext, str) and _is_public(ext):
            return ext
    return None


def _is_public(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


async def lookup_public_ip(client: httpx2.AsyncClient, url: str) -> str | None:
    r = await client.get(url, headers={"User-Agent": HEADERS["User-Agent"]})
    r.raise_for_status()
    text = r.text.strip()
    return text if _is_public(text) else None


async def fetch_exposure(client: httpx2.AsyncClient, ip: str) -> Exposure:
    r = await client.get(INTERNETDB.format(ip=ip), headers=HEADERS)
    if r.status_code == 404:
        return Exposure(ip=ip)  # Shodan has nothing on this address: nothing answers
    r.raise_for_status()
    return parse_internetdb(ip, r.json())


async def check_exposure(
    config: Config, store: Store, client: httpx2.AsyncClient | None = None
) -> Exposure | None:
    """Find the public address, ask InternetDB about it, store the answer as infra of kind
    "exposure" (current-state: an address no longer ours disappears). None when the public
    address could not be determined."""
    own = client is None
    client = client or httpx2.AsyncClient(timeout=20, follow_redirects=False)
    try:
        ip = public_ip_from_upnp(store)
        source = "upnp"
        if ip is None:
            ip = await lookup_public_ip(client, config.exposure.ip_lookup_url)
            source = "lookup"
        if ip is None:
            log.warning("exposure check: could not determine the public address")
            return None
        exposure = await fetch_exposure(client, ip)
        exposure.ip_source = source
    finally:
        if own:
            await client.aclose()
    snapshot_id = store.begin_snapshot("exposure", "internetdb")
    store.replace_infra(INFRA_KIND, {ip: exposure.as_dict()}, snapshot_id)
    store.finish_snapshot(snapshot_id, 1)
    log.info(
        "exposure check: %s has %d port%s visible from the internet%s",
        ip,
        len(exposure.ports),
        "" if len(exposure.ports) == 1 else "s",
        f", {len(exposure.vulns)} known vulnerabilities" if exposure.vulns else "",
    )
    return exposure
