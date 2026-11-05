"""Does the network's DNS resolver filter anything?

Asks the resolver that DHCP hands out for a few names whose only purpose is to be blocked
by filtering resolvers, and looks at the answers. Off by default: unlike everything else
lanwatch does, these lookups leave the network (through that resolver, as every lookup of
every device does).

The test names and what a block looks like were checked against the providers'
documentation and live resolvers (2026-11):

- doubleclick.net             on Pi-hole's default list (StevenBlack) and the AdGuard DNS
                              filter. Pi-hole and AdGuard Home answer 0.0.0.0 by default.
- malware.testcategory.com    Cloudflare for Families (1.1.1.2/1.1.1.3) answers 0.0.0.0.
- isitblocked.org             Quad9 answers NXDOMAIN.
- internetbadguys.com         OpenDNS answers with a block page in 146.112.61.104/29.

The last three exist only to be blocked by that one provider; elsewhere they resolve
normally, so they detect that provider's threat filtering and nothing more.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
from pathlib import Path
from typing import Any

from lanwatch import dnswire

log = logging.getLogger(__name__)

CONTROL = "example.com"
AD_TESTS = ("doubleclick.net",)
THREAT_TESTS = {
    "malware.testcategory.com": "Cloudflare for Families",
    "isitblocked.org": "Quad9",
    "internetbadguys.com": "OpenDNS",
}
RCODE_REFUSED = 5
# OpenDNS / Cisco Umbrella block pages (documented: .104 to .110).
_BLOCK_PAGES = ipaddress.ip_network("146.112.61.104/29")


async def query(resolver: str, name: str, timeout: float = 3.0) -> dnswire.Response | None:
    """One A query over UDP. None when the resolver did not answer in time."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    packet = dnswire.build_query(name)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (resolver, 53))
            await loop.sock_sendall(sock, packet)
            data = await asyncio.wait_for(loop.sock_recv(sock, 2048), timeout)
        except (TimeoutError, OSError):
            return None
    with contextlib.suppress(ValueError):
        r = dnswire.parse_response(data)
        if r.is_response and r.ident == int.from_bytes(packet[:2], "big"):
            return r
    return None


def is_blocked(response: dnswire.Response) -> bool:
    """Did a resolver refuse to resolve a name that does exist? The usual ways to say so:
    "no such name", "refused", no address at all, or an address that leads nowhere
    (0.0.0.0, loopback, a private address or a block page)."""
    if response.rcode in (dnswire.RCODE_NXDOMAIN, RCODE_REFUSED):
        return True
    if response.rcode != dnswire.RCODE_OK:
        return False  # a server failure is not a verdict
    addresses = [ipaddress.ip_address(a) for a in response.addresses()]
    if not addresses:
        return True
    return all(
        a.is_unspecified or a.is_loopback or a.is_private or a in _BLOCK_PAGES for a in addresses
    )


async def check_resolver(resolver: str) -> dict[str, Any]:
    """Ask one resolver for the control name and the test names."""
    result: dict[str, Any] = {
        "resolver": resolver,
        "working": False,
        "ads": None,
        "threats": None,
        "blocked": [],
    }
    control = await query(resolver, CONTROL)
    # A resolver that blocks or hijacks example.com tells us nothing about filtering.
    if control is None or is_blocked(control):
        return result
    result["working"] = True
    blocked: list[str] = []
    answered: dict[str, bool] = {}
    for name in (*AD_TESTS, *THREAT_TESTS):
        r = await query(resolver, name)
        if r is None:
            continue
        answered[name] = is_blocked(r)
        if answered[name]:
            blocked.append(name)
    if any(n in answered for n in AD_TESTS):
        result["ads"] = any(answered.get(n) for n in AD_TESTS)
    if any(n in answered for n in THREAT_TESTS):
        result["threats"] = any(answered.get(n) for n in THREAT_TESTS)
        result["provider"] = next((p for n, p in THREAT_TESTS.items() if answered.get(n)), None)
    result["blocked"] = blocked
    return result


def system_resolvers(path: Path = Path("/etc/resolv.conf")) -> list[str]:
    """This machine's own resolvers, for when no DHCP offer has been seen."""
    out: list[str] = []
    with contextlib.suppress(OSError):
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                with contextlib.suppress(ValueError):
                    out.append(str(ipaddress.ip_address(parts[1].split("%", 1)[0])))
    return out
