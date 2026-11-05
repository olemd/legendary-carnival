"""Decoy name lookups: ask the local network for a name that does not exist.

Windows-era name resolution (LLMNR, NetBIOS) and mDNS let any machine on the segment
answer a lookup. Poisoning tools such as Responder answer *every* lookup with their own
address, to catch the credentials a client then sends them. Nothing legitimate answers
for a random name, so one answer is enough to know such a tool is running, and where.

Plain UDP from an unprivileged port; nothing leaves the local segment.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import socket
import string
from dataclasses import dataclass

from lanwatch import dnswire

log = logging.getLogger(__name__)

LLMNR = ("224.0.0.252", 5355)
MDNS = ("224.0.0.251", 5353)
NBNS_PORT = 137


@dataclass(slots=True, frozen=True)
class PoisonAnswer:
    protocol: str  # llmnr | mdns | netbios
    responder: str
    name: str


def random_name(length: int = 12) -> str:
    """Looks like a mistyped host name; exists nowhere."""
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))


def is_poisoned_answer(protocol: str, data: bytes, ident: int, name: str) -> bool:
    """Is this datagram a positive answer to our question for a name that does not exist?"""
    try:
        r = dnswire.parse_response(data)
    except ValueError:
        return False
    if not r.is_response or r.rcode != dnswire.RCODE_OK or not r.answers:
        return False
    if protocol == "mdns":
        # mDNS has no transaction id to match; go by the name answered for.
        return any(a.name.lower() == f"{name}.local" for a in r.answers)
    return r.ident == ident


class _Collector(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.datagrams: list[tuple[bytes, str]] = []

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.datagrams.append((data, addr[0]))


async def probe_name_poisoning(
    interfaces: list[tuple[str, str]], timeout: float = 2.0
) -> list[PoisonAnswer]:
    """Ask on each (local address, broadcast address) pair; return whoever answered."""
    loop = asyncio.get_running_loop()
    name = random_name()
    own = {ip for ip, _ in interfaces}
    pending: list[tuple[str, int, _Collector, asyncio.DatagramTransport]] = []
    for local, broadcast in interfaces:
        plans = [
            ("llmnr", dnswire.build_query(name, recursion=False), LLMNR),
            ("mdns", dnswire.build_query(f"{name}.local", unicast_reply=True), MDNS),
            ("netbios", dnswire.netbios_query(name), (broadcast, NBNS_PORT)),
        ]
        for protocol, packet, destination in plans:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setblocking(False)
                sock.bind((local, 0))
                if protocol == "netbios":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                else:
                    sock.setsockopt(
                        socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local)
                    )
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                transport, collector = await loop.create_datagram_endpoint(_Collector, sock=sock)
                transport.sendto(packet, destination)
            except OSError as e:
                log.debug("%s probe from %s failed: %s", protocol, local, e)
                sock.close()
                continue
            ident = int.from_bytes(packet[:2], "big")
            pending.append((protocol, ident, collector, transport))
    try:
        await asyncio.sleep(timeout)
    finally:
        for _, _, _, transport in pending:
            with contextlib.suppress(Exception):
                transport.close()
    answers = {
        PoisonAnswer(protocol, responder, name)
        for protocol, ident, collector, _ in pending
        for data, responder in collector.datagrams
        if responder not in own and is_poisoned_answer(protocol, data, ident, name)
    }
    return sorted(answers, key=lambda a: (a.responder, a.protocol))
