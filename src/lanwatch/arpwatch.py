"""Passive ARP listener. The active scan asks who is there every five minutes; this hears
what the network says in between, without sending anything.

Two things are read out of the ARP traffic:

- an IP address claimed by two MAC addresses that keep taking it back from each other.
  That alternation is what ARP spoofing looks like: the real owner keeps announcing
  itself while the impostor keeps overwriting it. A single hand-over (a DHCP lease that
  moved to another device) is normal and not reported.
- a sender asking for a great many addresses: something is mapping the network.

It needs a packet socket and therefore CAP_NET_RAW, so it lives where that privilege is:
in lanwatch-helper for the packaged service, or in the main process when that runs as root.
Frames this machine sends itself (its own ARP scan) are never counted.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
import struct
import time
from collections import deque
from typing import Any

log = logging.getLogger(__name__)

ETH_P_ARP = 0x0806
PACKET_OUTGOING = 4
ARP_REQUEST = 1
# Senders asking for fewer distinct addresses than this are not worth reporting upward.
SWEEP_MIN_TARGETS = 10
MAX_FRAMES = 50_000
MAX_WINDOW_S = 3600.0


def parse_arp(packet: bytes) -> tuple[int, str, str, str] | None:
    """An Ethernet/IPv4 ARP packet -> (operation, sender MAC, sender IP, target IP)."""
    if len(packet) < 28:
        return None
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", packet[:8])
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
        return None
    sender_mac = ":".join(f"{b:02x}" for b in packet[8:14])
    sender_ip = str(ipaddress.IPv4Address(packet[14:18]))
    target_ip = str(ipaddress.IPv4Address(packet[24:28]))
    return op, sender_mac, sender_ip, target_ip


class ArpWatch:
    def __init__(self) -> None:
        # (monotonic time, operation, sender MAC, sender IP, target IP)
        self._frames: deque[tuple[float, int, str, str, str]] = deque(maxlen=MAX_FRAMES)
        self._sock: socket.socket | None = None
        self.error: str | None = None

    @property
    def listening(self) -> bool:
        return self._sock is not None

    def start(self) -> bool:
        """Open the packet socket on the running event loop. False (with .error set) when
        that is not possible, typically for lack of CAP_NET_RAW."""
        if self._sock is not None:
            return True
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ARP))
            sock.setblocking(False)
        except OSError as e:
            self.error = e.strerror or str(e)
            return False
        self._sock = sock
        asyncio.get_running_loop().add_reader(sock.fileno(), self._readable)
        log.info("listening to ARP traffic")
        return True

    def stop(self) -> None:
        if self._sock is None:
            return
        with contextlib.suppress(Exception):
            asyncio.get_running_loop().remove_reader(self._sock.fileno())
        self._sock.close()
        self._sock = None

    def _readable(self) -> None:
        assert self._sock is not None
        for _ in range(256):  # drain what has arrived, without starving the loop
            try:
                packet, address = self._sock.recvfrom(128)
            except BlockingIOError:
                return
            except OSError as e:
                log.warning("ARP listener stopped: %s", e)
                self.stop()
                return
            self.feed(packet, outgoing=address[2] == PACKET_OUTGOING)

    def feed(self, packet: bytes, outgoing: bool = False, now: float | None = None) -> None:
        if outgoing:
            return  # our own ARP scan would look like the biggest sweep on the network
        parsed = parse_arp(packet)
        if parsed is not None:
            self._frames.append((time.monotonic() if now is None else now, *parsed))

    def report(self, window_s: float, now: float | None = None) -> dict[str, Any]:
        """What the last `window_s` seconds of ARP traffic showed."""
        now = time.monotonic() if now is None else now
        since = now - min(max(window_s, 1.0), MAX_WINDOW_S)
        claimants: dict[str, list[str]] = {}  # ip -> MACs in the order they claimed it
        asked: dict[str, set[str]] = {}  # sender MAC -> addresses it asked for
        sender_ip: dict[str, str] = {}
        frames = 0
        for ts, op, mac, ip, target in self._frames:
            if ts < since:
                continue
            frames += 1
            if ip != "0.0.0.0":  # an address probe carries no claim
                sender_ip[mac] = ip
                seq = claimants.setdefault(ip, [])
                if not seq or seq[-1] != mac:
                    seq.append(mac)
            if op == ARP_REQUEST and target != ip:
                asked.setdefault(mac, set()).add(target)
        return {
            "frames": frames,
            "window_s": round(now - since),
            # Three entries or more means the address changed hands at least twice.
            "conflicts": {
                ip: sorted(set(seq)) for ip, seq in sorted(claimants.items()) if len(seq) >= 3
            },
            "sweeps": [
                {"mac": mac, "ip": sender_ip.get(mac, ""), "targets": sorted(targets)}
                for mac, targets in sorted(asked.items())
                if len(targets) >= SWEEP_MIN_TARGETS
            ],
        }


_shared: ArpWatch | None = None


def shared() -> ArpWatch:
    """The process's one listener, started on first use."""
    global _shared
    if _shared is None:
        _shared = ArpWatch()
    return _shared
