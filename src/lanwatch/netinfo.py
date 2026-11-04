"""Local interfaces and subnet selection. Default: every IPv4 subnet this host is on,
minus excluded interfaces, link-local, loopback and anything wider than max_auto_prefix."""

from __future__ import annotations

import fcntl
import fnmatch
import ipaddress
import json
import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from lanwatch.collectors.base import run_cmd
from lanwatch.config import NetworkConfig

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Interface:
    name: str
    mac: str | None
    addrs: list[ipaddress.IPv4Interface] = field(default_factory=list)
    up: bool = True


@dataclass(slots=True, frozen=True)
class Subnet:
    network: ipaddress.IPv4Network
    interface: str | None

    def __str__(self) -> str:
        return f"{self.network}" + (f" via {self.interface}" if self.interface else "")


def parse_ip_addr_json(data: list[dict[str, Any]]) -> list[Interface]:
    out: list[Interface] = []
    for entry in data:
        name = str(entry.get("ifname", ""))
        if not name:
            continue
        mac = entry.get("address") if entry.get("link_type") == "ether" else None
        flags = entry.get("flags", [])
        iface = Interface(name=name, mac=mac, up="UP" in flags and "LOWER_UP" in flags)
        for a in entry.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            try:
                iface.addrs.append(ipaddress.IPv4Interface(f"{a['local']}/{a['prefixlen']}"))
            except (KeyError, ValueError):
                continue
        out.append(iface)
    return out


async def list_interfaces() -> list[Interface]:
    """`ip -j addr` when available (all addresses), else ioctl (primary IPv4 per interface)."""
    rc, out, _ = await run_cmd(["ip", "-j", "addr", "show"], timeout=10)
    if rc == 0 and out.strip():
        try:
            return parse_ip_addr_json(json.loads(out))
        except ValueError:
            log.debug("ip -j addr returned non-JSON, falling back to ioctl")
    else:
        log.debug("ip -j addr unavailable (rc=%s), falling back to ioctl", rc)
    return list_interfaces_ioctl()


_SIOCGIFFLAGS = 0x8913
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B
_SIOCGIFHWADDR = 0x8927
_IFF_UP = 0x1
_IFF_RUNNING = 0x40
_ARPHRD_ETHER = 1


def list_interfaces_ioctl() -> list[Interface]:
    """Pure-stdlib interface listing for hosts without iproute2 or with busybox `ip`."""
    out: list[Interface] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _, name in socket.if_nameindex():
            ifreq = struct.pack("16s24s", name.encode()[:15], b"\0" * 24)
            try:
                flags = struct.unpack_from("H", fcntl.ioctl(s, _SIOCGIFFLAGS, ifreq), 16)[0]
            except OSError:
                continue
            up = bool(flags & _IFF_UP) and bool(flags & _IFF_RUNNING)
            mac: str | None = None
            try:
                hw = fcntl.ioctl(s, _SIOCGIFHWADDR, ifreq)
                if struct.unpack_from("H", hw, 16)[0] == _ARPHRD_ETHER:
                    mac = ":".join(f"{b:02x}" for b in hw[18:24])
            except OSError:
                pass
            iface = Interface(name=name, mac=mac, up=up)
            try:
                ip = socket.inet_ntoa(fcntl.ioctl(s, _SIOCGIFADDR, ifreq)[20:24])
                mask = fcntl.ioctl(s, _SIOCGIFNETMASK, ifreq)[20:24]
                prefix = bin(int.from_bytes(mask, "big")).count("1")
                iface.addrs.append(ipaddress.IPv4Interface(f"{ip}/{prefix}"))
            except OSError:
                pass  # no IPv4 address
            out.append(iface)
    return out


def _excluded(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def select_subnets(ifaces: list[Interface], cfg: NetworkConfig) -> list[Subnet]:
    usable = [i for i in ifaces if i.up and not _excluded(i.name, cfg.exclude_interfaces)]

    if cfg.subnets != "auto":
        out: list[Subnet] = []
        for s in cfg.subnets:
            net = ipaddress.ip_network(s, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                log.warning("skipping %s: only IPv4 subnets are scanned for now", s)
                continue
            via = next((i.name for i in usable for a in i.addrs if a.network.overlaps(net)), None)
            out.append(Subnet(network=net, interface=via))
        return out

    seen: set[ipaddress.IPv4Network] = set()
    auto: list[Subnet] = []
    for i in usable:
        for a in i.addrs:
            net = a.network
            if net in seen or net.is_loopback or net.is_link_local:
                continue
            if net.prefixlen < cfg.max_auto_prefix:
                log.warning(
                    "skipping %s on %s: wider than /%d (set network.subnets explicitly)",
                    net,
                    i.name,
                    cfg.max_auto_prefix,
                )
                continue
            seen.add(net)
            auto.append(Subnet(network=net, interface=i.name))
    return auto


def self_observations(
    ifaces: list[Interface], subnets: list[Subnet]
) -> list[tuple[str, str | None]]:
    """(ip, mac) for this host's own addresses inside the scanned subnets."""
    out: list[tuple[str, str | None]] = []
    nets = [s.network for s in subnets]
    for i in ifaces:
        for a in i.addrs:
            if any(a.ip in n for n in nets):
                out.append((str(a.ip), i.mac))
    return out
