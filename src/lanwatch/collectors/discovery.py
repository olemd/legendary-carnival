"""Host discovery. Backends in preference order: arp-scan, nmap -sn, plain ping sweep.

All three produce HostObservation. The ping sweep is pure Linux userland and always
available; it reads MACs from the kernel neighbour table afterwards.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Protocol

from lanwatch.collectors.base import have, run_cmd
from lanwatch.config import ScanConfig
from lanwatch.models import HostObservation
from lanwatch.netinfo import Subnet

log = logging.getLogger(__name__)

NMAP_TIMING = {"gentle": "-T2", "normal": "-T3", "thorough": "-T4"}


class DiscoveryBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    async def discover(self, subnets: list[Subnet], cfg: ScanConfig) -> list[HostObservation]: ...


# -- arp-scan ---------------------------------------------------------------


def parse_arp_scan_plain(text: str, source: str = "arp-scan") -> list[HostObservation]:
    """`arp-scan --plain` prints: IP<TAB>MAC<TAB>Vendor."""
    out: list[HostObservation] = []
    for line in text.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 2:
            continue
        ip, mac = parts[0].strip(), parts[1].strip()
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        vendor = parts[2].strip() if len(parts) > 2 else None
        if vendor and vendor.lower().startswith("(unknown"):
            vendor = None
        out.append(HostObservation(ip=ip, mac=mac, vendor=vendor, source=source))
    return out


class ArpScanBackend:
    name = "arp-scan"

    def available(self) -> bool:
        return have("arp-scan") and os.geteuid() == 0

    async def discover(self, subnets: list[Subnet], cfg: ScanConfig) -> list[HostObservation]:
        interval_ms = max(1, 1000 // cfg.rate_limit_pps)
        hosts: list[HostObservation] = []
        for s in subnets:
            if s.interface is None:
                log.warning("arp-scan: no interface for %s, skipping", s.network)
                continue
            args = [
                "arp-scan",
                "--plain",
                "--retry=2",
                f"--interval={interval_ms}",
                f"--interface={s.interface}",
                str(s.network),
            ]
            rc, out, err = await run_cmd(args, timeout=300)
            if rc != 0:
                log.warning("arp-scan failed on %s (rc=%s): %s", s, rc, err.strip()[:200])
                continue
            hosts.extend(parse_arp_scan_plain(out))
        return hosts


# -- nmap -sn ----------------------------------------------------------------


def parse_nmap_xml_hosts(xml_text: str, source: str = "nmap") -> list[HostObservation]:
    root = ET.fromstring(xml_text)
    out: list[HostObservation] = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = hostname = None
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t == "ipv4":
                ip = addr.get("addr")
            elif t == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        if ip:
            out.append(
                HostObservation(ip=ip, mac=mac, vendor=vendor, hostname=hostname, source=source)
            )
    return out


class NmapPingBackend:
    name = "nmap"

    def available(self) -> bool:
        return have("nmap")

    async def discover(self, subnets: list[Subnet], cfg: ScanConfig) -> list[HostObservation]:
        if not subnets:
            return []
        args = [
            "nmap",
            "-sn",
            "-oX",
            "-",
            NMAP_TIMING[cfg.profile],
            f"--max-rate={cfg.rate_limit_pps}",
            *[str(s.network) for s in subnets],
        ]
        rc, out, err = await run_cmd(args, timeout=600)
        if rc != 0:
            log.warning("nmap -sn failed (rc=%s): %s", rc, err.strip()[:200])
            return []
        return parse_nmap_xml_hosts(out)


# -- ping sweep + neighbour table -------------------------------------------


def parse_ip_neigh_json(data: list[dict[str, object]]) -> dict[str, str]:
    """ip -j neigh -> {ip: mac} for entries with a usable link address."""
    out: dict[str, str] = {}
    for e in data:
        state = e.get("state", [])
        if isinstance(state, list) and "FAILED" in state:
            continue
        dst, lladdr = e.get("dst"), e.get("lladdr")
        if isinstance(dst, str) and isinstance(lladdr, str) and ":" in dst:
            continue  # IPv6, not handled yet
        if isinstance(dst, str) and isinstance(lladdr, str):
            out[dst] = lladdr
    return out


def parse_proc_net_arp(text: str) -> dict[str, str]:
    """/proc/net/arp -> {ip: mac}; only complete entries (ATF_COM flag)."""
    out: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, flags, mac = parts[0], parts[2], parts[3]
        try:
            complete = int(flags, 16) & 0x2
        except ValueError:
            continue
        if complete and mac != "00:00:00:00:00:00":
            out[ip] = mac
    return out


async def neighbour_table() -> dict[str, str]:
    rc, out, _ = await run_cmd(["ip", "-j", "neigh", "show"], timeout=10)
    if rc == 0 and out.strip():
        try:
            return parse_ip_neigh_json(json.loads(out))
        except ValueError:
            pass
    try:
        return parse_proc_net_arp(Path("/proc/net/arp").read_text())
    except OSError:
        return {}


class PingSweepBackend:
    name = "ping"

    def available(self) -> bool:
        return have("ping")

    async def discover(self, subnets: list[Subnet], cfg: ScanConfig) -> list[HostObservation]:
        targets = [str(ip) for s in subnets for ip in s.network.hosts()]
        sem = asyncio.Semaphore(min(64, max(1, cfg.rate_limit_pps)))

        async def ping(ip: str) -> str | None:
            async with sem:
                rc, _, _ = await run_cmd(["ping", "-c", "1", "-W", "1", ip], timeout=3)
                return ip if rc == 0 else None

        replies = {r for r in await asyncio.gather(*(ping(t) for t in targets)) if r}

        neigh = await neighbour_table()
        ips = replies | {
            ip for ip in neigh if any(ipaddress.ip_address(ip) in s.network for s in subnets)
        }
        hosts = [
            HostObservation(ip=ip, mac=neigh.get(ip), source="ping")
            for ip in sorted(ips, key=ipaddress.ip_address)
        ]
        if cfg.resolve_hostnames:
            hosts = await resolve_hostnames(hosts)
        return hosts


async def resolve_hostnames(
    hosts: list[HostObservation], timeout: float = 1.0
) -> list[HostObservation]:
    loop = asyncio.get_running_loop()

    async def one(h: HostObservation) -> HostObservation:
        if h.hostname:
            return h
        try:
            name, _ = await asyncio.wait_for(
                loop.getnameinfo((h.ip, 0), socket.NI_NAMEREQD), timeout=timeout
            )
            return h.model_copy(update={"hostname": name})
        except (OSError, TimeoutError):
            return h

    return list(await asyncio.gather(*(one(h) for h in hosts)))


# -- selection ----------------------------------------------------------------

BACKENDS: dict[str, DiscoveryBackend] = {
    "arp-scan": ArpScanBackend(),
    "nmap": NmapPingBackend(),
    "ping": PingSweepBackend(),
}


def select_backend(cfg: ScanConfig) -> DiscoveryBackend:
    if cfg.discovery_backend != "auto":
        b = BACKENDS[cfg.discovery_backend]
        if not b.available():
            raise RuntimeError(f"discovery backend {b.name!r} is configured but not usable here")
        return b
    for name in ("arp-scan", "nmap", "ping"):
        b = BACKENDS[name]
        if b.available():
            return b
    raise RuntimeError("no discovery backend available (need arp-scan, nmap, or ping)")
