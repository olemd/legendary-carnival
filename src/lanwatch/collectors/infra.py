"""Infrastructure probes: DHCP servers answering on the segment, mDNS service announcements,
and IPv6 global addresses with reachable services. nmap prescripts need raw sockets
(root, CAP_NET_RAW, or the helper); the rest is unprivileged."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from lanwatch.collectors.base import Executor
from lanwatch.collectors.services import _script_data, parse_nmap_xml_services
from lanwatch.config import ScanConfig
from lanwatch.models import normalize_mac

log = logging.getLogger(__name__)

TIMING = {"gentle": "-T2", "normal": "-T3", "thorough": "-T4"}


@dataclass(slots=True)
class DhcpOffer:
    server: str
    interface: str
    offered_ip: str = ""
    router: str = ""
    dns: list[str] = field(default_factory=list)
    domain: str = ""
    ntp: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "interface": self.interface,
            "offered_ip": self.offered_ip,
            "router": self.router,
            "dns": self.dns,
            "domain": self.domain,
            "ntp": self.ntp,
        }


@dataclass(slots=True)
class InfraResult:
    dhcp: list[DhcpOffer] = field(default_factory=list)
    mdns: dict[str, list[str]] = field(default_factory=dict)  # ip -> service strings
    ipv6: dict[str, list[str]] = field(default_factory=dict)  # mac -> global addresses
    ipv6_open: dict[str, list[str]] = field(default_factory=dict)  # addr -> ["22/tcp", ...]
    probed_dhcp: bool = False


# -- nmap prescripts -------------------------------------------------------------------


def _prescripts(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    out: dict[str, Any] = {}
    for s in root.findall("prescript/script"):
        sid = s.get("id")
        if sid:
            out[sid] = _script_data(s)
    return out


def _as_list(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)] if v else []


def parse_broadcast_results(
    xml_text: str, interface: str
) -> tuple[list[DhcpOffer], dict[str, list[str]]]:
    scripts = _prescripts(xml_text)
    offers: list[DhcpOffer] = []
    dhcp = scripts.get("broadcast-dhcp-discover")
    if isinstance(dhcp, dict):
        responses = [v for k, v in dhcp.items() if k.startswith("Response") and isinstance(v, dict)]
        if not responses and "Server Identifier" in dhcp:
            responses = [dhcp]
        for r in responses:
            server = str(r.get("Server Identifier", "")).strip()
            if not server:
                continue
            offers.append(
                DhcpOffer(
                    server=server,
                    interface=str(r.get("Interface", interface)),
                    offered_ip=str(r.get("IP Offered", "")),
                    router=" ".join(_as_list(r.get("Router"))),
                    dns=_as_list(r.get("Domain Name Server")),
                    domain=str(r.get("Domain Name", "")),
                    ntp=_as_list(r.get("NTP Servers")),
                )
            )
    mdns: dict[str, list[str]] = {}
    dns_sd = scripts.get("broadcast-dns-service-discovery")
    if isinstance(dns_sd, dict):
        for ip, services in dns_sd.items():
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            names: list[str] = []
            if isinstance(services, dict):
                for port, entries in services.items():
                    for e in _as_list(entries):
                        names.append(f"{e} ({port})")
            else:
                names = _as_list(services)
            mdns[ip] = sorted(set(names))[:25]
    return offers, mdns


def build_broadcast_args(interface: str, cfg: ScanConfig) -> list[str]:
    return [
        "nmap",
        "-oX",
        "-",
        "-n",
        TIMING[cfg.profile],
        "-e",
        interface,
        "--script=broadcast-dhcp-discover,broadcast-dns-service-discovery",
    ]


# -- IPv6 -------------------------------------------------------------------------------


def parse_ipv6_neigh(data: list[dict[str, object]]) -> dict[str, list[str]]:
    """ip -j -6 neigh -> {mac: [global addresses]} (link-local, ULA and multicast dropped)."""
    out: dict[str, list[str]] = {}
    for e in data:
        state = e.get("state", [])
        if isinstance(state, list) and "FAILED" in state:
            continue
        dst, lladdr = e.get("dst"), e.get("lladdr")
        if not isinstance(dst, str) or not isinstance(lladdr, str):
            continue
        try:
            addr = ipaddress.IPv6Address(dst)
        except ValueError:
            continue
        if not addr.is_global or addr.is_multicast:
            continue
        mac = normalize_mac(lladdr)
        if mac:
            out.setdefault(mac, []).append(str(addr))
    return {k: sorted(set(v)) for k, v in out.items()}


def build_ipv6_scan_args(addrs: list[str], cfg: ScanConfig) -> list[str]:
    return [
        "nmap",
        "-6",
        "-oX",
        "-",
        "-n",
        "-Pn",
        TIMING[cfg.profile],
        f"--max-rate={cfg.rate_limit_pps}",
        "--host-timeout",
        "3m",
        f"--top-ports={cfg.ipv6_top_ports}",
        *addrs,
    ]


# -- runner --------------------------------------------------------------------------


async def run_probes(
    ex: Executor, interfaces: list[str], cfg: ScanConfig, root: bool
) -> InfraResult:
    result = InfraResult()
    if root:
        result.probed_dhcp = True
        for iface in interfaces:
            rc, out, err = await ex.run(build_broadcast_args(iface, cfg), timeout=120)
            if rc != 0:
                log.warning(
                    "broadcast probes on %s failed (rc=%s): %s", iface, rc, err.strip()[:200]
                )
                continue
            try:
                offers, mdns = parse_broadcast_results(out, iface)
            except ET.ParseError as e:
                log.warning("broadcast probe output unparsable: %s", e)
                continue
            result.dhcp.extend(offers)
            result.mdns.update(mdns)
    else:
        log.info("skipping DHCP/mDNS broadcast probes: need root, CAP_NET_RAW or the helper")

    if cfg.ipv6:
        for iface in interfaces:
            await ex.run(["ping", "-6", "-c", "1", "-W", "1", f"ff02::1%{iface}"], timeout=5)
        rc, out, _ = await ex.run(["ip", "-j", "-6", "neigh", "show"], timeout=10)
        if rc == 0 and out.strip():
            with contextlib.suppress(ValueError):
                result.ipv6 = parse_ipv6_neigh(json.loads(out))
        addrs = sorted({a for v in result.ipv6.values() for a in v})
        if addrs:
            rc, out, err = await ex.run(build_ipv6_scan_args(addrs, cfg), timeout=600)
            if rc == 0:
                try:
                    for host in parse_nmap_xml_services(out, address_type="ipv6").hosts:
                        if host.ports:
                            result.ipv6_open[host.ip] = [f"{p.port}/{p.proto}" for p in host.ports]
                except ET.ParseError:
                    pass
            else:
                log.warning("ipv6 service scan failed (rc=%s): %s", rc, err.strip()[:200])
    return result
