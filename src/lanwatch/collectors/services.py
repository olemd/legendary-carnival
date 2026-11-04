"""Service inventory via nmap. Produces typed port observations plus structured script
output (certificate validity, SSH algorithm lists, SMB dialects) for the rules."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict

from lanwatch.collectors.base import Executor
from lanwatch.config import ScanConfig
from lanwatch.models import normalize_mac

log = logging.getLogger(__name__)

TIMING = {"gentle": "-T2", "normal": "-T3", "thorough": "-T4"}
VERSION_INTENSITY = {"gentle": 0, "normal": 2, "thorough": 5}


class PortObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    port: int
    proto: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None  # "ssl" when nmap saw TLS on the port
    scripts: dict[str, Any] = {}


class HostServices(BaseModel):
    ip: str
    mac: str | None = None
    ports: list[PortObservation] = []
    host_scripts: dict[str, Any] = {}


@dataclass(slots=True, frozen=True)
class PortSet:
    """Which ports nmap actually scanned, per protocol. Needed to tell "closed" from
    "not scanned this time" when a light scan follows a deep one."""

    ranges: tuple[tuple[int, int], ...]

    @classmethod
    def from_spec(cls, spec: str) -> PortSet:
        out: list[tuple[int, int]] = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                out.append((int(a), int(b)))
            else:
                out.append((int(part), int(part)))
        return cls(tuple(out))

    def __contains__(self, port: int) -> bool:
        return any(a <= port <= b for a, b in self.ranges)

    def __len__(self) -> int:
        return sum(b - a + 1 for a, b in self.ranges)


@dataclass(slots=True)
class ServiceScanResult:
    hosts: list[HostServices] = field(default_factory=list)
    scanned: dict[str, PortSet] = field(default_factory=dict)  # proto -> ports


# -- XML parsing ---------------------------------------------------------------


def _script_data(elem: ET.Element) -> Any:
    """nmap script <table>/<elem> structure -> dict/list/str."""
    children = list(elem)
    if not children:
        return elem.text or ""
    if all(c.get("key") is not None for c in children):
        return {str(c.get("key")): _script_data(c) for c in children}
    return [_script_data(c) for c in children]


def _scripts(parent: ET.Element) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for s in parent.findall("script"):
        sid = s.get("id")
        if not sid:
            continue
        out[sid] = {"output": s.get("output", ""), "data": _script_data(s)}
    return out


def parse_nmap_xml_services(xml_text: str) -> ServiceScanResult:
    root = ET.fromstring(xml_text)
    result = ServiceScanResult()
    for si in root.findall("scaninfo"):
        proto, spec = si.get("protocol"), si.get("services")
        if proto and spec:
            result.scanned[proto] = PortSet.from_spec(spec)
    for host in root.iter("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = normalize_mac(addr.get("addr"))
        if not ip:
            continue
        hs = HostServices(ip=ip, mac=mac)
        hostscript = host.find("hostscript")
        if hostscript is not None:
            hs.host_scripts = _scripts(hostscript)
        for p in host.findall("ports/port"):
            state_el = p.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            if state != "open":
                continue
            svc = p.find("service")
            hs.ports.append(
                PortObservation(
                    port=int(p.get("portid", "0")),
                    proto=p.get("protocol", "tcp"),
                    state=state,
                    name=svc.get("name") if svc is not None else None,
                    product=svc.get("product") if svc is not None else None,
                    version=svc.get("version") if svc is not None else None,
                    extrainfo=svc.get("extrainfo") if svc is not None else None,
                    tunnel=svc.get("tunnel") if svc is not None else None,
                    scripts=_scripts(p),
                )
            )
        result.hosts.append(hs)
    return result


# -- command line ---------------------------------------------------------------


def build_nmap_args(targets: list[str], cfg: ScanConfig, deep: bool) -> list[str]:
    args = [
        "nmap",
        "-oX",
        "-",
        "-n",
        "-Pn",
        TIMING[cfg.profile],
        f"--max-rate={cfg.rate_limit_pps}",
        f"--max-hostgroup={cfg.max_parallel_hosts}",
        "--host-timeout",
        "15m" if deep else "4m",
    ]
    args.append("-p-" if deep else f"--top-ports={cfg.light_top_ports}")
    if cfg.exclude_ports:
        args.append("--exclude-ports=" + ",".join(str(p) for p in cfg.exclude_ports))
    if cfg.version_detection:
        args += ["-sV", f"--version-intensity={VERSION_INTENSITY[cfg.profile]}"]
    if cfg.scripts:
        args.append("--script=" + ",".join(cfg.scripts))
    return [*args, *targets]


def build_nmap_udp_args(targets: list[str], cfg: ScanConfig) -> list[str]:
    return [
        "nmap",
        "-oX",
        "-",
        "-n",
        "-Pn",
        "-sU",
        TIMING[cfg.profile],
        f"--max-rate={cfg.rate_limit_pps}",
        f"--max-hostgroup={cfg.max_parallel_hosts}",
        "--host-timeout",
        "15m",
        f"--top-ports={cfg.deep_udp_top_ports}",
        *targets,
    ]


async def nmap_available(ex: Executor) -> bool:
    return (await ex.which("nmap"))[0]


async def scan_services(
    ex: Executor, targets: list[str], cfg: ScanConfig, deep: bool
) -> ServiceScanResult:
    if not targets:
        return ServiceScanResult()
    present, root = await ex.which("nmap")
    if not present:
        raise RuntimeError("nmap is required for service inventory (apt install nmap)")
    rc, out, err = await ex.run(build_nmap_args(targets, cfg, deep), timeout=3600 if deep else 900)
    if rc != 0:
        raise RuntimeError(f"nmap failed (rc={rc}): {err.strip()[:300]}")
    result = parse_nmap_xml_services(out)
    if deep and cfg.deep_udp_top_ports > 0:
        if not root:
            log.warning("skipping UDP scan: needs root or CAP_NET_RAW")
        else:
            rc, out, err = await ex.run(build_nmap_udp_args(targets, cfg), timeout=3600)
            if rc != 0:
                log.warning("UDP scan failed (rc=%s): %s", rc, err.strip()[:200])
            else:
                udp = parse_nmap_xml_services(out)
                result.scanned.update(udp.scanned)
                by_ip = {h.ip: h for h in result.hosts}
                for h in udp.hosts:
                    if h.ip in by_ip:
                        by_ip[h.ip].ports.extend(h.ports)
                    else:
                        result.hosts.append(h)
    return result
