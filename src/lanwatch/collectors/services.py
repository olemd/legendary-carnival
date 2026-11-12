"""Service inventory via nmap. Produces typed port observations plus structured script
output (certificate validity, SSH algorithm lists, SMB dialects) for the rules."""

from __future__ import annotations

import asyncio
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
    # Hosts nmap gave up on (--host-timeout). nmap still reports them as up, with
    # whatever it had found so far, which is usually nothing. They are left out of
    # `hosts` so their services stay as they were instead of all being closed.
    timed_out: set[str] = field(default_factory=set)


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


def parse_nmap_xml_services(xml_text: str, address_type: str = "ipv4") -> ServiceScanResult:
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
            if addr.get("addrtype") == address_type:
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = normalize_mac(addr.get("addr"))
        if not ip:
            continue
        if host.get("timedout") == "true":
            result.timed_out.add(ip)
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


def _host_timeout_s(deep: bool) -> int:
    """How long nmap may spend on one host before giving up on it."""
    return 900 if deep else 240


# nmap works through its targets a host group at a time, and each group can take up to the
# per-host timeout. One run over every device therefore has no useful upper bound: 27
# devices at the gentle profile need up to 28 minutes, and the single 15-minute limit that
# used to cover the whole scan killed it every time, losing all of it. Scanning a few
# groups per run keeps each run short and its limit honest, and a batch that does fail
# costs only its own hosts.
GROUPS_PER_BATCH = 2


def batches(targets: list[str], cfg: ScanConfig, deep: bool) -> list[tuple[list[str], float]]:
    """Split targets into nmap runs: [(targets, timeout in seconds)]."""
    group = max(1, cfg.max_parallel_hosts)
    size = group * GROUPS_PER_BATCH
    out: list[tuple[list[str], float]] = []
    for i in range(0, len(targets), size):
        chunk = targets[i : i + size]
        groups = -(-len(chunk) // group)  # ceiling division
        out.append((chunk, groups * _host_timeout_s(deep) + 120))
    return out


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
        f"{_host_timeout_s(deep) // 60}m",
    ]
    args.append("-p-" if deep else f"--top-ports={cfg.light_top_ports}")
    if cfg.exclude_ports:
        args.append("--exclude-ports=" + ",".join(str(p) for p in cfg.exclude_ports))
    if cfg.version_detection:
        args += ["-sV", f"--version-intensity={VERSION_INTENSITY[cfg.profile]}"]
    scripts = [*cfg.scripts, *(["vulners"] if cfg.vulners else [])]
    if scripts:
        args.append("--script=" + ",".join(scripts))
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


async def _retry_alone(ex: Executor, result: ServiceScanResult, cfg: ScanConfig) -> None:
    """Rescan each timed-out host in an nmap run of its own.

    nmap takes a host group through each phase together, so one host that drops every
    probe holds the others back until the whole group runs out of time: a server that
    needs 96 s alone timed out at 240 s next to a switch that filters all its ports. Alone,
    the held-back hosts finish; a host that is slow by itself times out again and is left
    as it was. The runs go in parallel, as many at a time as a host group holds, so a bad
    round costs a few minutes more rather than one timeout per host.
    """
    sem = asyncio.Semaphore(max(1, cfg.max_parallel_hosts))
    timeout = _host_timeout_s(deep=False) + 120

    async def one(ip: str) -> ServiceScanResult | None:
        async with sem:
            rc, out, err = await ex.run(build_nmap_args([ip], cfg, deep=False), timeout=timeout)
        if rc != 0:
            log.warning("rescan of %s failed (rc=%s): %s", ip, rc, err.strip()[:200])
            return None
        return parse_nmap_xml_services(out)

    ips = sorted(result.timed_out)
    log.info("service scan: rescanning %d timed-out hosts one by one", len(ips))
    for part in await asyncio.gather(*(one(ip) for ip in ips)):
        if part is None:
            continue
        result.hosts.extend(part.hosts)
        result.timed_out -= {h.ip for h in part.hosts}


async def scan_services(
    ex: Executor, targets: list[str], cfg: ScanConfig, deep: bool
) -> ServiceScanResult:
    if not targets:
        return ServiceScanResult()
    present, root = await ex.which("nmap")
    if not present:
        raise RuntimeError("nmap is required for service inventory (apt install nmap)")
    result = ServiceScanResult()
    plan = batches(targets, cfg, deep)
    failures: list[str] = []
    done = 0
    for chunk, timeout in plan:
        rc, out, err = await ex.run(build_nmap_args(chunk, cfg, deep), timeout=timeout)
        done += len(chunk)
        if rc != 0:
            failures.append(f"rc={rc}: {err.strip()[:300]}")
            log.warning(
                "service scan of %d hosts failed (%s); their services are left as they were",
                len(chunk),
                failures[-1],
            )
            continue
        part = parse_nmap_xml_services(out)
        result.hosts.extend(part.hosts)
        result.scanned.update(part.scanned)
        result.timed_out |= part.timed_out
        if len(plan) > 1:
            log.info("service scan: %d of %d hosts done", done, len(targets))
    if len(failures) == len(plan):
        raise RuntimeError(f"nmap failed ({failures[0]})")
    if result.timed_out and not deep:
        await _retry_alone(ex, result, cfg)
    if deep and cfg.deep_udp_top_ports > 0:
        if not root:
            log.warning("skipping UDP scan: needs root or CAP_NET_RAW")
        else:
            by_ip = {h.ip: h for h in result.hosts}
            for chunk, timeout in plan:
                rc, out, err = await ex.run(build_nmap_udp_args(chunk, cfg), timeout=timeout)
                if rc != 0:
                    log.warning("UDP scan failed (rc=%s): %s", rc, err.strip()[:200])
                    continue
                udp = parse_nmap_xml_services(out)
                result.scanned.update(udp.scanned)
                result.timed_out |= udp.timed_out
                for h in udp.hosts:
                    if h.ip in by_ip:
                        by_ip[h.ip].ports.extend(h.ports)
                    else:
                        result.hosts.append(h)
                        by_ip[h.ip] = h
    if result.timed_out:
        # A host that timed out in one pass has only half a result. Recording it would
        # close the other protocol's ports, so it is left out as a whole.
        result.hosts = [h for h in result.hosts if h.ip not in result.timed_out]
        log.warning(
            "service scan timed out on %d hosts, their services are left as they were: %s",
            len(result.timed_out),
            ", ".join(sorted(result.timed_out)),
        )
    return result
