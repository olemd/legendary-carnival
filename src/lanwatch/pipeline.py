"""One discovery round: subnets -> backend -> store -> rules -> overview."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from lanwatch.collectors.base import Executor, make_executor
from lanwatch.collectors.canary import probe_name_poisoning
from lanwatch.collectors.discovery import select_backend
from lanwatch.collectors.infra import run_probes
from lanwatch.collectors.services import nmap_available, scan_services
from lanwatch.collectors.upnp import discover_upnp
from lanwatch.config import Config
from lanwatch.llm import hooks as llm_hooks
from lanwatch.models import Finding, HostObservation, ServiceDiff, iso, now_utc
from lanwatch.netinfo import (
    default_gateways,
    ipv6_routers,
    list_interfaces,
    select_subnets,
    self_observations,
)
from lanwatch.notify import dispatch as notify
from lanwatch.overview import update as update_overview
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.rules.infra import infrastructure_ips
from lanwatch.store import Store

log = logging.getLogger(__name__)


@dataclass(slots=True)
class DiscoveryOutcome:
    snapshot_id: int
    backend: str
    subnets: list[str]
    hosts: int
    new_devices: list[int] = field(default_factory=list)
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)
    baseline: bool = False


@dataclass(slots=True)
class InventoryOutcome:
    snapshot_id: int
    deep: bool
    devices: int
    opened: int = 0
    closed: int = 0
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)


def _log_new_findings(config: Config, emitted: list[Finding], new_ids: list[str]) -> None:
    if not config.notify.log:
        return
    for f in emitted:
        if f.id in new_ids:
            log.warning("finding [%s] %s: %s", f.severity.value, f.rule_id, f.title)


async def run_inventory(
    config: Config,
    store: Store,
    device_ids: list[int] | None = None,
    deep: bool = False,
    executor: Executor | None = None,
) -> InventoryOutcome:
    """Service scan of online devices (or the given ones), then rules and overview."""
    ex = executor or make_executor(config.scan.helper_socket)
    if device_ids is None:
        targets = {d.id: d for d in store.devices(online_only=True)}
    else:
        targets = {}
        for did in device_ids:
            d = store.device(did)
            if d is not None and d.ip:
                targets[d.id] = d
    if deep:
        due = set(
            store.devices_needing_deep_scan(
                iso(now_utc() - timedelta(seconds=config.schedule.deep_interval_s))
            )
        )
        targets = {k: v for k, v in targets.items() if k in due}
    ips = [d.ip for d in targets.values() if d.ip]
    kind = "deep" if deep else "inventory"
    if not ips:
        log.info("%s: nothing to scan", kind)
        snapshot_id = store.begin_snapshot(kind, "nmap")
        store.finish_snapshot(snapshot_id, 0)
        return InventoryOutcome(snapshot_id=snapshot_id, deep=deep, devices=0)

    log.info("%s scan of %d devices (%s profile)", kind, len(ips), config.scan.profile)
    snapshot_id = store.begin_snapshot(kind, "nmap")
    log.debug("targets: %s", ", ".join(ips))
    result = await scan_services(ex, ips, config.scan, deep=deep)
    by_ip = {h.ip: h for h in result.hosts}
    diffs: dict[int, ServiceDiff] = {}
    for d in targets.values():
        host = by_ip.get(d.ip or "")
        if host is None:
            log.debug("%s (%s): no answer", d.ip, d.label)
            continue  # host did not answer this time; leave its services as they were
        diffs[d.id] = store.record_services(snapshot_id, d.id, host.ports, result.scanned, deep)
        open_ports = [f"{p.port}/{p.proto}" for p in host.ports if p.state == "open"]
        log.debug("%s (%s): %s", d.ip, d.label, ", ".join(open_ports) or "no open ports")
    store.finish_snapshot(snapshot_id, len(diffs))

    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=snapshot_id,
        previous_snapshot_id=None,
        is_baseline=False,
        service_diffs=diffs,
    )
    rules = Engine(config).run(ctx)
    _log_new_findings(config, rules.emitted, rules.new_ids)
    opened = sum(len(x.opened) for x in diffs.values())
    closed = sum(len(x.closed) for x in diffs.values())
    log.info(
        "%s done: %d devices answered, %d ports opened, %d closed, %d new findings, %d resolved",
        kind,
        len(diffs),
        opened,
        closed,
        len(rules.new_ids),
        len(rules.resolved_ids),
    )
    await llm_hooks.after_round(config, store, list(diffs), rules.new_ids)
    await notify.after_round(config, store, rules.new_ids, rules.resolved_ids)
    update_overview(store, config)
    return InventoryOutcome(
        snapshot_id=snapshot_id,
        deep=deep,
        devices=len(diffs),
        opened=opened,
        closed=closed,
        new_findings=rules.new_ids,
        resolved_findings=rules.resolved_ids,
    )


@dataclass(slots=True)
class InfraOutcome:
    snapshot_id: int
    dhcp_servers: list[str] = field(default_factory=list)
    upnp_devices: int = 0
    igd_mappings: int = 0
    ipv6_devices: int = 0
    devices_enriched: int = 0
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)


async def run_infra(config: Config, store: Store, executor: Executor | None = None) -> InfraOutcome:
    """DHCP/mDNS broadcast probes, UPnP discovery and IGD mappings, IPv6 exposure."""
    ex = executor or make_executor(config.scan.helper_socket)
    ifaces = await list_interfaces(ex)
    subnets = select_subnets(ifaces, config.network)
    iface_names = sorted({s.interface for s in subnets if s.interface})
    bind_ips = [ip for ip, _ in self_observations(ifaces, subnets)]
    _, root = await ex.which("nmap")
    snapshot_id = store.begin_snapshot("infra", ex.name)
    out = InfraOutcome(snapshot_id=snapshot_id)

    probes = await run_probes(ex, iface_names, config.scan, root)
    if probes.probed_dhcp:
        store.replace_infra(
            "dhcp", {f"{o.interface}/{o.server}": o.as_dict() for o in probes.dhcp}, snapshot_id
        )
        store.pin_dhcp_settings()
        out.dhcp_servers = sorted({o.server for o in probes.dhcp})
    enriched: set[int] = set()
    for ip, names in probes.mdns.items():
        d = store.device_by_ip(ip)
        if d and store.merge_device_attrs(d.id, {"mdns": names}):
            enriched.add(d.id)
    if config.scan.ipv6:
        for mac, addrs in probes.ipv6.items():
            d = store.device_by_key(mac)
            if d is None:
                continue
            open_ports = {a: probes.ipv6_open[a] for a in addrs if a in probes.ipv6_open}
            if store.merge_device_attrs(d.id, {"ipv6": addrs, "ipv6_open": open_ports}):
                enriched.add(d.id)
        out.ipv6_devices = len(probes.ipv6)

    if config.scan.upnp:
        try:
            upnp = await discover_upnp(bind_ips)
        except Exception:
            log.exception("upnp discovery failed")
            upnp = []
        entries: dict[str, dict[str, Any]] = {}
        for u in upnp:
            entries[u.addr] = {
                **u.info(),
                "location": u.location,
                "is_igd": u.is_igd,
                "external_ip": u.external_ip,
                "mappings": [m.as_dict() for m in u.mappings],
            }
            d = store.device_by_ip(u.addr)
            if d and store.merge_device_attrs(d.id, {"upnp": u.info()}):
                enriched.add(d.id)
        store.replace_infra("upnp", entries, snapshot_id)
        out.upnp_devices = len(upnp)
        out.igd_mappings = sum(len(u.mappings) for u in upnp)
    # IPv6 routers this host has learned, on the interfaces lanwatch watches.
    routers = [r for r in await ipv6_routers(ex) if r["dev"] in iface_names]
    store.replace_infra(
        "ipv6-router", {f"{r['gateway']}%{r['dev']}": r for r in routers}, snapshot_id
    )
    store.pin_ipv6_routers()

    if config.scan.name_poisoning_check:
        pairs = [
            (str(a.ip), str(a.network.broadcast_address))
            for i in ifaces
            if i.name in iface_names
            for a in i.addrs
            if str(a.ip) in bind_ips
        ]
        try:
            answers = await probe_name_poisoning(pairs)
        except Exception:
            log.exception("name poisoning probe failed")
            answers = []
        poisoners: dict[str, dict[str, Any]] = {}
        for a in answers:
            entry = poisoners.setdefault(a.responder, {"responder": a.responder, "protocols": []})
            entry["protocols"].append(a.protocol)
            entry["name"] = a.name
        store.replace_infra("name-poisoning", poisoners, snapshot_id)

    store.finish_snapshot(snapshot_id, len(enriched))
    out.devices_enriched = len(enriched)

    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=snapshot_id,
        previous_snapshot_id=None,
        is_baseline=False,
    )
    rules = Engine(config).run(ctx)
    _log_new_findings(config, rules.emitted, rules.new_ids)
    log.info(
        "infra done: %d dhcp servers, %d upnp devices, %d port mappings, %d ipv6 devices, "
        "%d new findings, %d resolved",
        len(out.dhcp_servers),
        out.upnp_devices,
        out.igd_mappings,
        out.ipv6_devices,
        len(rules.new_ids),
        len(rules.resolved_ids),
    )
    # Re-classify enriched devices: new facts (UPnP model, mDNS names) change the cache key.
    await llm_hooks.after_round(config, store, sorted(enriched), rules.new_ids)
    await notify.after_round(config, store, rules.new_ids, rules.resolved_ids)
    update_overview(store, config)
    out.new_findings, out.resolved_findings = rules.new_ids, rules.resolved_ids
    return out


def _excluded(h: HostObservation, excludes: list[str]) -> bool:
    ex = {e.lower() for e in excludes}
    return h.ip in ex or (h.mac is not None and h.mac in ex)


async def run_maintenance(config: Config, store: Store) -> dict[str, int]:
    """Daily housekeeping: drop history older than the configured retention, so a database
    that records every five minutes stops growing after the first month."""

    def cutoff(days: int) -> str | None:
        return iso(now_utc() - timedelta(days=days)) if days > 0 else None

    keep = config.store
    deleted = store.prune(
        rounds_before=cutoff(keep.keep_rounds_days),
        events_before=cutoff(keep.keep_events_days),
        notifications_before=cutoff(keep.keep_notifications_days),
    )
    if any(deleted.values()):
        log.info("maintenance: pruned %s", ", ".join(f"{n} {t}" for t, n in deleted.items() if n))
    return deleted


async def _record_arp_traffic(config: Config, store: Store, ex: Executor, snapshot_id: int) -> None:
    """Store what the passive ARP listener heard since the previous discovery round."""
    report_fn = getattr(ex, "arp_report", None)
    if not config.scan.arp_watch or report_fn is None:
        return
    try:
        report = await report_fn(config.schedule.discovery_interval_s + 30)
    except Exception as e:  # an older helper, or one that is restarting
        log.debug("no ARP report: %s", e)
        return
    if report is None:
        return  # no raw-socket privilege; the status page says so
    conflicts = {
        str(ip): {"ip": str(ip), "macs": [str(m) for m in macs]}
        for ip, macs in (report.get("conflicts") or {}).items()
    }
    sweeps = {
        str(s["mac"]): {"mac": str(s["mac"]), "ip": str(s.get("ip") or ""), "targets": s["targets"]}
        for s in report.get("sweeps") or []
        if isinstance(s, dict) and s.get("mac") and isinstance(s.get("targets"), list)
    }
    store.replace_infra("arp-conflict", conflicts, snapshot_id)
    store.replace_infra("arp-sweep", sweeps, snapshot_id)
    store.meta_set("arp.frames", str(int(report.get("frames") or 0)))
    log.debug(
        "ARP listener: %s frames, %d conflicts, %d busy senders",
        report.get("frames"),
        len(conflicts),
        len(sweeps),
    )


async def run_discovery(
    config: Config, store: Store, executor: Executor | None = None
) -> DiscoveryOutcome:
    ex = executor or make_executor(config.scan.helper_socket)
    ifaces = await list_interfaces(ex)
    subnets = select_subnets(ifaces, config.network)
    if not subnets:
        raise RuntimeError("no subnets to scan (check network.subnets / exclude_interfaces)")
    backend = await select_backend(ex, config.scan)
    log.info("discovery via %s on %s", backend.name, ", ".join(str(s) for s in subnets))
    # The decoys use this to tell a device on the watched networks from the internet.
    store.meta_set("net.subnets", json.dumps([str(s.network) for s in subnets]))

    snapshot_id = store.begin_snapshot("discovery", backend.name)
    hosts = await backend.discover(ex, subnets, config.scan)
    # This machine knows its own MAC addresses; a scan that reports it at all (nmap does,
    # without a MAC) would otherwise make it a second device on the same IP.
    own = dict(self_observations(ifaces, subnets))
    hosts = [h for h in hosts if h.ip not in own]
    hosts.extend(HostObservation(ip=ip, mac=mac, source="self") for ip, mac in own.items())
    hosts = [h for h in hosts if not _excluded(h, config.network.exclude_hosts)]

    is_baseline = store.finished_snapshot_count("discovery") == 0
    previous = store.latest_snapshot("discovery")
    rec = store.record_hosts(snapshot_id, hosts)
    store.finish_snapshot(snapshot_id, len(rec.seen_device_ids))
    log.debug("answered: %s", ", ".join(sorted(h.ip for h in hosts)) or "nobody")
    # Note who holds the gateway and the other addresses the network depends on, so the
    # rules can tell when that changes.
    gateways = await default_gateways(ex)
    if gateways:
        store.meta_set("net.gateways", json.dumps(gateways))
    store.pin_infrastructure(infrastructure_ips(store))
    await _record_arp_traffic(config, store, ex, snapshot_id)

    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=snapshot_id,
        previous_snapshot_id=previous.id if previous else None,
        is_baseline=is_baseline,
        new_device_ids=rec.new_device_ids,
        ip_changes=rec.ip_changes,
    )
    result = Engine(config).run(ctx)
    _log_new_findings(config, result.emitted, result.new_ids)

    if is_baseline:
        log.info(
            "baseline established: %d devices recorded, no findings raised",
            len(rec.seen_device_ids),
        )
    else:
        log.info(
            "discovery done: %d hosts, %d new devices, %d new findings, %d resolved",
            len(rec.seen_device_ids),
            len(rec.new_device_ids),
            len(result.new_ids),
            len(result.resolved_ids),
        )
    if (
        config.scan.scan_new_devices_immediately
        and not is_baseline
        and rec.new_device_ids
        and await nmap_available(ex)
    ):
        try:
            await run_inventory(config, store, device_ids=rec.new_device_ids, executor=ex)
        except RuntimeError as e:
            log.warning("inventory of new devices failed: %s", e)

    await llm_hooks.after_round(config, store, [], result.new_ids)
    await notify.after_round(config, store, result.new_ids, result.resolved_ids)

    path = update_overview(store, config)
    if path:
        log.info("overview updated: %s", path)

    return DiscoveryOutcome(
        snapshot_id=snapshot_id,
        backend=backend.name,
        subnets=[str(s) for s in subnets],
        hosts=len(rec.seen_device_ids),
        new_devices=rec.new_device_ids,
        new_findings=result.new_ids,
        resolved_findings=result.resolved_ids,
        baseline=is_baseline,
    )
