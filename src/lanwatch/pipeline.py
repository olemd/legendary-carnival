"""One discovery round: subnets -> backend -> store -> rules -> overview."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta

from lanwatch.collectors.base import Executor, make_executor
from lanwatch.collectors.discovery import select_backend
from lanwatch.collectors.services import nmap_available, scan_services
from lanwatch.config import Config
from lanwatch.llm import hooks as llm_hooks
from lanwatch.models import Finding, HostObservation, ServiceDiff, iso, now_utc
from lanwatch.netinfo import list_interfaces, select_subnets, self_observations
from lanwatch.overview import update as update_overview
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
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
    result = await scan_services(ex, ips, config.scan, deep=deep)
    by_ip = {h.ip: h for h in result.hosts}
    diffs: dict[int, ServiceDiff] = {}
    for d in targets.values():
        host = by_ip.get(d.ip or "")
        if host is None:
            continue  # host did not answer this time; leave its services as they were
        diffs[d.id] = store.record_services(snapshot_id, d.id, host.ports, result.scanned, deep)
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


def _excluded(h: HostObservation, excludes: list[str]) -> bool:
    ex = {e.lower() for e in excludes}
    return h.ip in ex or (h.mac is not None and h.mac in ex)


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

    snapshot_id = store.begin_snapshot("discovery", backend.name)
    hosts = await backend.discover(ex, subnets, config.scan)
    for ip, mac in self_observations(ifaces, subnets):
        hosts.append(HostObservation(ip=ip, mac=mac, source="self"))
    hosts = [h for h in hosts if not _excluded(h, config.network.exclude_hosts)]

    is_baseline = store.finished_snapshot_count("discovery") == 0
    previous = store.latest_snapshot("discovery")
    rec = store.record_hosts(snapshot_id, hosts)
    store.finish_snapshot(snapshot_id, len(rec.seen_device_ids))

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
