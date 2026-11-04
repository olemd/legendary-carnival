"""One discovery round: subnets -> backend -> store -> rules -> overview."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from lanwatch.collectors.discovery import select_backend
from lanwatch.config import Config
from lanwatch.models import HostObservation
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


def _excluded(h: HostObservation, excludes: list[str]) -> bool:
    ex = {e.lower() for e in excludes}
    return h.ip in ex or (h.mac is not None and h.mac in ex)


async def run_discovery(config: Config, store: Store) -> DiscoveryOutcome:
    ifaces = await list_interfaces()
    subnets = select_subnets(ifaces, config.network)
    if not subnets:
        raise RuntimeError("no subnets to scan (check network.subnets / exclude_interfaces)")
    backend = select_backend(config.scan)
    log.info("discovery via %s on %s", backend.name, ", ".join(str(s) for s in subnets))

    snapshot_id = store.begin_snapshot("discovery", backend.name)
    hosts = await backend.discover(subnets, config.scan)
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
    if config.notify.log:
        for f in result.emitted:
            if f.id in result.new_ids:
                log.warning("finding [%s] %s: %s", f.severity.value, f.rule_id, f.title)

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
