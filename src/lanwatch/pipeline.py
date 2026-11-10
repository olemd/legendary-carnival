"""One discovery round: subnets -> backend -> store -> rules -> overview."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import httpx2

from lanwatch import oui
from lanwatch.collectors.base import Executor, make_executor
from lanwatch.collectors.canary import probe_name_poisoning
from lanwatch.collectors.discovery import neighbour_table, select_backend
from lanwatch.collectors.dnsfilter import check_resolver, system_resolvers
from lanwatch.collectors.infra import run_probes
from lanwatch.collectors.latency import measure, resolve_targets
from lanwatch.collectors.services import nmap_available, scan_services
from lanwatch.collectors.snmp import DhcpLease, Neighbour, SnmpClient, SnmpError, SystemInfo
from lanwatch.collectors.unifi import (
    TOTAL_TIMEOUT_S,
    UnifiError,
    UnifiSnapshot,
    client_attrs,
    device_attrs,
    fetch_unifi,
    firmware_attrs,
    infra_rows,
)
from lanwatch.collectors.upnp import discover_upnp
from lanwatch.config import Config
from lanwatch.decoy import listening_ports
from lanwatch.exposure import Exposure, check_exposure
from lanwatch.firmware import Firmware, check_firmware
from lanwatch.llm import hooks as llm_hooks
from lanwatch.models import Device, Finding, HostObservation, ServiceDiff, iso, now_utc
from lanwatch.netinfo import (
    Subnet,
    default_gateways,
    ipv6_routers,
    is_local_address,
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
    if config.scan.skip_hosts:
        # Devices that do not tolerate nmap (scan.skip_hosts): discovered and tracked as
        # usual, never port-scanned, whichever way this scan was requested.
        skipped = [d for d in targets.values() if _excluded(d, config.scan.skip_hosts)]
        if skipped:
            log.info("skipping %s (scan.skip_hosts)", ", ".join(d.label for d in skipped))
            targets = {k: v for k, v in targets.items() if not _excluded(v, config.scan.skip_hosts)}
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
    decoys = listening_ports(store)
    for h in result.hosts:
        if decoys and is_local_address(h.ip):
            # Our own decoy ports, seen by our own scan. They are not services.
            h.ports = [p for p in h.ports if not (p.proto == "tcp" and p.port in decoys)]
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
    unifi_clients: int = 0
    unifi_devices: int = 0
    unifi_error: str | None = None
    snmp_error: str | None = None
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UnifiOutcome:
    snapshot: UnifiSnapshot | None = None
    clients: int = 0
    known_clients: int = 0
    devices: int = 0
    enriched: set[int] = field(default_factory=set)
    named: int = 0
    error: str | None = None
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)


async def collect_unifi(
    config: Config, store: Store, snapshot_id: int, client: httpx2.AsyncClient | None = None
) -> UnifiOutcome:
    """Ask the controller and merge the answer: infra rows for networks, SSIDs, UniFi
    devices and clients; per-device attrs; names for unnamed devices. A controller that
    cannot be read leaves the previous state in place (no flapping through a reboot) and
    never fails the round: the error is logged and kept in meta for the status page."""
    out = UnifiOutcome()
    try:
        snap = await asyncio.wait_for(fetch_unifi(config.unifi, client), TOTAL_TIMEOUT_S)
    except (UnifiError, TimeoutError) as e:
        out.error = str(e)[:300]
        log.warning("unifi: controller not read, keeping the previous state: %s", out.error)
        store.meta_set("unifi.last_error", out.error)
        return out
    except Exception as e:
        out.error = f"{type(e).__name__}: {str(e)[:200]}"
        log.exception("unifi: unexpected failure, keeping the previous state")
        store.meta_set("unifi.last_error", out.error)
        return out

    rows = infra_rows(snap, lambda mac: store.device_by_key(mac) is not None)
    for kind, entries in rows.items():
        store.replace_infra(kind, entries, snapshot_id)
    store.meta_set("unifi.site", json.dumps({"id": snap.site_id, "name": snap.site_name}))
    store.meta_set("unifi.version", snap.version or "")
    store.meta_set("unifi.last_ok", snap.fetched_at)
    store.meta_set("unifi.last_error", "")

    for c in snap.clients:
        if not c.mac:
            continue
        out.clients += 1
        d = store.device_by_key(c.mac)
        if d is None:
            continue
        out.known_clients += 1
        if store.merge_device_attrs(d.id, {"unifi": client_attrs(c, snap)}):
            out.enriched.add(d.id)
        # The controller fills `name` with the hostname when nobody set an alias; only a
        # name a person chose there is worth adopting, and only where lanwatch has none.
        if (
            config.unifi.adopt_names
            and d.name is None
            and c.name
            and c.name.lower() != (d.hostname or "").lower()
            and store.set_device_name(d.id, c.name)
        ):
            out.named += 1
    for dev in snap.devices:
        if not dev.mac:
            continue
        out.devices += 1
        d = store.device_by_key(dev.mac)
        if d is None:
            continue
        attrs: dict[str, Any] = {"unifi_device": device_attrs(dev, snap)}
        if (
            config.unifi.adopt_names
            and d.name is None
            and dev.name
            and dev.name.lower() != (d.hostname or "").lower()
            and store.set_device_name(d.id, dev.name)
        ):
            out.named += 1
        fw = d.attrs.get("firmware")
        # Do not overwrite a version read off the device itself by the firmware check.
        if not isinstance(fw, dict) or fw.get("source") == "unifi":
            attrs["firmware"] = firmware_attrs(dev, snap.fetched_at)
        if store.merge_device_attrs(d.id, attrs):
            out.enriched.add(d.id)
    out.snapshot = snap
    log.info(
        "unifi: %s, %d clients (%d known to lanwatch), %d devices, %d named",
        snap.site_name,
        out.clients,
        out.known_clients,
        out.devices,
        out.named,
    )
    return out


@dataclass(slots=True)
class SnmpOutcome:
    host: str | None = None
    system: SystemInfo | None = None
    neighbours: list[Neighbour] = field(default_factory=list)
    # None: the router has no DHCP lease table lanwatch can read (not a Juniper, or no
    # DHCP server on it). An empty list is a DHCP server with no leases.
    leases: list[DhcpLease] | None = None
    enriched: set[int] = field(default_factory=set)
    mismatches: int = 0
    error: str | None = None
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)


async def snmp_host(config: Config, ex: Executor | None = None) -> str | None:
    """The configured router, else this host's first default gateway."""
    if config.snmp.host:
        return config.snmp.host
    gateways = await default_gateways(ex)
    return gateways[0] if gateways else None


async def collect_snmp(
    config: Config, store: Store, snapshot_id: int, ex: Executor | None = None
) -> SnmpOutcome:
    """Read the router over SNMPv3: what it is, its ARP table and (Juniper) its DHCP
    leases. None of it counts as presence: a router keeps an ARP entry or a lease for many
    minutes after a device has gone. The tables tell the discovery recheck where else to
    look, and give a second view of who holds each address to compare with lanwatch's own.
    A router that cannot be read keeps the previous state and never fails the round; the
    error is kept for the status page."""
    out = SnmpOutcome(host=await snmp_host(config, ex))
    if out.host is None:
        out.error = "no snmp.host set and no default gateway to use instead"
    else:
        try:
            async with SnmpClient(config.snmp, out.host) as client:
                out.system = await client.system()
                out.neighbours = await client.neighbours()
                if out.system.vendor == "Juniper":
                    out.leases = await client.juniper_leases()
        except SnmpError as e:
            out.error = str(e)[:400]
        except Exception as e:
            log.exception("snmp: unexpected failure, keeping the previous state")
            out.error = f"{type(e).__name__}: {str(e)[:200]}"
    if out.error is not None:
        log.warning("snmp: %s not read, keeping the previous state: %s", out.host, out.error)
        store.meta_set("snmp.last_error", out.error)
        return out
    assert out.system is not None
    store.meta_set("snmp.host", out.host or "")
    store.meta_set("snmp.system", json.dumps(out.system.as_dict()))
    store.meta_set("snmp.last_ok", iso(now_utc()))
    store.meta_set("snmp.last_error", "")
    store.replace_infra("router-arp", {n.ip: n.as_dict() for n in out.neighbours}, snapshot_id)
    if out.leases is not None:
        store.replace_infra("router-dhcp", {x.ip: x.as_dict() for x in out.leases}, snapshot_id)
    out.enriched = _router_device_facts(store, out.neighbours, out.leases)
    out.mismatches = _track_router_mismatches(store, out.neighbours, snapshot_id)
    log.info(
        "snmp: %s is %s (%s), up %d days; %d ARP entries%s%s",
        out.host,
        out.system.name or "?",
        out.system.vendor or out.system.object_id,
        out.system.uptime_s // 86400,  # whole days, as `lanwatch snmp` prints them
        len(out.neighbours),
        f", {len(out.leases)} DHCP leases" if out.leases is not None else "",
        f", {out.mismatches} addresses held by another MAC than lanwatch saw"
        if out.mismatches
        else "",
    )
    return out


def _router_device_facts(
    store: Store, neighbours: list[Neighbour], leases: list[DhcpLease] | None
) -> set[int]:
    """attrs.router on known devices: the router has them in its ARP table, and (when it
    serves DHCP and lanwatch can read the leases) since when they hold a lease, or that
    they hold none, so their address is set by hand or comes from another server."""
    by_mac = {x.mac: x for x in leases or []}
    enriched: set[int] = set()
    for n in neighbours:
        d = store.device_by_key(n.mac)
        if d is None:
            continue
        facts: dict[str, Any] = {"arp_interface": n.interface}
        if leases is not None:
            lease = by_mac.get(n.mac)
            facts["dhcp_lease"] = lease is not None
            facts["dhcp_lease_since"] = lease.since if lease else None
        if store.merge_device_attrs(d.id, {"router": facts}):
            enriched.add(d.id)
    return enriched


def _track_router_mismatches(store: Store, neighbours: list[Neighbour], snapshot_id: int) -> int:
    """Addresses where the router's ARP table names another MAC than the one that answered
    lanwatch in the newest discovery round. The two reads are minutes apart, so a single
    disagreement can be an address that just changed hands; `rounds` counts how many reads
    in a row saw the same disagreement, and the rule waits for two."""
    holders = store.ip_holders()
    before = {r.key: r.data for r in store.infra("router-arp-mismatch")}
    entries: dict[str, dict[str, Any]] = {}
    for n in neighbours:
        seen = sorted({mac for _, mac in holders.get(n.ip, []) if mac})
        if not seen or n.mac in seen:
            continue  # lanwatch has no MAC for it this round, or the two agree
        prev = before.get(n.ip) or {}
        same = prev.get("router_mac") == n.mac and prev.get("lanwatch_macs") == seen
        entries[n.ip] = {
            "ip": n.ip,
            "router_mac": n.mac,
            "lanwatch_macs": seen,
            "interface": n.interface,
            "rounds": int(prev.get("rounds") or 0) + 1 if same else 1,
        }
    store.replace_infra("router-arp-mismatch", entries, snapshot_id)
    return len(entries)


async def run_snmp(config: Config, store: Store) -> SnmpOutcome:
    """On demand (`lanwatch snmp`): read the router, then the rules."""
    snapshot_id = store.begin_snapshot("snmp", "snmpv3")
    out = await collect_snmp(config, store, snapshot_id)
    store.finish_snapshot(snapshot_id, len(out.enriched))
    if out.error is not None:
        return out
    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=snapshot_id,
        previous_snapshot_id=None,
        is_baseline=False,
    )
    rules = Engine(config).run(ctx)
    _log_new_findings(config, rules.emitted, rules.new_ids)
    await notify.after_round(config, store, rules.new_ids, rules.resolved_ids)
    update_overview(store, config)
    out.new_findings, out.resolved_findings = rules.new_ids, rules.resolved_ids
    return out


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
    # The infra page tells "could not probe" (no raw sockets) from "nobody answered".
    store.meta_set("dhcp.probed", "yes" if probes.probed_dhcp else "no")
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
            decoys = {f"{p}/tcp" for p in listening_ports(store)}
            for own in [addr for addr in open_ports if decoys and is_local_address(addr)]:
                # Our own decoy ports on our own IPv6 addresses are not exposed services.
                open_ports[own] = [p for p in open_ports[own] if p not in decoys]
            open_ports = {addr: ports for addr, ports in open_ports.items() if ports}
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
    if config.unifi.enabled:
        uni = await collect_unifi(config, store, snapshot_id)
        enriched |= uni.enriched
        out.unifi_clients, out.unifi_devices, out.unifi_error = (
            uni.clients,
            uni.devices,
            uni.error,
        )
    if config.snmp.enabled:
        snmp = await collect_snmp(config, store, snapshot_id, ex)
        enriched |= snmp.enriched
        out.snmp_error = snmp.error
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

    if config.scan.dns_filter_check:
        announced = {
            str(dns) for r in store.infra("dhcp") for dns in r.data.get("dns") or [] if dns
        }
        results: dict[str, dict[str, Any]] = {}
        for resolver in sorted(announced) or system_resolvers():
            try:
                results[resolver] = await check_resolver(resolver)
            except Exception:
                log.exception("DNS filtering check of %s failed", resolver)
            else:
                results[resolver]["announced_by_dhcp"] = resolver in announced
        store.replace_infra("dns-filter", results, snapshot_id)

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
        "infra done: %d dhcp servers, %d upnp devices, %d port mappings, %d ipv6 devices%s, "
        "%d new findings, %d resolved",
        len(out.dhcp_servers),
        out.upnp_devices,
        out.igd_mappings,
        out.ipv6_devices,
        f", unifi: {out.unifi_clients} clients, {out.unifi_devices} devices"
        if config.unifi.enabled and not out.unifi_error
        else " (unifi not read)"
        if config.unifi.enabled
        else "",
        len(rules.new_ids),
        len(rules.resolved_ids),
    )
    # Re-classify enriched devices: new facts (UPnP model, mDNS names) change the cache key.
    await llm_hooks.after_round(config, store, sorted(enriched), rules.new_ids)
    await notify.after_round(config, store, rules.new_ids, rules.resolved_ids)
    update_overview(store, config)
    out.new_findings, out.resolved_findings = rules.new_ids, rules.resolved_ids
    return out


def _excluded(h: HostObservation | Device, excludes: list[str]) -> bool:
    """Is this host named in the list, by IP or by MAC (case-insensitive)?"""
    ex = {e.lower() for e in excludes}
    return h.ip in ex or (h.mac is not None and h.mac.lower() in ex)


@dataclass(slots=True)
class FirmwareOutcome:
    found: list[tuple[str, Firmware]] = field(default_factory=list)  # device label, firmware
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)


async def run_firmware(
    config: Config, store: Store, executor: Executor | None = None
) -> FirmwareOutcome:
    """Daily: read firmware versions off the devices that offer them, then run the rules."""
    ex = executor or make_executor(config.scan.helper_socket)
    ifaces = await list_interfaces(ex)
    subnets = select_subnets(ifaces, config.network)
    bind_ips = [ip for ip, _ in self_observations(ifaces, subnets)]
    results = await check_firmware(store, bind_ips, online=config.firmware.online)
    snapshot_id = store.begin_snapshot("firmware", "local")
    store.finish_snapshot(snapshot_id, len(results))
    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=snapshot_id,
        previous_snapshot_id=None,
        is_baseline=False,
    )
    rules = Engine(config).run(ctx)
    _log_new_findings(config, rules.emitted, rules.new_ids)
    outdated = sum(1 for _, fw in results if fw.update)
    log.info(
        "firmware check: %d devices report a version, %d behind%s",
        len(results),
        outdated,
        "" if config.firmware.online else " (online lookups are off)",
    )
    await notify.after_round(config, store, rules.new_ids, rules.resolved_ids)
    update_overview(store, config)
    return FirmwareOutcome(
        found=[(d.label, fw) for d, fw in results],
        new_findings=rules.new_ids,
        resolved_findings=rules.resolved_ids,
    )


async def run_exposure(config: Config, store: Store) -> Exposure | None:
    """Daily: what Shodan sees of our public address, then the rules."""
    exposure = await check_exposure(config, store)
    if exposure is None:
        return None
    snap = store.latest_snapshot("exposure")
    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=snap.id if snap else 0,
        previous_snapshot_id=None,
        is_baseline=False,
    )
    rules = Engine(config).run(ctx)
    _log_new_findings(config, rules.emitted, rules.new_ids)
    await notify.after_round(config, store, rules.new_ids, rules.resolved_ids)
    update_overview(store, config)
    return exposure


async def run_unifi(config: Config, store: Store) -> UnifiOutcome:
    """On demand (`lanwatch unifi`): read the controller, then the rules."""
    snapshot_id = store.begin_snapshot("unifi", "integration-api")
    out = await collect_unifi(config, store, snapshot_id)
    store.finish_snapshot(snapshot_id, out.clients)
    if out.error is not None:
        return out
    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=snapshot_id,
        previous_snapshot_id=None,
        is_baseline=False,
    )
    rules = Engine(config).run(ctx)
    _log_new_findings(config, rules.emitted, rules.new_ids)
    await notify.after_round(config, store, rules.new_ids, rules.resolved_ids)
    update_overview(store, config)
    out.new_findings, out.resolved_findings = rules.new_ids, rules.resolved_ids
    return out


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


# Second look at silent addresses: pings per address, seconds to wait for each reply, and
# at most this many addresses per round (a failed scan should not turn into a ping storm).
RECHECK_COUNT = 3
RECHECK_WAIT_S = 2
RECHECK_MAX = 64


async def recheck_silent(
    config: Config,
    store: Store,
    ex: Executor,
    subnets: list[Subnet],
    hosts: list[HostObservation],
    previous_snapshot_id: int | None,
) -> list[HostObservation]:
    """Ping, more patiently than the scan did, the addresses that should have answered and
    did not: devices seen in the previous round, clients the UniFi controller lists, and
    addresses in the router's ARP table and DHCP leases (read over SNMP), on a scanned
    subnet. Power-saving Wi-Fi devices often sleep through an ARP probe but answer a ping
    that waits a second or two. Only a reply counts, and the MAC comes from this host's
    neighbour table, so a device that has really gone is still offline this round; the
    controller and the router only say where to look again."""
    if not config.scan.recheck_silent:
        return []
    seen_ips = {h.ip for h in hosts}
    seen_macs = {h.mac for h in hosts if h.mac}
    excluded = {e.lower() for e in config.network.exclude_hosts}
    targets: list[str] = []

    def consider(ip: str | None, mac: str | None) -> None:
        if not ip or ip in seen_ips or ip in targets or ip in excluded:
            return
        if mac is not None and (mac.lower() in seen_macs or mac.lower() in excluded):
            return  # answered under another address; the scan has it
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if any(addr in s.network for s in subnets):
            targets.append(ip)

    if previous_snapshot_id is not None:
        for did in sorted(store.sighting_device_ids(previous_snapshot_id)):
            d = store.device(did)
            if d is not None:
                consider(d.ip, d.mac)
    if config.unifi.enabled:
        for r in store.infra("unifi-client"):
            ip, mac = r.data.get("ip"), r.data.get("mac")
            consider(ip if isinstance(ip, str) else None, mac if isinstance(mac, str) else None)
    if config.snmp.enabled:
        for kind in ("router-arp", "router-dhcp"):
            for r in store.infra(kind):
                ip, mac = r.data.get("ip"), r.data.get("mac")
                consider(ip if isinstance(ip, str) else None, mac if isinstance(mac, str) else None)
    if not targets:
        return []
    if len(targets) > RECHECK_MAX:
        log.info("recheck: %d silent addresses, pinging the first %d", len(targets), RECHECK_MAX)
        targets = targets[:RECHECK_MAX]
    results = await measure(ex, targets, RECHECK_COUNT, RECHECK_WAIT_S)
    answered = [r.target for r in results if r.received]
    neigh = await neighbour_table(ex) if answered else {}
    # A reply without a neighbour entry has no MAC to tie it to a device: not recorded.
    out = [
        HostObservation(ip=ip, mac=neigh[ip], source="recheck") for ip in answered if neigh.get(ip)
    ]
    log.info(
        "recheck: %d of %d silent addresses answered a slower ping%s",
        len(out),
        len(targets),
        f": {', '.join(h.ip for h in out)}" if out else "",
    )
    return out


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
    previous = store.latest_snapshot("discovery")
    hosts.extend(
        await recheck_silent(config, store, ex, subnets, hosts, previous.id if previous else None)
    )
    hosts = [h for h in hosts if not _excluded(h, config.network.exclude_hosts)]
    # The backend's own OUI list may predate the device's prefix; try a fresher registry.
    hosts = oui.fill_vendors(hosts, oui.load(config.data_dir))

    is_baseline = store.finished_snapshot_count("discovery") == 0
    rec = store.record_hosts(snapshot_id, hosts)
    store.finish_snapshot(snapshot_id, len(rec.seen_device_ids))
    log.debug("answered: %s", ", ".join(sorted(h.ip for h in hosts)) or "nobody")
    # Note who holds the gateway and the other addresses the network depends on, so the
    # rules can tell when that changes.
    gateways = await default_gateways(ex)
    if gateways:
        store.meta_set("net.gateways", json.dumps(gateways))
    store.pin_infrastructure(infrastructure_ips(store))
    if config.latency.enabled:
        targets = resolve_targets(config.latency.targets, gateways)
        for r in await measure(ex, targets, config.latency.count):
            store.record_latency(r.target, r.sent, r.received, r.avg_ms, r.max_ms)
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
