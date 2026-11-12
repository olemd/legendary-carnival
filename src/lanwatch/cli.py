"""Command line interface."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Any

import typer

from lanwatch import __version__, oui
from lanwatch.collectors.audit_snmp import available as audit_available
from lanwatch.config import ConfigError, LoadedConfig, dump_effective, load_config
from lanwatch.decoy import Decoys, publish_listening, record_hit
from lanwatch.logging_setup import set_verbose, setup_logging
from lanwatch.models import FindingStatus, local_str
from lanwatch.overview import render
from lanwatch.overview import update as update_overview
from lanwatch.pipeline import (
    run_airos,
    run_discovery,
    run_exposure,
    run_firmware,
    run_infra,
    run_inventory,
    run_maintenance,
    run_snmp,
    run_snmp_audit,
    run_unifi,
)
from lanwatch.rules.engine import all_rules
from lanwatch.scheduler import Job, Scheduler
from lanwatch.sdnotify import notify_ready
from lanwatch.store import Store

app = typer.Typer(no_args_is_help=True, add_completion=False, help="lanwatch: audit your own LAN.")
config_app = typer.Typer(no_args_is_help=True, help="Show effective configuration.")
llm_app = typer.Typer(no_args_is_help=True, help="Local LLM: status and evaluation.")
app.add_typer(config_app, name="config")
app.add_typer(llm_app, name="llm")
log = logging.getLogger("lanwatch")


@dataclass
class State:
    loaded: LoadedConfig


# Offered both before the command (`lanwatch -v scan`) and on the commands that can take
# minutes (`lanwatch scan --verbose`), since that is where people look for it.
VerboseOpt = Annotated[
    bool,
    typer.Option(
        "--verbose",
        "-v",
        help="Show each command and LLM call as it starts and finishes, per-device results,"
        " and a sign of life every 30 seconds while waiting.",
    ),
]


def _state(ctx: typer.Context) -> State:
    st = ctx.obj
    assert isinstance(st, State)
    return st


def _open_store(ctx: typer.Context) -> Store:
    return Store(_state(ctx).loaded.config.store_path)


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Config file (TOML).")
    ] = None,
    data_dir: Annotated[Path | None, typer.Option(help="Override data_dir.")] = None,
    log_level: Annotated[str, typer.Option(help="debug, info, warning, error")] = "info",
    log_format: Annotated[str, typer.Option(help="text or json")] = "text",
    verbose: VerboseOpt = False,
) -> None:
    setup_logging(log_level, "json" if log_format == "json" else "text")
    if verbose:
        set_verbose()
    overrides: dict[str, Any] = {}
    if data_dir is not None:
        overrides["data_dir"] = str(data_dir)
    try:
        ctx.obj = State(loaded=load_config(config, overrides))
    except ConfigError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from e


@app.command()
def version() -> None:
    typer.echo(f"lanwatch {__version__}")


@app.command()
def scan(
    ctx: typer.Context,
    discovery_only: Annotated[bool, typer.Option(help="Skip the service inventory.")] = False,
    deep: Annotated[bool, typer.Option(help="Full port range instead of top ports.")] = False,
    verbose: VerboseOpt = False,
) -> None:
    """Run one discovery round plus a service inventory of online devices, then exit."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config

    async def _scan() -> None:
        with _open_store(ctx) as store:
            d = await run_discovery(cfg, store)
            typer.echo(
                f"discovery: {d.hosts} hosts via {d.backend} on {', '.join(d.subnets)}; "
                f"{len(d.new_devices)} new devices, {len(d.new_findings)} new findings"
                + (" (baseline)" if d.baseline else "")
            )
            if discovery_only:
                return
            i = await run_inventory(cfg, store, deep=deep)
            typer.echo(
                f"inventory: {i.devices} devices answered, {i.opened} ports opened, "
                f"{i.closed} closed, {len(i.new_findings)} new findings, "
                f"{len(i.resolved_findings)} resolved"
            )
            f = await run_infra(cfg, store)
            typer.echo(_infra_line(f))

    try:
        asyncio.run(_scan())
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1) from e


@app.command()
def inventory(
    ctx: typer.Context,
    device_ids: Annotated[
        list[int] | None, typer.Argument(help="Device ids; default: all online.")
    ] = None,
    deep: Annotated[
        bool, typer.Option(help="Full port range, plus UDP top ports as root.")
    ] = False,
    verbose: VerboseOpt = False,
) -> None:
    """Service inventory (nmap) of online devices, without a discovery round first."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    try:
        with _open_store(ctx) as store:
            i = asyncio.run(run_inventory(cfg, store, device_ids=device_ids or None, deep=deep))
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1) from e
    typer.echo(
        f"{i.devices} devices answered, {i.opened} ports opened, {i.closed} closed, "
        f"{len(i.new_findings)} new findings, {len(i.resolved_findings)} resolved"
    )


def _infra_line(f: Any) -> str:
    return (
        f"infra: dhcp servers {', '.join(f.dhcp_servers) or '-'}; {f.upnp_devices} upnp devices, "
        f"{f.igd_mappings} port mappings; {f.ipv6_devices} devices with global IPv6; "
        + (
            f"unifi: {f.unifi_clients} clients, {f.unifi_devices} devices; "
            if f.unifi_clients or f.unifi_devices
            else f"unifi not read ({f.unifi_error}); "
            if f.unifi_error
            else ""
        )
        + f"{len(f.new_findings)} new findings, {len(f.resolved_findings)} resolved"
    )


@app.command()
def infra(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """Infra probes now: DHCP servers, mDNS, UPnP (+ router port mappings), IPv6 exposure."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    try:
        with _open_store(ctx) as store:
            f = asyncio.run(run_infra(cfg, store))
            typer.echo(_infra_line(f))
            for r in store.infra("upnp"):
                flag = " [IGD]" if r.data.get("is_igd") else ""
                typer.echo(
                    f"  upnp {r.key:<15} {r.data.get('friendly_name') or '-'} "
                    f"{r.data.get('model') or ''}{flag}"
                )
                for m in r.data.get("mappings", []):
                    typer.echo(
                        f"       {m['external_port']}/{m['protocol']} -> {m['internal_client']}:"
                        f"{m['internal_port']}  {m.get('description', '')}"
                    )
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1) from e


@app.command()
def firmware(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """Firmware check now: versions devices report, and whether a newer release exists."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    try:
        with _open_store(ctx) as store:
            out = asyncio.run(run_firmware(cfg, store))
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1) from e
    if not out.found:
        typer.echo("no device reported a firmware version")
    for label, fw in sorted(out.found, key=lambda x: x[0].lower()):
        state = (
            (f"behind {fw.latest}" if fw.latest else "update available")
            if fw.update
            else "up to date"
            if fw.update is False
            else "latest unknown"
        )
        typer.echo(f"{label[:28]:<28} {fw.product:<15} {fw.version:<34} {state}")
    if not cfg.firmware.online:
        typer.echo(
            "online lookups are off ([firmware] online = false): only devices that"
            " check for updates themselves can report one"
        )


@app.command()
def exposure(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """What the internet sees of this network now: Shodan InternetDB on the public address."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    if not cfg.exposure.enabled:
        typer.echo(
            "the exposure check is off ([exposure] enabled = false): it sends the public"
            " address to internetdb.shodan.io, so it is opt-in",
            err=True,
        )
        raise typer.Exit(1)
    try:
        with _open_store(ctx) as store:
            out = asyncio.run(run_exposure(cfg, store))
    except RuntimeError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1) from e
    if out is None:
        typer.echo("could not determine the public address")
        raise typer.Exit(1)
    typer.echo(f"{out.ip} (address from {out.ip_source})")
    typer.echo(f"ports visible from the internet: {', '.join(map(str, out.ports)) or 'none'}")
    if out.hostnames:
        typer.echo(f"hostnames: {', '.join(out.hostnames)}")
    if out.vulns:
        typer.echo(f"known vulnerabilities: {', '.join(out.vulns)}")


@app.command()
def airos(
    ctx: typer.Context,
    accept_cert: Annotated[
        str | None,
        typer.Option(
            "--accept-cert",
            metavar="HOST",
            help="Forget the certificate pinned for this radio and pin the one it presents"
            " now. Only after checking why it changed (reset, replaced radio).",
        ),
    ] = None,
    retry_login: Annotated[
        str | None,
        typer.Option(
            "--retry-login",
            metavar="HOST",
            help="Forget that this radio rejected the login and try the configured"
            " credentials on it once more. Only after fixing the account on the radio:"
            " airOS locks it after three failures.",
        ),
    ] = None,
    verbose: VerboseOpt = False,
) -> None:
    """Read the airMAX radios now: model, firmware, and the link each one is part of."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    if not cfg.airos.enabled:
        typer.echo(
            "the airOS link is off ([airos] enabled = false): set hosts, username and"
            " password, see docs/airos.md",
            err=True,
        )
        raise typer.Exit(1)
    if accept_cert is not None:
        if accept_cert not in cfg.airos.hosts:
            typer.echo(f"{accept_cert} is not in airos.hosts", err=True)
            raise typer.Exit(1)
        with _open_store(ctx) as store:
            store.meta_delete(f"airos.pin.{accept_cert}")
        typer.echo(f"{accept_cert}: pinned certificate forgotten; pinning the current one")
    if retry_login is not None:
        if retry_login not in cfg.airos.hosts:
            typer.echo(f"{retry_login} is not in airos.hosts", err=True)
            raise typer.Exit(1)
        with _open_store(ctx) as store:
            store.meta_delete(f"airos.rejected.{retry_login}")
        typer.echo(f"{retry_login}: rejected login forgotten; trying the credentials once more")
    with _open_store(ctx) as store:
        out = asyncio.run(run_airos(cfg, store))
    for host in cfg.airos.hosts:
        if host in out.pinned:
            typer.echo(f"{host}: pinned certificate SHA-256 {out.pinned[host]}")
        radio = out.radios.get(host)
        if radio is None:
            typer.echo(f"{host}: error: {out.errors.get(host)}", err=True)
            continue
        eth = radio.ethernet
        typer.echo(
            f"{host}: {radio.hostname or '?'}, {radio.model}, airOS {radio.firmware},"
            f" {radio.mode} ({radio.netrole}), {radio.frequency_mhz or '?'} MHz"
            + (f", ethernet {eth.speed} Mbit/s" if eth and eth.speed else "")
        )
        for st in radio.stations:
            typer.echo(
                f"  linked with {st.remote_hostname or st.name or st.mac} ({st.ip or '?'}):"
                f" signal {st.signal} dBm / noise {st.noise} dBm here,"
                f" {st.remote_signal} / {st.remote_noise} there; CCQ {st.ccq}%,"
                f" airMAX quality {st.airmax_quality}% capacity {st.airmax_capacity}%,"
                f" {st.tx_mbps:g}/{st.rx_mbps:g} Mbit/s"
                if st.tx_mbps is not None and st.rx_mbps is not None
                else f"  linked with {st.remote_hostname or st.name or st.mac}"
            )
        if not radio.stations:
            typer.echo("  no link")
    if out.errors:
        raise typer.Exit(1)


@app.command()
def unifi(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """Read the UniFi controller now: networks, UniFi devices and the clients it sees."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    if not cfg.unifi.enabled:
        typer.echo(
            "the UniFi link is off ([unifi] enabled = false): set url and api_key, see"
            " docs/unifi.md",
            err=True,
        )
        raise typer.Exit(1)
    with _open_store(ctx) as store:
        out = asyncio.run(run_unifi(cfg, store))
    if out.error is not None:
        typer.echo(f"error: {out.error}", err=True)
        if "401" in out.error or "403" in out.error:
            typer.echo("the controller rejected the API key", err=True)
        if "CERTIFICATE_VERIFY_FAILED" in out.error or "certificate" in out.error.lower():
            typer.echo(
                "the console's certificate is self-signed: point unifi.ca_file at its"
                " certificate, or set verify_tls = false",
                err=True,
            )
        raise typer.Exit(1)
    snap = out.snapshot
    assert snap is not None
    typer.echo(f"UniFi Network {snap.version or '?'}, site {snap.site_name}")
    typer.echo("networks:")
    for n in snap.networks:
        flags = ", ".join(
            f for f, on in (("default", n.default), ("isolated", bool(n.isolation))) if on
        )
        typer.echo(
            f"  {n.name[:24]:<24} VLAN {n.vlan_id or '-'!s:<5} {n.subnet or '-':<20} {flags}"
        )
    typer.echo("devices:")
    # Columns as wide as their longest entry: model names run from "U6 Lite" to
    # "USW Pro Max 16 PoE", and a fixed width let the long ones run into the state.
    name_w = min(24, max((len(d.name or d.model) for d in snap.devices), default=0))
    model_w = max((len(d.model) for d in snap.devices), default=0)
    for dev in snap.devices:
        update = " update available" if dev.firmware_updatable else ""
        typer.echo(
            f"  {(dev.name or dev.model)[:24]:<{name_w}}  {dev.model:<{model_w}}  "
            f"{dev.state.lower():<8} {dev.firmware_version or '-':<14}{update}".rstrip()
        )
    if snap.pending:
        typer.echo("waiting for adoption:")
    for p in snap.pending:
        typer.echo(f"  {p.model or '?'}  {p.ip or '-'}  {p.mac}")
    wired = sum(1 for c in snap.clients if c.mac and c.wired)
    wireless = sum(1 for c in snap.clients if c.mac and not c.wired)
    guests = sum(1 for c in snap.clients if c.mac and c.guest)
    typer.echo(
        f"clients: {out.clients} ({wired} wired, {wireless} wireless, {guests} guest); "
        f"{out.clients - out.known_clients} not seen by lanwatch"
        + (f"; {out.named} devices named from the controller" if out.named else "")
    )
    with _open_store(ctx) as store:
        unknown = [r.data for r in store.infra("unifi-client") if not r.data.get("known")]
    for c in sorted(unknown, key=lambda c: str(c.get("name") or c.get("mac"))):
        typer.echo(
            f"  {str(c.get('name') or '-')[:24]:<24} {c.get('ip') or '-':<15} {c.get('mac'):<17} "
            f"{c.get('network_name') or '-'}"
        )


@app.command()
def snmp(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """Read every SNMPv3 target now: the router (what it is, its ARP table and DHCP
    leases) and every other device under [snmp.devices]."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    if not cfg.snmp.targets():
        typer.echo(
            "nothing to read over SNMP: no enabled devices under [snmp.devices]; see docs/snmp.md",
            err=True,
        )
        raise typer.Exit(1)
    with _open_store(ctx) as store:
        out = asyncio.run(run_snmp(cfg, store))
    failed = 0
    for t in out.targets:
        label = t.host or "the router"
        if t.error is not None:
            failed += 1
            typer.echo(f"error reading {label}: {t.error}", err=True)
            continue
        sys_ = t.system
        assert sys_ is not None
        days, rest = divmod(int(sys_.uptime_s), 86400)
        name = t.name or sys_.name or "(no name)"
        typer.echo(f"{label}: {name}, {sys_.vendor or sys_.object_id} ({t.role})")
        typer.echo(f"  {sys_.descr}")
        typer.echo(f"  up {days} days {rest // 3600} hours")
        if t.role == "router":
            typer.echo(
                f"  {len(out.neighbours)} ARP entries"
                + (f", {len(out.leases)} DHCP leases" if out.leases is not None else "")
                + (
                    f", {out.mismatches} held by another MAC than lanwatch saw"
                    if out.mismatches
                    else ""
                )
            )
        if sys_.location:
            typer.echo(f"  location: {sys_.location}")
    if failed:
        raise typer.Exit(1)


@app.command("snmp-audit")
def snmp_audit_cmd(
    ctx: typer.Context,
    host: Annotated[str | None, typer.Argument(help="one device's address; default: all")] = None,
    verbose: VerboseOpt = False,
) -> None:
    """Probe for SNMP default credentials now: v1/v2c with public and private, and
    whether an SNMPv3 agent answers. A GET of sysDescr only."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    if not audit_available():
        typer.echo("snmpget not found: install the snmp package", err=True)
        raise typer.Exit(1)
    with _open_store(ctx) as store:
        try:
            out = asyncio.run(run_snmp_audit(cfg, store, host))
        except ValueError as e:
            typer.echo(str(e), err=True)
            raise typer.Exit(1) from e
    for d, r in out.results:
        if r.communities:
            found = "; ".join(
                f"'{c}' on {', '.join('v' + v for v in vs)}" for c, vs in r.communities.items()
            )
            typer.echo(f"{d.ip} {d.label}: DEFAULT COMMUNITY answers: {found}")
            for key, what in (("sys_name", "name"), ("sys_descr", "description")):
                value = getattr(r, key)
                if value:
                    typer.echo(f"  {what}: {' '.join(value.split())[:200]}")
            if r.sys_object_id:
                typer.echo(f"  sysObjectID: {r.sys_object_id}")
        elif r.v3_agent:
            typer.echo(f"{d.ip} {d.label}: SNMPv3 agent, no default community answers")
        elif host is not None:
            typer.echo(f"{d.ip} {d.label}: no answer (no default community, no SNMPv3 agent)")
        for login in r.v3_defaults:
            typer.echo(f"{d.ip} {d.label}: SNMPv3 DEFAULT LOGIN works: {login}")
    typer.echo(f"{len(out.results)} devices probed, {len(out.new_findings)} new findings")


@app.command()
def services(ctx: typer.Context, device_id: int) -> None:
    """Open services on one device."""
    with _open_store(ctx) as store:
        d = store.device(device_id)
        if d is None:
            typer.echo("no such device", err=True)
            raise typer.Exit(1)
        rows = store.services(device_id)
        last = store.last_inventory_at(device_id)
    typer.echo(f"{d.label} {d.ip or ''}  last scan {local_str(last)}")
    if not rows:
        typer.echo("no open services recorded")
    for s in rows:
        scripts = ",".join(sorted(s.details)) if s.details else ""
        typer.echo(f"  {s.label:<50} {scripts}")


@app.command()
def web(ctx: typer.Context) -> None:
    """Serve only the web UI (no scanning)."""
    cfg = _state(ctx).loaded.config
    from lanwatch.web.app import create_app
    from lanwatch.web.server import make_server

    log.info("web ui on http://%s:%d", cfg.web.host, cfg.web.port)
    make_server(create_app(cfg), cfg.web.host, cfg.web.port).run()


@app.command()
def run(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """Run continuously: discovery, inventory, deep scans and the web UI in one process."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    log.info("lanwatch %s starting, data_dir=%s", __version__, cfg.data_dir)

    async def _main() -> None:
        with _open_store(ctx) as store:

            def persisted(
                name: str, fn: Callable[[], Awaitable[object]]
            ) -> Callable[[], Awaitable[None]]:
                async def wrapper() -> None:
                    await fn()
                    store.meta_set(f"job.{name}.last_run", str(time.time()))

                return wrapper

            def job(
                name: str,
                interval: int,
                fn: Callable[[], Awaitable[object]],
                lane: str = "main",
                after: str | None = None,
            ) -> Job:
                j = Job(name, interval, persisted(name, fn), lane=lane, after=after)
                last = store.meta_get(f"job.{name}.last_run")
                j.resume_from(float(last) if last else None)
                return j

            jobs = []
            if cfg.oui.online:
                # First in line: on a fresh install the registry is then in place before
                # the first discovery round names its devices.
                jobs.append(job("oui", 7 * 86400, lambda: oui.refresh(cfg)))
            jobs += [
                job(
                    "discovery",
                    cfg.schedule.discovery_interval_s,
                    lambda: run_discovery(cfg, store),
                ),
                # Service scans take their own lane: an hour of nmap must not hold up
                # discovery, infra and the rest. They wait for this process's first
                # discovery round, which gives them their targets.
                job(
                    "inventory",
                    cfg.schedule.inventory_interval_s,
                    lambda: run_inventory(cfg, store),
                    lane="scan",
                    after="discovery",
                ),
                job(
                    "deep",
                    cfg.schedule.deep_interval_s,
                    lambda: run_inventory(cfg, store, deep=True),
                    lane="scan",
                    after="discovery",
                ),
                job("infra", cfg.schedule.infra_interval_s, lambda: run_infra(cfg, store)),
                job("maintenance", 86400, lambda: run_maintenance(cfg, store)),
            ]
            if cfg.firmware.enabled:
                jobs.append(job("firmware", 86400, lambda: run_firmware(cfg, store)))
            if cfg.exposure.enabled:
                jobs.append(job("exposure", 86400, lambda: run_exposure(cfg, store)))
            if cfg.llm.enabled:
                from lanwatch.llm import hooks as llm_hooks

                async def digest_job() -> None:
                    from lanwatch.notify import dispatch as notify

                    await llm_hooks.catch_up(cfg, store)
                    text = await llm_hooks.write_digest(cfg, store)
                    if text:
                        await notify.digest(cfg, store, text)
                    update_overview(store, cfg)

                # The LLM jobs can take minutes on a large local model: their own lane.
                d = Job.daily(
                    "digest", cfg.schedule.digest_time, persisted("digest", digest_job), lane="llm"
                )
                last = store.meta_get("job.digest.last_run")
                d.resume_from(float(last) if last else None)
                jobs.append(d)
                # Structural suggestions change slowly with the inventory: weekly is enough,
                # and "Run now" on the status page covers the impatient case.
                jobs.append(
                    job(
                        "suggest",
                        7 * 86400,
                        lambda: llm_hooks.write_suggestions(cfg, store),
                        lane="llm",
                    )
                )
            sched = Scheduler(jobs)
            sched.install_signal_handlers()
            tasks = [asyncio.create_task(sched.run_forever())]

            def decoy_hit(source: str, port: int) -> None:
                # Run the rules right away instead of at the next scheduled round.
                if record_hit(store, source, port):
                    sched.trigger("discovery")

            decoys = Decoys(cfg.decoy, decoy_hit, lambda ports: publish_listening(store, ports))
            tasks.append(asyncio.create_task(decoys.serve_until(sched.stopped)))
            if cfg.web.enabled:
                from lanwatch.web.app import create_app
                from lanwatch.web.server import make_server, serve_until

                server = make_server(create_app(cfg, sched, decoys), cfg.web.host, cfg.web.port)
                log.info("web ui on http://%s:%d", cfg.web.host, cfg.web.port)
                tasks.append(asyncio.create_task(serve_until(server, sched.stopped)))
            # Config read and everything set up: a Type=notify unit's start job ends here.
            notify_ready()
            await asyncio.gather(*tasks)

    asyncio.run(_main())


@app.command()
def devices(
    ctx: typer.Context,
    all_: Annotated[bool, typer.Option("--all", "-a", help="Include offline devices.")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List known devices."""
    with _open_store(ctx) as store:
        rows = store.devices(online_only=not all_)
    if as_json:
        typer.echo(json.dumps([asdict(r) for r in rows], indent=2))
        return
    if not rows:
        typer.echo("no devices (run `lanwatch scan` first)")
        return
    typer.echo(f"{'':1} {'id':>4}  {'ip':<15} {'mac':<17} {'label':<28} {'vendor':<22} last seen")
    for d in rows:
        typer.echo(
            f"{'●' if d.online else '○'} {d.id:>4}  {d.ip or '-':<15} {d.mac or '-':<17} "
            f"{(d.name or d.hostname or '-')[:28]:<28} {(d.vendor or '-')[:22]:<22} "
            f"{local_str(d.last_seen)}"
        )


@app.command()
def findings(
    ctx: typer.Context,
    status: Annotated[str, typer.Option(help="open, acked, resolved or all")] = "open",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List findings."""
    st = None if status == "all" else FindingStatus(status)
    with _open_store(ctx) as store:
        rows = store.findings(st)
        if as_json:
            typer.echo(json.dumps([asdict(r) for r in rows], indent=2, default=str))
            return
        if not rows:
            typer.echo("no findings")
            return
        for f in rows:
            dev = store.device(f.device_id) if f.device_id is not None else None
            typer.echo(
                f"{f.id}  {f.severity.value:<8} {f.status.value:<8} {f.rule_id:<26} "
                f"{f.title}  [{dev.label if dev else '-'}]  {local_str(f.first_seen)}"
            )


@app.command()
def ack(
    ctx: typer.Context,
    finding_id: str,
    accept: Annotated[
        str | None,
        typer.Option(
            help="Accept the finding for good, giving the reason. It then stays acknowledged"
            " even if it goes away and comes back."
        ),
    ] = None,
) -> None:
    """Acknowledge an open finding."""
    cfg = _state(ctx).loaded.config
    with _open_store(ctx) as store:
        if not store.ack(finding_id, accept=accept is not None, note=accept or None):
            typer.echo("no open finding with that id", err=True)
            raise typer.Exit(1)
        update_overview(store, cfg)
    typer.echo(f"{'accepted' if accept is not None else 'acked'} {finding_id}")


@app.command()
def reopen(ctx: typer.Context, finding_id: str) -> None:
    """Undo an acknowledgement or acceptance."""
    cfg = _state(ctx).loaded.config
    with _open_store(ctx) as store:
        if not store.reopen(finding_id):
            typer.echo("no acknowledged finding with that id", err=True)
            raise typer.Exit(1)
        update_overview(store, cfg)
    typer.echo(f"reopened {finding_id}")


@app.command()
def name(ctx: typer.Context, device_id: int, label: str) -> None:
    """Give a device a human name (shown in overview and findings)."""
    cfg = _state(ctx).loaded.config
    with _open_store(ctx) as store:
        if not store.set_device_name(device_id, label):
            typer.echo("no such device", err=True)
            raise typer.Exit(1)
        update_overview(store, cfg)
    typer.echo(f"device {device_id} is now {label!r}")


@app.command()
def overview(
    ctx: typer.Context,
    write: Annotated[
        bool, typer.Option(help="Write to the overview path instead of stdout.")
    ] = False,
) -> None:
    """Render the network overview."""
    cfg = _state(ctx).loaded.config
    with _open_store(ctx) as store:
        if write:
            path = update_overview(store, cfg)
            typer.echo(str(path) if path else f"unchanged: {cfg.overview_path}")
        else:
            typer.echo(render(store, cfg))


@app.command()
def rules(ctx: typer.Context) -> None:
    """List rules with effective severity and enabled state."""
    cfg = _state(ctx).loaded.config
    for r in all_rules():
        o = cfg.rules.get(r.id)
        enabled = not (o is not None and o.enabled is False)
        sev = (o.severity if o is not None and o.severity is not None else r.default_severity).value
        typer.echo(f"{'on ' if enabled else 'off'}  {sev:<8} {r.id:<28} {r.description}")


@app.command()
def explain(
    ctx: typer.Context,
    finding_id: str,
    refresh: Annotated[bool, typer.Option(help="Ignore the stored explanation.")] = False,
    verbose: VerboseOpt = False,
) -> None:
    """Explain one finding with the local LLM (and store the explanation)."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    from lanwatch.llm.hooks import after_round

    with _open_store(ctx) as store:
        f = store.finding(finding_id)
        if f is None:
            typer.echo("no such finding", err=True)
            raise typer.Exit(1)
        if refresh:
            store.set_explanation(finding_id, "")
            f = store.finding(finding_id)
        if f is not None and not f.explanation:
            asyncio.run(after_round(cfg, store, [], [finding_id]))
            f = store.finding(finding_id)
        update_overview(store, cfg)
    assert f is not None
    typer.echo(f"{f.severity.value.upper()}  {f.title}\n")
    typer.echo(f.explanation or "(no explanation: LLM disabled or unavailable, see log)")


@app.command()
def classify(
    ctx: typer.Context,
    device_ids: Annotated[list[int] | None, typer.Argument(help="Default: all devices.")] = None,
    verbose: VerboseOpt = False,
) -> None:
    """Classify devices with the local LLM (kind + one-line description)."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    from lanwatch.llm.hooks import after_round

    with _open_store(ctx) as store:
        ids = device_ids or [d.id for d in store.devices()]
        asyncio.run(after_round(cfg, store, ids, []))
        update_overview(store, cfg)
        for did in ids:
            d = store.device(did)
            if d:
                conf = f"{d.kind_confidence:.0%}" if d.kind_confidence is not None else "-"
                typer.echo(
                    f"{d.id:>4}  {d.ip or '-':<15} {d.kind or '-':<16} {conf:>4}  "
                    f"{d.description or ''}"
                )


@app.command()
def digest(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """Write today's digest now (open findings + last 24h) and print it."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    from lanwatch.llm.hooks import catch_up, write_digest

    with _open_store(ctx) as store:
        asyncio.run(catch_up(cfg, store))
        text = asyncio.run(write_digest(cfg, store))
        update_overview(store, cfg)
    if text is None:
        typer.echo("no digest: LLM disabled or unavailable (see log)", err=True)
        raise typer.Exit(1)
    typer.echo(text)


@app.command()
def suggest(ctx: typer.Context, verbose: VerboseOpt = False) -> None:
    """Ask the local LLM for structural improvements based on the whole inventory."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    from lanwatch.llm.hooks import write_suggestions

    with _open_store(ctx) as store:
        text = asyncio.run(write_suggestions(cfg, store))
    if text is None:
        typer.echo("no suggestions: LLM disabled or unavailable (see log)", err=True)
        raise typer.Exit(1)
    typer.echo(text)


@app.command()
def ask(
    ctx: typer.Context,
    question: list[str],
    no_actions: Annotated[bool, typer.Option("--no-actions", help="Read-only tools only.")] = False,
    quiet: Annotated[bool, typer.Option("-q", help="Hide the tool trace.")] = False,
    verbose: VerboseOpt = False,
) -> None:
    """Ask the local LLM about the network. It reads the inventory through tools and can
    act (ack, name, scan) when you ask it to."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    from lanwatch.llm.hooks import ask as _ask

    with _open_store(ctx) as store:
        answer = asyncio.run(_ask(cfg, store, " ".join(question), allow_actions=not no_actions))
    if answer is None:
        typer.echo("no answer: LLM disabled or unavailable (see log)", err=True)
        raise typer.Exit(1)
    if not quiet:
        for t in answer.tools:
            args = ", ".join(f"{k}={v!r}" for k, v in t["arguments"].items())
            typer.echo(f"  [tool] {t['name']}({args}){'' if t['ok'] else '  -> error'}", err=True)
    typer.echo(answer.text)


@app.command()
def timeline(
    ctx: typer.Context,
    device: Annotated[int | None, typer.Option(help="Only this device id.")] = None,
    presence: Annotated[bool, typer.Option(help="Include online/offline events.")] = False,
    limit: Annotated[int, typer.Option()] = 50,
) -> None:
    """Recent events: devices, services, findings, infra changes."""
    with _open_store(ctx) as store:
        rows = store.events(
            device_id=device, limit=limit, exclude_prefix=None if presence else "presence."
        )
    if not rows:
        typer.echo("no events yet")
    for e in rows:
        dev = f"#{e.device_id}" if e.device_id is not None else ""
        typer.echo(f"{local_str(e.ts)}  {e.kind:<20} {dev:>5}  {e.summary}")


@app.command()
def search(ctx: typer.Context, query: str) -> None:
    """Search devices, services and findings."""
    with _open_store(ctx) as store:
        res = store.search(query)
        for d in res["devices"]:
            typer.echo(f"device  #{d.id:<4} {d.ip or '-':<15} {d.mac or '-':<17} {d.label}")
        for s in res["services"]:
            typer.echo(f"service #{s.device_id:<4} {s.label}")
        for f in res["findings"]:
            typer.echo(f"finding {f.id}  [{f.severity.value}] {f.status.value:<8} {f.title}")
    if not any(res.values()):
        typer.echo("no matches")


@app.command("notify")
def notify_cmd(
    ctx: typer.Context,
    test: Annotated[
        bool, typer.Option("--test", help="Send a test message to all channels.")
    ] = False,
    limit: Annotated[int, typer.Option(help="Log entries to show.")] = 20,
) -> None:
    """Show the notification log, or send a test notification."""
    cfg = _state(ctx).loaded.config
    from lanwatch.notify import dispatch

    with _open_store(ctx) as store:
        if test:
            chans = [c.name for c in dispatch.channels(cfg)]
            if not chans:
                typer.echo("no notification channels enabled (see [notify] in config)", err=True)
                raise typer.Exit(1)
            n = asyncio.run(dispatch.test_message(cfg, store))
            typer.echo(f"delivered to {n}/{len(chans)} channels: {', '.join(chans)}")
            if n < len(chans):
                raise typer.Exit(1)
            return
        rows = store.notifications(limit)
    if not rows:
        typer.echo("no notifications sent yet")
    for r in rows:
        status = "ok " if r.ok else "ERR"
        typer.echo(
            f"{local_str(r.ts)}  {status} {r.channel:<15} {r.kind:<17} {r.title}"
            + (f"  ({r.error})" if r.error else "")
        )


@llm_app.command("check")
def llm_check(ctx: typer.Context) -> None:
    """Verify the LLM endpoint (Ollama or KoboldCpp) and that the model is there.

    With [llm.fallback] both servers are checked; it fails only when neither is usable."""
    cfg = _state(ctx).loaded.config
    from lanwatch.llm.client import make_client

    async def _check() -> int:
        client = make_client(cfg.llm)
        servers = client.servers()
        try:
            statuses = [await s.status() for s in servers]
        finally:
            await client.aclose()
        usable = 0
        for i, (server, st) in enumerate(zip(servers, statuses, strict=True)):
            role = "  (fallback)" if i else ""
            version = f"  version: {st.version}" if st.version else ""
            typer.echo(f"backend: {server.backend_name}{role}")
            typer.echo(f"endpoint: {server.base_url}  reachable: {st.reachable}{version}")
            if not st.reachable:
                typer.echo(f"error: {st.error}", err=True)
                continue
            typer.echo(f"model: {server.cfg.model}  present: {st.model_present}")
            typer.echo("models: " + (", ".join(st.models) or "(none)"))
            if not st.model_present:
                typer.echo(server.missing_model_hint(), err=True)
                continue
            usable += 1
        # With a fallback, one working server is enough for the LLM features to run.
        return 0 if usable else 1

    raise typer.Exit(asyncio.run(_check()))


@llm_app.command("eval")
def llm_eval(
    ctx: typer.Context,
    model: Annotated[
        str | None, typer.Option(help="Model to evaluate; default from config.")
    ] = None,
    suite: Annotated[str, typer.Option(help="classify, chat or all")] = "all",
    file: Annotated[
        Path | None, typer.Option(help="JSONL golden set (overrides suite path).")
    ] = None,
    verbose: VerboseOpt = False,
) -> None:
    """Score a model on lanwatch's own tasks: device classification and tool-calling chat."""
    if verbose:
        set_verbose()
    cfg = _state(ctx).loaded.config
    if model:
        cfg = cfg.model_copy(update={"llm": cfg.llm.model_copy(update={"model": model})})
    from lanwatch.llm.evaluate import run_chat_eval, run_eval

    failed = False
    if suite in ("classify", "all"):
        report = asyncio.run(run_eval(cfg, file or Path("evals/devices.jsonl")))
        typer.echo(report.render())
        failed |= report.errors > 0
    if suite in ("chat", "all"):
        chat = asyncio.run(run_chat_eval(cfg, file or Path("evals/chat.jsonl")))
        typer.echo(chat.render())
        failed |= chat.errors > 0
    raise typer.Exit(1 if failed else 0)


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    """Print the effective configuration after all layers."""
    loaded = _state(ctx).loaded
    typer.echo(f"# file: {loaded.config_file or '(none, defaults)'}")
    if loaded.env_keys:
        typer.echo(f"# env: {', '.join(sorted(loaded.env_keys))}")
    typer.echo(f"# store: {loaded.config.store_path}")
    typer.echo(f"# overview: {loaded.config.overview_path}")
    typer.echo(dump_effective(loaded.config))


@config_app.command("path")
def config_path(ctx: typer.Context) -> None:
    """Print which config file is in use."""
    loaded = _state(ctx).loaded
    typer.echo(str(loaded.config_file) if loaded.config_file else "")


if __name__ == "__main__":
    sys.exit(app())
