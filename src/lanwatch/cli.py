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

from lanwatch import __version__
from lanwatch.config import ConfigError, LoadedConfig, dump_effective, load_config
from lanwatch.decoy import Decoys, publish_listening, record_hit
from lanwatch.logging_setup import set_verbose, setup_logging
from lanwatch.models import FindingStatus, local_str
from lanwatch.overview import render
from lanwatch.overview import update as update_overview
from lanwatch.pipeline import (
    run_discovery,
    run_firmware,
    run_infra,
    run_inventory,
    run_maintenance,
)
from lanwatch.rules.engine import all_rules
from lanwatch.scheduler import Job, Scheduler
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
        f"{len(f.new_findings)} new findings, {len(f.resolved_findings)} resolved"
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
            f"behind {fw.latest}"
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

            def job(name: str, interval: int, fn: Callable[[], Awaitable[object]]) -> Job:
                j = Job(name, interval, persisted(name, fn))
                last = store.meta_get(f"job.{name}.last_run")
                j.resume_from(float(last) if last else None)
                return j

            jobs = [
                job(
                    "discovery",
                    cfg.schedule.discovery_interval_s,
                    lambda: run_discovery(cfg, store),
                ),
                job(
                    "inventory",
                    cfg.schedule.inventory_interval_s,
                    lambda: run_inventory(cfg, store),
                ),
                job(
                    "deep",
                    cfg.schedule.deep_interval_s,
                    lambda: run_inventory(cfg, store, deep=True),
                ),
                job("infra", cfg.schedule.infra_interval_s, lambda: run_infra(cfg, store)),
                job("maintenance", 86400, lambda: run_maintenance(cfg, store)),
            ]
            if cfg.firmware.enabled:
                jobs.append(job("firmware", 86400, lambda: run_firmware(cfg, store)))
            if cfg.llm.enabled:
                from lanwatch.llm import hooks as llm_hooks

                async def digest_job() -> None:
                    from lanwatch.notify import dispatch as notify

                    await llm_hooks.catch_up(cfg, store)
                    text = await llm_hooks.write_digest(cfg, store)
                    if text:
                        await notify.digest(cfg, store, text)
                    update_overview(store, cfg)

                d = Job.daily("digest", cfg.schedule.digest_time, persisted("digest", digest_job))
                last = store.meta_get("job.digest.last_run")
                d.resume_from(float(last) if last else None)
                jobs.append(d)
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
    """Verify the Ollama endpoint and that the configured model is pulled."""
    cfg = _state(ctx).loaded.config
    from lanwatch.llm.client import OllamaClient

    async def _check() -> int:
        client = OllamaClient(cfg.llm)
        try:
            st = await client.status()
        finally:
            await client.aclose()
        version = f"  version: {st.version}" if st.version else ""
        typer.echo(f"endpoint: {cfg.llm.base_url}  reachable: {st.reachable}{version}")
        if not st.reachable:
            typer.echo(f"error: {st.error}", err=True)
            return 1
        typer.echo(f"model: {cfg.llm.model}  present: {st.model_present}")
        typer.echo("models: " + (", ".join(st.models) or "(none)"))
        if not st.model_present:
            typer.echo(f"run: ollama pull {cfg.llm.model}", err=True)
            return 1
        return 0

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
