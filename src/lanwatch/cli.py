"""Command line interface."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer

from lanwatch import __version__
from lanwatch.config import ConfigError, LoadedConfig, dump_effective, load_config
from lanwatch.logging_setup import setup_logging
from lanwatch.models import FindingStatus, local_str
from lanwatch.overview import render
from lanwatch.overview import update as update_overview
from lanwatch.pipeline import run_discovery
from lanwatch.rules.engine import all_rules
from lanwatch.scheduler import Job, Scheduler
from lanwatch.store import Store

app = typer.Typer(no_args_is_help=True, add_completion=False, help="lanwatch: audit your own LAN.")
config_app = typer.Typer(no_args_is_help=True, help="Show effective configuration.")
app.add_typer(config_app, name="config")
log = logging.getLogger("lanwatch")


@dataclass
class State:
    loaded: LoadedConfig


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
) -> None:
    setup_logging(log_level, "json" if log_format == "json" else "text")
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
def scan(ctx: typer.Context) -> None:
    """Run one discovery round now, then exit."""
    cfg = _state(ctx).loaded.config
    with _open_store(ctx) as store:
        try:
            outcome = asyncio.run(run_discovery(cfg, store))
        except RuntimeError as e:
            typer.echo(f"error: {e}", err=True)
            raise typer.Exit(1) from e
    typer.echo(
        f"{outcome.hosts} hosts via {outcome.backend} on {', '.join(outcome.subnets)}; "
        f"{len(outcome.new_devices)} new devices, {len(outcome.new_findings)} new findings"
        + (" (baseline)" if outcome.baseline else "")
    )


@app.command()
def run(ctx: typer.Context) -> None:
    """Run continuously (daemon mode). Stops cleanly on SIGTERM/SIGINT."""
    cfg = _state(ctx).loaded.config
    log.info("lanwatch %s starting, data_dir=%s", __version__, cfg.data_dir)

    async def _main() -> None:
        with _open_store(ctx) as store:

            async def discovery() -> None:
                await run_discovery(cfg, store)

            sched = Scheduler([Job("discovery", cfg.schedule.discovery_interval_s, discovery)])
            sched.install_signal_handlers()
            await sched.run_forever()

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
        typer.echo(json.dumps([r.__dict__ for r in rows], indent=2))
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
            typer.echo(json.dumps([r.__dict__ for r in rows], indent=2, default=str))
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
def ack(ctx: typer.Context, finding_id: str) -> None:
    """Acknowledge an open finding."""
    cfg = _state(ctx).loaded.config
    with _open_store(ctx) as store:
        if not store.ack(finding_id):
            typer.echo("no open finding with that id", err=True)
            raise typer.Exit(1)
        update_overview(store, cfg)
    typer.echo(f"acked {finding_id}")


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
