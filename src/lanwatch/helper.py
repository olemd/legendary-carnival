"""lanwatch-helper: a tiny root daemon that runs the few privileged commands lanwatch needs,
so the main process can live in an unprivileged (rootless podman) container.

Protocol: one JSON object per line over a unix socket.
  {"op": "which", "binary": "nmap"}                  -> {"available": true, "root": true}
  {"op": "run", "argv": [...], "timeout": 600}       -> {"rc": 0, "stdout": "...", "stderr": "..."}
  anything else, or an argv outside the allowlist    -> {"error": "..."}

The allowlist is the whole security model: only four binaries, only flags lanwatch itself
generates, targets must parse as IP addresses or networks. No shell, no files, no script args.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import grp
import ipaddress
import json
import logging
import os
import re
import signal
from pathlib import Path

from lanwatch.collectors.base import have, privileged, run_cmd
from lanwatch.logging_setup import setup_logging

log = logging.getLogger("lanwatch.helper")

MAX_TIMEOUT = 3600
MAX_ARGS = 1100  # deep scan target lists can be long

_IFACE = r"[A-Za-z][A-Za-z0-9_.:-]{0,31}"
_FLAGS: dict[str, list[str]] = {
    "nmap": [
        r"-oX",
        r"-",
        r"-n",
        r"-Pn",
        r"-sn",
        r"-sV",
        r"-sU",
        r"-6",
        r"-T[0-5]",
        r"-p-",
        r"--max-rate=\d{1,6}",
        r"--max-hostgroup=\d{1,4}",
        r"--top-ports=\d{1,5}",
        r"--exclude-ports=\d{1,5}(,\d{1,5}){0,50}",
        r"--version-intensity=\d",
        r"--script=[a-z0-9-]+(,[a-z0-9-]+){0,20}",
    ],
    "arp-scan": [
        r"--plain",
        r"--retry=\d{1,2}",
        r"--interval=\d{1,5}",
        rf"--interface={_IFACE}",
    ],
    "ip": [r"-j", r"-6", r"addr", r"neigh", r"route", r"show"],
    "ping": [r"-c", r"-W", r"-6", r"\d{1,3}"],
}
# Flags that consume the next argument, with the pattern that argument must match.
_PAIRED: dict[str, dict[str, str]] = {
    "nmap": {"--host-timeout": r"\d{1,4}[smh]", "-e": _IFACE},
}
_TARGET_BINARIES = {"nmap", "arp-scan", "ping"}
# ping may address the all-nodes multicast group on an interface to prime the IPv6 neighbour table.
_EXTRA_TARGETS: dict[str, str] = {"ping": rf"ff02::1%{_IFACE}"}
_COMPILED = {b: [re.compile(f"^(?:{f})$") for f in flags] for b, flags in _FLAGS.items()}
_COMPILED_PAIRED = {
    b: {flag: re.compile(f"^(?:{pat})$") for flag, pat in pairs.items()}
    for b, pairs in _PAIRED.items()
}
_COMPILED_EXTRA = {b: re.compile(f"^(?:{p})$") for b, p in _EXTRA_TARGETS.items()}


def _is_target(arg: str) -> bool:
    if "%" in arg:  # scope ids are free-form in ipaddress; only _EXTRA_TARGETS may carry one
        return False
    try:
        ipaddress.ip_network(arg, strict=False)
        return True
    except ValueError:
        return False


def validate_argv(argv: list[str]) -> str | None:
    """Return None when argv is allowed, else the reason it is not."""
    if not argv or not all(isinstance(a, str) for a in argv):
        return "argv must be a non-empty list of strings"
    if len(argv) > MAX_ARGS:
        return f"too many arguments ({len(argv)})"
    binary = argv[0]
    patterns = _COMPILED.get(binary)
    if patterns is None:
        return f"binary not allowed: {binary!r}"
    paired = _COMPILED_PAIRED.get(binary, {})
    extra = _COMPILED_EXTRA.get(binary)
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in paired:
            if i + 1 >= len(argv) or not paired[arg].match(argv[i + 1]):
                return f"bad value for {arg} in {binary}: {argv[i + 1 : i + 2]!r}"
            i += 2
            continue
        if any(p.match(arg) for p in patterns):
            i += 1
            continue
        if binary in _TARGET_BINARIES and _is_target(arg):
            i += 1
            continue
        if extra is not None and extra.match(arg):
            i += 1
            continue
        return f"argument not allowed for {binary}: {arg!r}"
    return None


async def handle_request(payload: object, sem: asyncio.Semaphore) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {"error": "request must be a JSON object"}
    op = payload.get("op")
    if op == "which":
        binary = payload.get("binary")
        if not isinstance(binary, str) or binary not in _FLAGS:
            return {"error": "unknown binary"}
        # The key is called "root" for wire compatibility; it means raw-socket privilege.
        return {"available": have(binary), "root": privileged()}
    if op == "run":
        argv = payload.get("argv")
        if not isinstance(argv, list):
            return {"error": "argv must be a list"}
        reason = validate_argv(argv)
        if reason:
            log.warning("refused: %s", reason)
            return {"error": reason}
        timeout_raw = payload.get("timeout", 600)
        timeout = float(timeout_raw) if isinstance(timeout_raw, int | float) else 600.0
        timeout = max(1.0, min(timeout, MAX_TIMEOUT))
        async with sem:
            log.info("run: %s", " ".join(argv[:6]) + (" ..." if len(argv) > 6 else ""))
            rc, out, err = await run_cmd(argv, timeout)
        return {"rc": rc, "stdout": out, "stderr": err}
    return {"error": f"unknown op {op!r}"}


async def _serve(socket_path: Path, group: str | None, concurrency: int) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            try:
                payload = json.loads(line) if line.strip() else None
            except ValueError:
                payload = None
            reply = (
                await handle_request(payload, sem) if payload is not None else {"error": "bad JSON"}
            )
            writer.write(json.dumps(reply).encode() + b"\n")
            await writer.drain()
        except (TimeoutError, OSError) as e:
            log.warning("client error: %s", e)
        finally:
            writer.close()

    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()
    server = await asyncio.start_unix_server(on_client, path=str(socket_path), limit=1 << 20)
    os.chmod(socket_path, 0o660)
    if group:
        os.chown(socket_path, -1, grp.getgrnam(group).gr_gid)
    log.info("listening on %s (group %s)", socket_path, group or "unchanged")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    async with server:
        await stop.wait()
    with contextlib.suppress(OSError):
        socket_path.unlink()
    log.info("stopped")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="lanwatch-helper", description=__doc__.split("\n", 2)[0])
    p.add_argument("--socket", type=Path, default=Path("/run/lanwatch/helper.sock"))
    p.add_argument("--group", default=None, help="group owner of the socket (e.g. lanwatch)")
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--log-level", default="info")
    a = p.parse_args(argv)
    setup_logging(a.log_level)
    if not privileged():
        log.warning("neither root nor CAP_NET_RAW: raw-socket scans will be unavailable")
    asyncio.run(_serve(a.socket, a.group, a.concurrency))


if __name__ == "__main__":
    main()
