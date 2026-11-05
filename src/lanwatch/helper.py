"""lanwatch-helper: a tiny daemon that runs the few privileged commands lanwatch needs, so
the main process can run without any privileges (packaged service, rootless podman).

It needs raw sockets and nothing else: run it as root, or as a dedicated user with
CAP_NET_RAW as an ambient capability. Under systemd it takes its listening socket from a
.socket unit (socket activation), so it never has to create or chown one itself.

Protocol: one JSON object per line over a unix socket.
  {"op": "which", "binary": "nmap"}                  -> {"available": true, "root": true}
  {"op": "run", "argv": [...], "timeout": 600}       -> {"rc": 0, "stdout": "...", "stderr": "..."}
  anything else, or an argv outside the allowlist    -> {"error": "..."}

The allowlist is the whole security model: only four binaries, only flags lanwatch itself
generates, only the nmap scripts lanwatch uses, and only targets inside networks this host
is directly attached to. No shell, no files, no script args. Whoever controls the client
can therefore at most make this host scan its own LAN with the scripts it already runs.
Anything more (another script, a routed subnet) has to be allowed here, on the privileged
side, with --allow-script / --allow-net.
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
import socket
import sys
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from lanwatch.collectors.base import have, privileged, run_cmd
from lanwatch.config import ScanConfig
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


Net = ipaddress.IPv4Network | ipaddress.IPv6Network

# Every nmap script lanwatch can ask for with its default configuration: the service-scan
# scripts, the optional vulners lookup and the two broadcast probes.
DEFAULT_SCRIPTS = frozenset(
    {
        *ScanConfig().scripts,
        "vulners",
        "broadcast-dhcp-discover",
        "broadcast-dns-service-discovery",
    }
)


@dataclass(frozen=True, slots=True)
class Policy:
    """The part of the allowlist that depends on this installation rather than on fixed
    patterns: which nmap scripts may run, and which networks may be scanned."""

    scripts: frozenset[str]
    nets: tuple[Net, ...]

    def allows_target(self, target: Net) -> bool:
        return any(
            target.version == net.version and target.subnet_of(net)  # type: ignore[arg-type]
            for net in self.nets
        )


def parse_attached(data: object) -> tuple[Net, ...]:
    """The networks of every address in `ip -j addr show` output, IPv4 and IPv6."""
    nets: list[Net] = []
    for iface in data if isinstance(data, list) else []:
        for a in iface.get("addr_info", []) if isinstance(iface, dict) else []:
            try:
                nets.append(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network)
            except (KeyError, TypeError, ValueError):
                continue
    return tuple(dict.fromkeys(nets))


async def attached_networks() -> tuple[Net, ...]:
    """Networks this host has an address in. Empty when `ip` is unavailable: the helper then
    refuses every target rather than guess (fail closed)."""
    rc, out, _ = await run_cmd(["ip", "-j", "addr", "show"], 10)
    if rc != 0:
        return ()
    try:
        return parse_attached(json.loads(out))
    except ValueError:
        return ()


class Policies:
    """Hands out the current Policy. Attached networks are re-read at most every `ttl`
    seconds, so a new address or VLAN is picked up without restarting the helper."""

    def __init__(self, scripts: Iterable[str] = (), nets: Iterable[Net] = (), ttl: float = 30):
        self._scripts = DEFAULT_SCRIPTS | frozenset(scripts)
        self._extra = tuple(nets)
        self._ttl = ttl
        self._attached: tuple[Net, ...] = ()
        self._read_at = float("-inf")

    async def current(self) -> Policy:
        if time.monotonic() - self._read_at > self._ttl:
            self._attached = await attached_networks()
            self._read_at = time.monotonic()
        return Policy(self._scripts, (*self._attached, *self._extra))


def _target(arg: str) -> Net | None:
    if "%" in arg:  # scope ids are free-form in ipaddress; only _EXTRA_TARGETS may carry one
        return None
    try:
        return ipaddress.ip_network(arg, strict=False)
    except ValueError:
        return None


def validate_argv(argv: list[str], policy: Policy) -> str | None:
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
            if arg.startswith("--script="):
                for name in arg.removeprefix("--script=").split(","):
                    if name not in policy.scripts:
                        return (
                            f"nmap script not allowed: {name!r}"
                            f" (start lanwatch-helper with --allow-script {name})"
                        )
            i += 1
            continue
        target = _target(arg) if binary in _TARGET_BINARIES else None
        if target is not None:
            if not policy.allows_target(target):
                return (
                    f"target {arg} is outside the networks this host is attached to"
                    f" (start lanwatch-helper with --allow-net {target})"
                )
            i += 1
            continue
        if extra is not None and extra.match(arg):
            i += 1
            continue
        return f"argument not allowed for {binary}: {arg!r}"
    return None


async def handle_request(
    payload: object, sem: asyncio.Semaphore, policy: Policy
) -> dict[str, object]:
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
        reason = validate_argv(argv, policy)
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


async def _answer_while_connected(
    payload: object, sem: asyncio.Semaphore, policy: Policy, reader: asyncio.StreamReader
) -> dict[str, object] | None:
    """Handle one request, but stop (and kill the command) if the client hangs up first.
    A client sends one line and then only waits, so end-of-file on its side means it has
    gone: stopped, restarted or killed. Returns None in that case."""
    work = asyncio.create_task(handle_request(payload, sem, policy))
    hangup = asyncio.create_task(reader.read(1))
    try:
        await asyncio.wait({work, hangup}, return_when=asyncio.FIRST_COMPLETED)
        if not work.done() and hangup.result() != b"":
            await work  # stray bytes are not a hang-up; let the command finish
        if work.done():
            return work.result()
        work.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await work
        return None
    finally:
        hangup.cancel()
        work.cancel()


# First file descriptor systemd passes to a socket-activated service (sd_listen_fds(3)).
SD_LISTEN_FDS_START = 3


def systemd_socket_fd(environ: Mapping[str, str], pid: int) -> int | None:
    """The fd of the listening socket systemd passed to this process, if it passed exactly
    one. LISTEN_PID guards against variables inherited from a parent they were meant for."""
    if environ.get("LISTEN_PID") != str(pid) or environ.get("LISTEN_FDS") != "1":
        return None
    return SD_LISTEN_FDS_START


async def _serve(
    socket_path: Path,
    group: str | None,
    concurrency: int,
    inherited: socket.socket | None = None,
    policies: Policies | None = None,
) -> None:
    """Serve until SIGINT/SIGTERM. With `inherited` (a listening socket from systemd) the
    socket path, its permissions and its lifetime belong to systemd and are left alone;
    otherwise the helper creates and removes the socket itself."""
    sem = asyncio.Semaphore(concurrency)
    policies = policies or Policies()

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            try:
                payload = json.loads(line) if line.strip() else None
            except ValueError:
                payload = None
            reply = (
                await _answer_while_connected(payload, sem, await policies.current(), reader)
                if payload is not None
                else {"error": "bad JSON"}
            )
            if reply is None:
                log.info("client went away, command cancelled")
                return
            writer.write(json.dumps(reply).encode() + b"\n")
            await writer.drain()
        except (TimeoutError, OSError) as e:
            log.warning("client error: %s", e)
        finally:
            writer.close()

    if inherited is not None:
        # Python 3.13+ would unlink the socket file when the server closes, leaving the
        # still-active .socket unit listening on a path that no longer exists.
        if sys.version_info >= (3, 13):
            server = await asyncio.start_unix_server(
                on_client, sock=inherited, limit=1 << 20, cleanup_socket=False
            )
        else:
            server = await asyncio.start_unix_server(on_client, sock=inherited, limit=1 << 20)
        log.info("listening on the socket passed by systemd")
    else:
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
    if inherited is None:
        with contextlib.suppress(OSError):
            socket_path.unlink()
    log.info("stopped")


def _env_list(name: str) -> list[str]:
    """A comma- or space-separated environment variable as a list (a systemd drop-in with
    Environment= is the easy way to extend the packaged helper)."""
    return [x for x in re.split(r"[,\s]+", os.environ.get(name, "")) if x]


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="lanwatch-helper", description=__doc__.split("\n", 2)[0])
    p.add_argument(
        "--socket",
        type=Path,
        default=Path("/run/lanwatch/helper.sock"),
        help="socket to create; ignored when systemd passes one (socket activation)",
    )
    p.add_argument(
        "--group",
        default=None,
        help="group owner of the socket (e.g. lanwatch); ignored under socket activation",
    )
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--log-level", default="info")
    p.add_argument(
        "--allow-script",
        action="append",
        default=_env_list("LANWATCH_HELPER_ALLOW_SCRIPTS"),
        metavar="NAME",
        help="also allow this nmap script (repeatable; or LANWATCH_HELPER_ALLOW_SCRIPTS=a,b)."
        " Needed for scripts added to scan.scripts in the lanwatch config",
    )
    p.add_argument(
        "--allow-net",
        action="append",
        default=_env_list("LANWATCH_HELPER_ALLOW_NETS"),
        metavar="CIDR",
        help="also allow targets in this network (repeatable; or LANWATCH_HELPER_ALLOW_NETS)."
        " Needed for routed subnets listed in network.subnets",
    )
    a = p.parse_args(argv)
    setup_logging(a.log_level)
    bad = [n for n in a.allow_script if not re.fullmatch(r"[a-z0-9-]+", n)]
    if bad:
        p.error(f"not an nmap script name: {', '.join(bad)}")
    try:
        nets = [ipaddress.ip_network(n, strict=False) for n in a.allow_net]
    except ValueError as e:
        p.error(f"--allow-net: {e}")
    policies = Policies(a.allow_script, nets)
    if not privileged():
        log.warning("neither root nor CAP_NET_RAW: raw-socket scans will be unavailable")
    fd = systemd_socket_fd(os.environ, os.getpid())
    inherited = socket.socket(fileno=fd) if fd is not None else None
    # The variables are addressed to this process only; keep them away from nmap and friends.
    for var in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(var, None)
    asyncio.run(_serve(a.socket, a.group, a.concurrency, inherited, policies))


if __name__ == "__main__":
    main()
