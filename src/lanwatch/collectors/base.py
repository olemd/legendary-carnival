"""Command execution for collectors. Either local subprocesses, or forwarded to the root
helper over a unix socket (for unprivileged containers). Every call has a timeout."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Protocol

from lanwatch import arpwatch
from lanwatch.logging_setup import with_heartbeat

log = logging.getLogger(__name__)

CmdResult = tuple[int, str, str]


def _shown(args: list[str], limit: int = 240) -> str:
    """A command line for the log, cut short when the target list is long."""
    text = " ".join(args)
    return text if len(text) <= limit else text[:limit] + f" … ({len(args)} arguments)"


class CommandError(RuntimeError):
    pass


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


# Bit number of CAP_NET_RAW in the kernel's capability masks (linux/capability.h).
_CAP_NET_RAW = 13


def ambient_net_raw(status_text: str) -> bool:
    """Whether CAP_NET_RAW is in the ambient set of a /proc/<pid>/status dump.

    Ambient, not effective: the scans run in child processes (nmap, arp-scan), and only the
    ambient set survives exec of a binary that has no file capabilities of its own."""
    for line in status_text.splitlines():
        if line.startswith("CapAmb:"):
            try:
                return bool((int(line.split(":", 1)[1], 16) >> _CAP_NET_RAW) & 1)
            except ValueError:
                return False
    return False


def privileged() -> bool:
    """Can child processes open raw sockets? True for root, and for a non-root process
    that was started with CAP_NET_RAW as an ambient capability (systemd
    AmbientCapabilities=), which is how the packaged helper runs."""
    if os.geteuid() == 0:
        return True
    try:
        return ambient_net_raw(Path("/proc/self/status").read_text())
    except OSError:
        return False


def _child_env(binary: str) -> dict[str, str] | None:
    """nmap decides on raw-socket mode by uid alone; NMAP_PRIVILEGED tells it to trust the
    capabilities instead. Root needs no hint, and other binaries get the plain environment."""
    if binary == "nmap" and os.geteuid() != 0 and privileged():
        return {**os.environ, "NMAP_PRIVILEGED": "1"}
    return None


async def run_cmd(args: list[str], timeout: float, stdin: bytes | None = None) -> CmdResult:
    """Run a command; returns (rc, stdout, stderr). rc -1 on timeout, -2 if missing."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_child_env(args[0]),
        )
    except FileNotFoundError:
        return -2, "", f"{args[0]}: not found"
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        log.warning("timeout after %.0fs: %s", timeout, " ".join(args[:3]))
        return -1, "", "timeout"
    except asyncio.CancelledError:
        # The caller gave up (shutdown, or the helper's client went away). A scan nobody is
        # waiting for must not keep running.
        proc.kill()
        raise
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def local_arp_report(window_s: float) -> dict[str, Any] | None:
    """Start this process's ARP listener if needed and allowed, and report from it."""
    if not privileged():
        return None
    watch = arpwatch.shared()
    return watch.report(window_s) if watch.start() else None


class Executor(Protocol):
    name: str

    async def run(self, args: list[str], timeout: float) -> CmdResult: ...

    async def which(self, binary: str) -> tuple[bool, bool]:
        """(binary available, runs with raw-socket privileges)."""
        ...


class LocalExecutor:
    name = "local"

    async def run(self, args: list[str], timeout: float) -> CmdResult:
        return await with_heartbeat(run_cmd(args, timeout), _shown(args), log)

    async def which(self, binary: str) -> tuple[bool, bool]:
        return have(binary), privileged()

    async def arp_report(self, window_s: float) -> dict[str, Any] | None:
        """What the passive ARP listener heard; None when this process may not listen."""
        return local_arp_report(window_s)


class HelperExecutor:
    """Forwards commands to `lanwatch-helper` (see lanwatch.helper) over a unix socket."""

    name = "helper"

    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    async def _request(self, payload: dict[str, object], timeout: float) -> dict[str, object]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self.socket_path)), timeout=5
            )
        except (OSError, TimeoutError) as e:
            raise CommandError(f"helper socket {self.socket_path}: {e}") from e
        try:
            writer.write(json.dumps(payload).encode() + b"\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=timeout + 10)
        finally:
            writer.close()
        if not line:
            raise CommandError("helper closed the connection without a reply")
        reply = json.loads(line)
        if not isinstance(reply, dict):
            raise CommandError("helper sent a malformed reply")
        if "error" in reply:
            raise CommandError(f"helper refused: {reply['error']}")
        return reply

    async def run(self, args: list[str], timeout: float) -> CmdResult:
        request = self._request({"op": "run", "argv": args, "timeout": timeout}, timeout)
        r = await with_heartbeat(request, f"(via helper) {_shown(args)}", log)
        return int(str(r.get("rc", -3))), str(r.get("stdout", "")), str(r.get("stderr", ""))

    async def which(self, binary: str) -> tuple[bool, bool]:
        r = await self._request({"op": "which", "binary": binary}, 5)
        return bool(r.get("available")), bool(r.get("root"))

    async def arp_report(self, window_s: float) -> dict[str, Any] | None:
        r = await self._request({"op": "arp-report", "window": window_s}, 5)
        report = r.get("report")
        return report if isinstance(report, dict) else None


def make_executor(helper_socket: Path | None) -> Executor:
    return HelperExecutor(helper_socket) if helper_socket else LocalExecutor()
