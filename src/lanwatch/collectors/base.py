"""Command execution for collectors. Either local subprocesses, or forwarded to the root
helper over a unix socket (for unprivileged containers). Every call has a timeout."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Protocol

log = logging.getLogger(__name__)

CmdResult = tuple[int, str, str]


class CommandError(RuntimeError):
    pass


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


async def run_cmd(args: list[str], timeout: float, stdin: bytes | None = None) -> CmdResult:
    """Run a command; returns (rc, stdout, stderr). rc -1 on timeout, -2 if missing."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


class Executor(Protocol):
    name: str

    async def run(self, args: list[str], timeout: float) -> CmdResult: ...

    async def which(self, binary: str) -> tuple[bool, bool]:
        """(binary available, runs with root privileges)."""
        ...


class LocalExecutor:
    name = "local"

    async def run(self, args: list[str], timeout: float) -> CmdResult:
        return await run_cmd(args, timeout)

    async def which(self, binary: str) -> tuple[bool, bool]:
        return have(binary), os.geteuid() == 0


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
        r = await self._request({"op": "run", "argv": args, "timeout": timeout}, timeout)
        return int(str(r.get("rc", -3))), str(r.get("stdout", "")), str(r.get("stderr", ""))

    async def which(self, binary: str) -> tuple[bool, bool]:
        r = await self._request({"op": "which", "binary": binary}, 5)
        return bool(r.get("available")), bool(r.get("root"))


def make_executor(helper_socket: Path | None) -> Executor:
    return HelperExecutor(helper_socket) if helper_socket else LocalExecutor()
