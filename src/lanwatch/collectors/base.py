"""Subprocess helpers shared by collectors. Every external call has a timeout."""

from __future__ import annotations

import asyncio
import logging
import shutil

log = logging.getLogger(__name__)


class CommandError(RuntimeError):
    pass


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


async def run_cmd(
    args: list[str], timeout: float, stdin: bytes | None = None
) -> tuple[int, str, str]:
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
