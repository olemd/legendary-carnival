"""Logging: 24h timestamps, text or JSON lines. Plus the verbose mode's sign of life."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from collections.abc import Awaitable
from datetime import datetime
from typing import Literal

# How often a long wait says it is still going, in verbose mode.
HEARTBEAT_S = 30.0


def set_verbose() -> None:
    """--verbose: debug output from lanwatch itself (commands run, results, progress), not
    from the libraries underneath."""
    logging.getLogger("lanwatch").setLevel(logging.DEBUG)


async def with_heartbeat[T](work: Awaitable[T], what: str, log: logging.Logger) -> T:
    """Await `work`; in verbose mode say what is being waited for, every HEARTBEAT_S
    seconds that it is still going, and how long it took. A service scan or an LLM answer
    can take minutes without printing anything, and this is what shows it has not hung.
    Outside verbose mode it only awaits."""
    if not log.isEnabledFor(logging.DEBUG):
        return await work
    started = time.monotonic()
    task = asyncio.ensure_future(work)
    log.debug("started: %s", what)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=HEARTBEAT_S)
            if done:
                break
            log.debug("still running after %.0f s: %s", time.monotonic() - started, what)
    finally:
        if not task.done():
            task.cancel()  # we were cancelled ourselves: do not leave the work behind
    log.debug("finished in %.1f s: %s", time.monotonic() - started, what)
    return task.result()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="seconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str = "info", fmt: Literal["text", "json"] = "text") -> None:
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
            )
        )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    logging.getLogger("lanwatch").setLevel(logging.NOTSET)  # undo an earlier set_verbose()
    logging.getLogger("httpx2").setLevel(logging.WARNING)
