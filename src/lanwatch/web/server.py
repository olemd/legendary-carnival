"""uvicorn embedding. The scheduler owns signal handling, so uvicorn must not."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Iterator

import uvicorn
from fastapi import FastAPI

log = logging.getLogger(__name__)


class _QuietServer(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def make_server(app: FastAPI, host: str, port: int) -> uvicorn.Server:
    cfg = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    return _QuietServer(cfg)


async def serve_until(server: uvicorn.Server, stop: asyncio.Event) -> None:
    """Run the server until `stop` is set, then shut it down."""
    task = asyncio.create_task(server.serve())
    await stop.wait()
    server.should_exit = True
    await task
