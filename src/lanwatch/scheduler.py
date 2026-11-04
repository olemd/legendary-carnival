"""Minimal asyncio scheduler: jobs with fixed intervals, one job at a time, clean shutdown."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Job:
    name: str
    interval_s: float
    run: Callable[[], Awaitable[object]]
    next_due: float = field(default_factory=time.monotonic)
    failures: int = 0


class Scheduler:
    def __init__(self, jobs: list[Job]) -> None:
        self.jobs = jobs
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()

    def stop(self) -> None:
        self._stop.set()

    def install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.stop)

    async def run_job(self, job: Job) -> None:
        async with self._lock:
            started = time.monotonic()
            try:
                await job.run()
                job.failures = 0
                log.debug("job %s took %.1fs", job.name, time.monotonic() - started)
            except Exception:
                job.failures += 1
                log.exception("job %s failed (%d in a row)", job.name, job.failures)
            finally:
                # Back off on repeated failure, capped at 8x the interval.
                factor = min(2 ** min(job.failures, 3), 8)
                job.next_due = time.monotonic() + job.interval_s * factor

    async def run_forever(self) -> None:
        log.info(
            "scheduler: %s", ", ".join(f"{j.name} every {int(j.interval_s)}s" for j in self.jobs)
        )
        while not self._stop.is_set():
            now = time.monotonic()
            due = [j for j in self.jobs if j.next_due <= now]
            for job in due:
                if self._stop.is_set():
                    break
                await self.run_job(job)
            if self._stop.is_set():
                break
            wait = max(0.5, min(j.next_due for j in self.jobs) - time.monotonic())
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=wait)
        log.info("scheduler stopped")
