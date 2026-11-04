"""Minimal asyncio scheduler: jobs with fixed intervals, one job at a time, clean shutdown."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


def seconds_until_daily(hhmm: str, now: datetime | None = None) -> float:
    """Seconds from now (local time) until the next occurrence of HH:MM."""
    now = now or datetime.now().astimezone()
    h, m = (int(x) for x in hhmm.split(":"))
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


@dataclass(slots=True)
class Job:
    name: str
    interval_s: float
    run: Callable[[], Awaitable[object]]
    next_due: float = field(default_factory=time.monotonic)
    failures: int = 0
    # Daily jobs run at a fixed local time instead of on an interval.
    daily_at: str | None = None

    @classmethod
    def daily(cls, name: str, hhmm: str, run: Callable[[], Awaitable[object]]) -> Job:
        j = cls(name, 86400, run, daily_at=hhmm)
        j.next_due = time.monotonic() + seconds_until_daily(hhmm)
        return j

    def resume_from(self, last_run_wall: float | None) -> None:
        """Keep cadence across restarts: due at last_run + interval, or now."""
        if self.daily_at is not None:
            # Missed today's slot since the last run -> run now, else wait for the slot.
            now = datetime.now().astimezone()
            h, m = (int(x) for x in self.daily_at.split(":"))
            slot = now.replace(hour=h, minute=m, second=0, microsecond=0)
            if slot > now:
                slot -= timedelta(days=1)
            missed = last_run_wall is None or last_run_wall < slot.timestamp()
            self.next_due = (
                time.monotonic()
                if missed
                else time.monotonic() + seconds_until_daily(self.daily_at)
            )
            return
        if last_run_wall is None:
            return
        remaining = (last_run_wall + self.interval_s) - time.time()
        self.next_due = time.monotonic() + max(0.0, remaining)

    def schedule_next(self) -> None:
        if self.daily_at is not None:
            self.next_due = time.monotonic() + seconds_until_daily(self.daily_at)
        else:
            # Back off on repeated failure, capped at 8x the interval.
            factor = min(2 ** min(self.failures, 3), 8)
            self.next_due = time.monotonic() + self.interval_s * factor


class Scheduler:
    def __init__(self, jobs: list[Job]) -> None:
        self.jobs = jobs
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()

    @property
    def stopped(self) -> asyncio.Event:
        return self._stop

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
                job.schedule_next()

    async def run_forever(self) -> None:
        log.info(
            "scheduler: %s",
            ", ".join(
                f"{j.name} daily at {j.daily_at}"
                if j.daily_at
                else f"{j.name} every {int(j.interval_s)}s"
                for j in self.jobs
            ),
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
