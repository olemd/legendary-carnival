"""Minimal asyncio scheduler: jobs with fixed intervals, grouped in lanes. Each lane runs one
job at a time and the lanes run side by side, so an hour-long service scan in the "scan"
lane does not hold up the five-minute discovery round in the "main" lane. Stopping cancels
the jobs in progress, a job can be requested to run now, and each job remembers how its
last run went so the web UI can show it."""

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
    # Jobs in one lane run one at a time; different lanes run concurrently.
    lane: str = "main"
    # Name of a job that must have completed once in this process before this one may
    # start (a service scan needs the device list a discovery round produces).
    after: str | None = None
    # Observable state, wall-clock seconds. Read by the web UI from another thread, which is
    # fine for plain attribute reads.
    running_since: float | None = None
    last_finished: float | None = None
    last_duration_s: float | None = None
    last_error: str | None = None

    @classmethod
    def daily(
        cls, name: str, hhmm: str, run: Callable[[], Awaitable[object]], lane: str = "main"
    ) -> Job:
        j = cls(name, 86400, run, daily_at=hhmm, lane=lane)
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
        # Per lane: set by trigger() or a finished job to cut the idle wait short.
        self._wake: dict[str, asyncio.Event] = {j.lane: asyncio.Event() for j in jobs}
        self._locks: dict[str, asyncio.Lock] = {lane: asyncio.Lock() for lane in self._wake}
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def stopped(self) -> asyncio.Event:
        return self._stop

    @property
    def lanes(self) -> list[str]:
        return list(self._wake)

    def stop(self) -> None:
        self._stop.set()

    def job(self, name: str) -> Job | None:
        return next((j for j in self.jobs if j.name == name), None)

    @property
    def running_jobs(self) -> list[Job]:
        """Jobs in progress, the longest-running first."""
        busy = [j for j in self.jobs if j.running_since is not None]
        return sorted(busy, key=lambda j: j.running_since or 0.0)

    @property
    def running(self) -> Job | None:
        """The longest-running job in progress, if any."""
        busy = self.running_jobs
        return busy[0] if busy else None

    def _wake_all(self) -> None:
        for e in self._wake.values():
            e.set()

    def trigger(self, name: str) -> bool:
        """Make a job due now. Safe to call from any thread; False for an unknown job.
        If another job in the same lane is running, this one starts as soon as that
        finishes."""
        job = self.job(name)
        if job is None:
            return False
        job.next_due = time.monotonic()
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._wake[job.lane].set)
        return True

    def install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.stop)

    def _ready(self, job: Job) -> bool:
        """Has the job this one waits for (Job.after) completed at least once?"""
        if job.after is None:
            return True
        dep = self.job(job.after)
        return dep is None or dep.last_finished is not None

    async def run_job(self, job: Job) -> None:
        async with self._locks[job.lane]:
            started = time.monotonic()
            job.running_since = time.time()
            try:
                await job.run()
                job.failures = 0
                job.last_error = None
                log.debug("job %s took %.1fs", job.name, time.monotonic() - started)
            except asyncio.CancelledError:
                # Shutdown. Not a failure and not a completed run: leave the job due, so it
                # starts over the next time the scheduler runs.
                log.info("job %s cancelled after %.0fs", job.name, time.monotonic() - started)
                job.running_since = None
                raise
            except Exception as e:
                job.failures += 1
                job.last_error = f"{type(e).__name__}: {e}"[:300]
                log.exception("job %s failed (%d in a row)", job.name, job.failures)
            job.running_since = None
            job.last_finished = time.time()
            job.last_duration_s = time.monotonic() - started
            job.schedule_next()
        # A job in another lane may have been waiting for this one (Job.after).
        self._wake_all()

    async def _run_until_stopped(self, job: Job) -> None:
        """Run a job, but give up on it the moment stop() is called. A scan can take many
        minutes; a service that is asked to stop should not make everyone wait for it."""
        task = asyncio.create_task(self.run_job(job))
        stopped = asyncio.create_task(self._stop.wait())
        try:
            await asyncio.wait({task, stopped}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            # Also reached when the scheduler itself is cancelled: never leave the job behind.
            stopped.cancel()
            if not task.done():
                task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _run_lane(self, lane: str) -> None:
        jobs = [j for j in self.jobs if j.lane == lane]
        wake = self._wake[lane]
        while not self._stop.is_set():
            now = time.monotonic()
            due = [j for j in jobs if j.next_due <= now and self._ready(j)]
            for job in due:
                if self._stop.is_set():
                    break
                await self._run_until_stopped(job)
            if self._stop.is_set():
                break
            wake.clear()
            waiting = [j.next_due for j in jobs if self._ready(j)]
            if waiting:
                wait: float | None = max(0.0, min(waiting) - time.monotonic())
                if wait == 0.0:
                    continue  # something was triggered while the last job ran
            else:
                wait = None  # every job waits for another lane; that lane wakes this one
            sleepers = [asyncio.create_task(e.wait()) for e in (self._stop, wake)]
            await asyncio.wait(sleepers, timeout=wait, return_when=asyncio.FIRST_COMPLETED)
            for t in sleepers:
                t.cancel()

    async def run_forever(self) -> None:
        log.info(
            "scheduler: %s",
            "; ".join(
                f"{lane}: "
                + ", ".join(
                    f"{j.name} daily at {j.daily_at}"
                    if j.daily_at
                    else f"{j.name} every {int(j.interval_s)}s"
                    for j in self.jobs
                    if j.lane == lane
                )
                for lane in self.lanes
            ),
        )
        self._loop = asyncio.get_running_loop()
        lanes = [asyncio.create_task(self._run_lane(lane)) for lane in self.lanes]
        try:
            await asyncio.gather(*lanes)
        finally:
            for t in lanes:
                t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(*lanes, return_exceptions=True)
        log.info("scheduler stopped")
