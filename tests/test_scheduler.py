from __future__ import annotations

import asyncio

from lanwatch.scheduler import Job, Scheduler


async def test_scheduler_runs_jobs_and_backs_off() -> None:
    calls: list[str] = []

    async def ok() -> None:
        calls.append("ok")

    async def bad() -> None:
        calls.append("bad")
        raise RuntimeError("boom")

    jobs = [Job("ok", 1000, ok), Job("bad", 1000, bad)]
    s = Scheduler(jobs)

    async def stopper() -> None:
        await asyncio.sleep(0.2)
        s.stop()

    await asyncio.gather(s.run_forever(), stopper())
    assert calls == ["ok", "bad"]
    assert jobs[1].failures == 1
    assert jobs[1].next_due > jobs[0].next_due  # failed job backed off further


def test_resume_from_last_run() -> None:
    import time

    async def noop() -> None:
        pass

    j = Job("x", 3600, noop)
    j.resume_from(time.time() - 600)
    assert 2900 < j.next_due - time.monotonic() <= 3000
    j.resume_from(time.time() - 7200)
    assert j.next_due <= time.monotonic()
