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
