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


def test_daily_job_scheduling() -> None:
    import time
    from datetime import datetime, timedelta

    from lanwatch.scheduler import seconds_until_daily

    now = datetime(2026, 11, 4, 6, 30).astimezone()
    assert seconds_until_daily("07:00", now) == 1800
    assert seconds_until_daily("06:30", now) == 86400
    assert seconds_until_daily("00:00", now) == (24 - 6.5) * 3600

    async def noop() -> None:
        pass

    j = Job.daily("digest", "07:00", noop)
    assert j.daily_at == "07:00" and 0 < j.next_due - time.monotonic() <= 86400
    # Ran 10 minutes ago: if today's slot already passed since then, run now; else wait.
    j.resume_from(time.time() - 600)
    slot_passed_recently = seconds_until_daily("07:00") > 86400 - 600
    assert (j.next_due <= time.monotonic() + 1) == slot_passed_recently
    j.resume_from(time.time() - 3 * 86400)
    assert j.next_due <= time.monotonic() + 1
    j.failures = 5
    j.schedule_next()
    assert j.next_due - time.monotonic() <= 86400  # no backoff multiplier for daily jobs
    _ = timedelta
