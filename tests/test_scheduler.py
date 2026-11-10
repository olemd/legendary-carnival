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


async def test_stop_cancels_the_running_job_and_leaves_it_due() -> None:
    import time

    started = asyncio.Event()

    async def scan_for_ages() -> None:
        started.set()
        await asyncio.sleep(3600)

    job = Job("inventory", 1000, scan_for_ages)
    s = Scheduler([job])
    runner = asyncio.create_task(s.run_forever())
    await asyncio.wait_for(started.wait(), timeout=2)
    assert s.running is job and job.running_since is not None
    s.stop()
    await asyncio.wait_for(runner, timeout=2)  # returns at once, not after the scan
    assert s.running is None
    assert job.last_finished is None and job.failures == 0  # neither completed nor failed
    assert job.next_due <= time.monotonic()  # so it starts over next time


async def test_trigger_runs_an_idle_job_now_and_records_the_outcome() -> None:
    runs: list[str] = []

    async def infra() -> None:
        runs.append("infra")
        if len(runs) == 2:
            raise RuntimeError("helper socket gone")

    job = Job("infra", 3600, infra)
    s = Scheduler([job])
    runner = asyncio.create_task(s.run_forever())
    await asyncio.sleep(0.05)
    assert runs == ["infra"] and job.last_error is None and job.last_finished is not None
    assert job.last_duration_s is not None

    assert s.trigger("no-such-job") is False
    assert s.trigger("infra") is True  # an hour early
    await asyncio.sleep(0.05)
    assert runs == ["infra", "infra"]
    assert job.last_error == "RuntimeError: helper socket gone"

    s.stop()
    await asyncio.wait_for(runner, timeout=2)


async def test_lanes_run_side_by_side() -> None:
    """An hour-long service scan in the scan lane must not hold up discovery and infra:
    on a fresh install the first infra round otherwise waited for inventory and deep."""
    scan_started = asyncio.Event()
    runs: list[str] = []

    async def inventory() -> None:
        scan_started.set()
        await asyncio.sleep(3600)

    async def quick(name: str) -> None:
        await scan_started.wait()  # only finishes because the scan lane is busy in parallel
        runs.append(name)

    jobs = [
        Job("inventory", 3600, inventory, lane="scan"),
        Job("discovery", 300, lambda: quick("discovery")),
        Job("infra", 900, lambda: quick("infra")),
    ]
    s = Scheduler(jobs)
    runner = asyncio.create_task(s.run_forever())
    for _ in range(100):
        if runs == ["discovery", "infra"]:
            break
        await asyncio.sleep(0.01)
    assert runs == ["discovery", "infra"]  # in list order within their lane
    assert s.running is jobs[0] and s.running_jobs == [jobs[0]]
    s.stop()
    await asyncio.wait_for(runner, timeout=2)
    assert s.running_jobs == []


async def test_a_job_waits_for_the_job_it_needs() -> None:
    """Service scans need a discovery round's device list: `after` holds them back until
    discovery completed once in this process, then wakes their lane at once."""
    order: list[str] = []
    discovery_may_finish = asyncio.Event()

    async def discovery() -> None:
        await discovery_may_finish.wait()
        order.append("discovery")

    async def inventory() -> None:
        order.append("inventory")

    jobs = [
        Job("inventory", 3600, inventory, lane="scan", after="discovery"),
        Job("discovery", 300, discovery),
    ]
    s = Scheduler(jobs)
    runner = asyncio.create_task(s.run_forever())
    await asyncio.sleep(0.05)
    assert order == []  # inventory is due but must not start before discovery finished
    discovery_may_finish.set()
    for _ in range(100):
        if len(order) == 2:
            break
        await asyncio.sleep(0.01)
    assert order == ["discovery", "inventory"]
    s.stop()
    await asyncio.wait_for(runner, timeout=2)


async def test_trigger_queues_only_behind_the_same_lane() -> None:
    import time

    started = asyncio.Event()
    runs: list[str] = []

    async def scan() -> None:
        started.set()
        await asyncio.sleep(3600)

    async def infra() -> None:
        runs.append("infra")

    jobs = [Job("deep", 3600, scan, lane="scan"), Job("infra", 900, infra)]
    s = Scheduler(jobs)
    runner = asyncio.create_task(s.run_forever())
    await asyncio.wait_for(started.wait(), timeout=2)
    await asyncio.sleep(0.02)
    assert runs == ["infra"]
    jobs[1].next_due = time.monotonic() + 1000
    assert s.trigger("infra")
    await asyncio.sleep(0.05)
    assert runs == ["infra", "infra"]  # ran although deep is still busy
    s.stop()
    await asyncio.wait_for(runner, timeout=2)
