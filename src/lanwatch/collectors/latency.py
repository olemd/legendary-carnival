"""Round-trip time and packet loss to the gateway (and any other address you name).

A few pings per discovery round, stored as a time series. Not a security check: it is the
kind of problem you otherwise notice when the video call stutters, and the history says
whether it is the gateway or the internet, and since when. The target "gateway" stands for
this host's default gateways; anything else is pinged as written, so an internet address
only goes in when you put it in [latency] targets yourself.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass

from lanwatch.collectors.base import CommandError, Executor, LocalExecutor

log = logging.getLogger(__name__)

GATEWAY = "gateway"
_STATS = re.compile(r"(\d+) packets transmitted, (\d+) received")
_RTT = re.compile(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/([\d.]+)/")


@dataclass(slots=True, frozen=True)
class PingResult:
    target: str
    sent: int
    received: int
    avg_ms: float | None  # None when nothing came back
    max_ms: float | None

    @property
    def loss(self) -> float:
        """Fraction of probes lost, 0.0 to 1.0."""
        return 1.0 - self.received / self.sent if self.sent else 1.0


def parse_ping(target: str, text: str) -> PingResult | None:
    """iputils ping summary -> PingResult; None when the summary line is missing (ping
    itself failed, e.g. the name did not resolve)."""
    m = _STATS.search(text)
    if m is None:
        return None
    sent, received = int(m.group(1)), int(m.group(2))
    rtt = _RTT.search(text)
    avg = float(rtt.group(1)) if rtt else None
    mx = float(rtt.group(2)) if rtt else None
    return PingResult(target, sent, received, avg, mx)


def resolve_targets(configured: list[str], gateways: list[str]) -> list[str]:
    """Replace the word "gateway" with the default gateways, keep the rest, drop repeats."""
    out: list[str] = []
    for t in configured:
        for addr in gateways if t == GATEWAY else [t]:
            if addr not in out:
                out.append(addr)
    return out


async def measure(ex: Executor, targets: list[str], count: int) -> list[PingResult]:
    """Ping every target `count` times, concurrently. A target ping cannot reach at all
    still yields a result (all lost); a target ping cannot run against yields nothing.

    ping needs no privilege on a modern Linux (unprivileged ICMP sockets are open to every
    group by default), so it runs in this process first. Only when that is impossible (no
    ping binary here, or the sockets are closed) does it go through the privileged helper,
    which refuses targets outside the attached networks unless started with --allow-net.
    Nothing raised here reaches the discovery round: a measurement that cannot be made is
    logged and skipped."""
    local = ex if ex.name == "local" else LocalExecutor()
    args = ["ping", "-c", str(count), "-W", "1"]
    timeout = count * 2 + 5

    async def one(target: str) -> PingResult | None:
        try:
            rc, out, err = await local.run([*args, target], timeout=timeout)
            if rc != -2 and "not permitted" not in err:
                return _result(target, rc, out, err)
            if local is ex:
                log.debug("cannot ping %s from here (rc=%s): %s", target, rc, err.strip()[:120])
                return None
            rc, out, err = await ex.run([*args, target], timeout=timeout)
            return _result(target, rc, out, err)
        except CommandError as e:
            log.warning("latency: %s not measured: %s", target, e)
        except Exception:
            log.exception("latency: ping %s failed", target)
        return None

    results = await asyncio.gather(*(one(t) for t in targets))
    return [r for r in results if r is not None]


def _result(target: str, rc: int, out: str, err: str) -> PingResult | None:
    if rc == -2:
        log.debug("ping is not installed; latency not measured")
        return None
    result = parse_ping(target, out)
    if result is None:
        log.debug("ping %s gave no summary (rc=%s): %s", target, rc, err.strip()[:120])
    return result
