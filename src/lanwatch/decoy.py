"""Decoy ports: listeners on ports this machine does not otherwise use. Nothing on the
network has a reason to connect to them, so anything that does is looking around: a
scanner, a worm, a compromised gadget working through its list of default services.

A connection is closed at once, without reading a byte, and recorded as an event. The
rule ids.decoy-touched turns the events into findings.

Ports that cannot be bound are skipped, not fought over: one that is in use belongs to a
real service, and one below 1024 needs CAP_NET_BIND_SERVICE (the packaged unit grants it).
Note the reverse as well: a port held here cannot be used by a service installed later,
until it is taken out of [decoy] ports.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import json
import logging
import time
from collections.abc import Callable

from lanwatch.config import DecoyConfig
from lanwatch.netinfo import is_local_address
from lanwatch.store import Store

log = logging.getLogger(__name__)

# What the port usually means, for readable findings.
SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    445: "smb",
    1433: "mssql",
    2323: "telnet",
    3306: "mysql",
    3389: "rdp",
    5555: "adb",
    5900: "vnc",
    6379: "redis",
    7547: "tr-069",
}

# One event per source and port in this many seconds, however often it knocks.
REPEAT_S = 600.0


def port_label(port: int) -> str:
    name = SERVICE_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def _plain_ip(address: str) -> str:
    """The peer address without IPv4-in-IPv6 mapping or an IPv6 zone."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


class Decoys:
    def __init__(
        self,
        config: DecoyConfig,
        on_hit: Callable[[str, int], None],
        on_change: Callable[[list[int]], None] | None = None,
    ) -> None:
        self.config = config
        self.on_hit = on_hit
        # Called with the ports being listened on whenever that set changes.
        self.on_change = on_change
        self.listening: list[int] = []
        self.skipped: dict[int, str] = {}  # port -> why it is not a decoy
        self._servers: list[asyncio.Server] = []
        self._last: dict[tuple[str, int], float] = {}
        self._ignore = set(config.ignore)

    async def start(self) -> None:
        if not self.config.enabled:
            return
        for port in dict.fromkeys(self.config.ports):
            try:
                server = await asyncio.start_server(
                    lambda r, w, port=port: self._connected(w, port),  # type: ignore[misc]
                    host=None,
                    port=port,
                )
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    reason = "in use by another service"
                elif e.errno == errno.EACCES:
                    reason = "not permitted (ports below 1024 need CAP_NET_BIND_SERVICE)"
                else:
                    reason = e.strerror or str(e)
                self.skipped[port] = reason
                continue
            self._servers.append(server)
            self.listening.append(port)
        if self.listening:
            log.info("decoy ports: listening on %s", ", ".join(map(port_label, self.listening)))
        for port, reason in self.skipped.items():
            log.info("decoy port %s skipped: %s", port_label(port), reason)
        if self.on_change is not None:
            self.on_change(list(self.listening))

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()
        self._servers.clear()
        self.listening.clear()
        if self.on_change is not None:
            self.on_change([])

    async def serve_until(self, stopped: asyncio.Event) -> None:
        await self.start()
        try:
            await stopped.wait()
        finally:
            await self.stop()

    async def _connected(self, writer: asyncio.StreamWriter, port: int) -> None:
        peer = writer.get_extra_info("peername")
        local = writer.get_extra_info("sockname")
        writer.close()  # no banner, no reading: the connection itself is the whole signal
        try:
            source, own = _plain_ip(str(peer[0])), _plain_ip(str(local[0]))
        except (TypeError, ValueError, IndexError):
            return
        # This machine connecting to itself is lanwatch's own service scan. With several
        # addresses on one machine the two ends need not be the same address.
        if source == own or is_local_address(source) or source in self._ignore:
            return
        now = time.monotonic()
        if now - self._last.get((source, port), float("-inf")) < REPEAT_S:
            return
        self._last[(source, port)] = now
        try:
            self.on_hit(source, port)
        except Exception:
            log.exception("recording a decoy connection failed")


LISTENING_KEY = "decoy.listening"


def publish_listening(store: Store, ports: list[int]) -> None:
    """Tell the scans which ports on this machine are decoys right now. lanwatch scans the
    machine it runs on like any other, and would otherwise report its own decoys as an
    open telnet and a database, with findings to match."""
    store.meta_set(LISTENING_KEY, json.dumps(sorted(ports)))


def listening_ports(store: Store) -> set[int]:
    try:
        return {int(p) for p in json.loads(store.meta_get(LISTENING_KEY) or "[]")}
    except (ValueError, TypeError):
        return set()


def record_hit(store: Store, source: str, port: int) -> bool:
    """Store one decoy connection as an event. Returns False when the source is outside
    the networks lanwatch watches (the decoys listen on every interface, and one of them
    may face the internet, where being probed is the normal state of things)."""
    try:
        watched = [
            ipaddress.ip_network(n) for n in json.loads(store.meta_get("net.subnets") or "[]")
        ]
    except ValueError:
        watched = []
    ip = ipaddress.ip_address(source)
    if watched and not any(ip.version == n.version and ip in n for n in watched):
        log.debug("decoy port %s touched from %s, outside the watched networks", port, source)
        return False
    device = store.device_by_ip(source)
    who = f"{device.label} ({source})" if device is not None else source
    store.add_event(
        "decoy.touched",
        f"{who} connected to decoy port {port_label(port)}",
        device.id if device is not None else None,
        data={"ip": source, "port": port},
    )
    log.warning("decoy port %s touched by %s", port_label(port), who)
    return True
