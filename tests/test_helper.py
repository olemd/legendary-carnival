from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import signal
import socket
from pathlib import Path

import pytest

from lanwatch import helper
from lanwatch.collectors import base
from lanwatch.collectors.base import (
    CommandError,
    HelperExecutor,
    LocalExecutor,
    ambient_net_raw,
    privileged,
    run_cmd,
)
from lanwatch.collectors.services import build_nmap_args, build_nmap_udp_args
from lanwatch.config import ScanConfig
from lanwatch.helper import (
    Policies,
    Policy,
    _serve,
    handle_request,
    parse_attached,
    systemd_socket_fd,
    validate_argv,
)
from tests.conftest import HELPER_POLICY, fixture_text, helper_refusal


def test_validate_allows_what_lanwatch_generates() -> None:
    cfg = ScanConfig()
    assert helper_refusal(build_nmap_args(["10.0.0.1", "10.0.0.2"], cfg, deep=False)) is None
    assert (
        helper_refusal(build_nmap_args(["10.0.0.0/24"], ScanConfig(profile="thorough"), True))
        is None
    )
    assert helper_refusal(build_nmap_udp_args(["10.0.0.1"], cfg)) is None
    assert (
        helper_refusal(["nmap", "-sn", "-oX", "-", "-T2", "--max-rate=100", "192.168.1.0/24"])
        is None
    )
    assert (
        helper_refusal(
            [
                "arp-scan",
                "--plain",
                "--retry=2",
                "--interval=10",
                "--interface=eth0",
                "192.168.1.0/24",
            ]
        )
        is None
    )
    assert helper_refusal(["ip", "-j", "neigh", "show"]) is None
    assert helper_refusal(["ping", "-c", "1", "-W", "1", "10.0.0.1"]) is None
    assert helper_refusal(["ping", "-6", "-c", "1", "-W", "1", "ff02::1%eth0"]) is None
    assert helper_refusal(["ip", "-j", "-6", "neigh", "show"]) is None
    assert helper_refusal(["ip", "-j", "route", "show"]) is None
    assert (
        helper_refusal(["nmap", "-oX", "-", "-e", "eth0", "--script=broadcast-dhcp-discover"])
        is None
    )
    assert (
        helper_refusal(["nmap", "-6", "-oX", "-", "-n", "-Pn", "--top-ports=100", "2001:db8::1"])
        is None
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["bash", "-c", "id"],
        ["nmap", "-iL", "/etc/passwd"],
        ["nmap", "--script=../../evil"],
        ["nmap", "--script-args=x=1", "10.0.0.1"],
        ["nmap", "-oN", "/tmp/x", "10.0.0.1"],
        ["nmap", "10.0.0.1; id"],
        ["nmap", "example.com"],
        ["arp-scan", "--file=/etc/hosts"],
        ["ip", "link", "set", "eth0", "down"],
        ["ping", "-f", "10.0.0.1"],
        ["ping", "-c", "1", "ff02::1%eth0; id"],
        ["nmap", "-e"],
        ["nmap", "-e", "../etc"],
        ["nmap", "--host-timeout", "forever", "10.0.0.1"],
        ["nmap", "eth0"],
        [],
    ],
)
def test_validate_rejects(argv: list[str]) -> None:
    assert helper_refusal(argv) is not None


async def test_handle_request_ops() -> None:
    sem = asyncio.Semaphore(1)
    assert "error" in await handle_request("nope", sem, HELPER_POLICY)
    assert "error" in await handle_request({"op": "run", "argv": ["bash"]}, sem, HELPER_POLICY)
    assert "error" in await handle_request({"op": "which", "binary": "bash"}, sem, HELPER_POLICY)
    r = await handle_request({"op": "which", "binary": "nmap"}, sem, HELPER_POLICY)
    assert set(r) == {"available", "root"}
    # A missing allowed binary is reported through rc, not as a refusal.
    r = await handle_request(
        {"op": "run", "argv": ["arp-scan", "--plain", "10.0.0.0/24"], "timeout": 5},
        sem,
        HELPER_POLICY,
    )
    assert "rc" in r


async def test_helper_executor_roundtrip(tmp_path: Path) -> None:
    sock = tmp_path / "h.sock"
    sem = asyncio.Semaphore(1)

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        payload = json.loads(await reader.readline())
        writer.write(json.dumps(await handle_request(payload, sem, HELPER_POLICY)).encode() + b"\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(on_client, path=str(sock))
    async with server:
        ex = HelperExecutor(sock)
        present, root = await ex.which("ping")
        assert isinstance(present, bool) and isinstance(root, bool)
        with pytest.raises(CommandError, match="refused"):
            await ex.run(["bash", "-c", "id"], timeout=5)
        rc, _, _ = await ex.run(["ip", "-j", "addr", "show"], timeout=5)
        assert rc in (0, -2)  # depends on iproute2 being installed here
    with pytest.raises(CommandError, match="helper socket"):
        await HelperExecutor(tmp_path / "missing.sock").which("nmap")


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("Name:\tpython\nCapAmb:\t0000000000002000\n", True),  # CAP_NET_RAW (bit 13)
        ("CapAmb:\t0000000000003000\n", True),  # NET_ADMIN + NET_RAW
        ("CapAmb:\t0000000000001000\n", False),  # NET_ADMIN only
        # Effective alone does not count: it would not survive exec into nmap.
        ("CapEff:\t000001ffffffffff\nCapAmb:\t0000000000000000\n", False),
        ("CapAmb:\tnot-hex\n", False),
        ("", False),
    ],
)
def test_ambient_net_raw(status: str, expected: bool) -> None:
    assert ambient_net_raw(status) is expected


def test_privileged_is_root_or_ambient_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "ambient_net_raw", lambda _text: False)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert privileged() is True
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert privileged() is False
    monkeypatch.setattr(base, "ambient_net_raw", lambda _text: True)
    assert privileged() is True


def _fake_binary(directory: Path, name: str) -> None:
    """A stand-in that prints whether it was told it may use raw sockets."""
    script = directory / name
    script.write_text('#!/bin/sh\nprintf %s "${NMAP_PRIVILEGED:-unset}"\n')
    script.chmod(0o755)


async def test_run_cmd_tells_only_unprivileged_uid_nmap_about_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_binary(tmp_path, "nmap")
    _fake_binary(tmp_path, "arp-scan")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("NMAP_PRIVILEGED", raising=False)

    # Non-root with the capability: nmap needs the hint, other binaries are left alone.
    monkeypatch.setattr(base, "privileged", lambda: True)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert (await run_cmd(["nmap"], 5))[1] == "1"
    assert (await run_cmd(["arp-scan"], 5))[1] == "unset"

    # Root: nmap works out raw mode from the uid by itself.
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert (await run_cmd(["nmap"], 5))[1] == "unset"

    # No privilege at all: never claim it.
    monkeypatch.setattr(base, "privileged", lambda: False)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert (await run_cmd(["nmap"], 5))[1] == "unset"


@pytest.mark.parametrize("value", [True, False])
async def test_which_reports_raw_socket_privilege(
    value: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(base, "privileged", lambda: value)
    monkeypatch.setattr(helper, "privileged", lambda: value)
    assert (await LocalExecutor().which("nmap"))[1] is value
    r = await handle_request({"op": "which", "binary": "nmap"}, asyncio.Semaphore(1), HELPER_POLICY)
    assert r["root"] is value


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({"LISTEN_PID": "42", "LISTEN_FDS": "1"}, 3),
        ({"LISTEN_PID": "41", "LISTEN_FDS": "1"}, None),  # meant for another process
        ({"LISTEN_PID": "42", "LISTEN_FDS": "2"}, None),  # we expect exactly one socket
        ({"LISTEN_PID": "42"}, None),
        ({}, None),
    ],
)
def test_systemd_socket_fd(environ: dict[str, str], expected: int | None) -> None:
    assert systemd_socket_fd(environ, 42) == expected


async def _stop_serving(task: asyncio.Task[None]) -> None:
    os.kill(os.getpid(), signal.SIGTERM)  # _serve handles it and returns
    await asyncio.wait_for(task, timeout=5)


async def test_serve_on_socket_passed_by_systemd(tmp_path: Path) -> None:
    path = tmp_path / "h.sock"
    listening = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listening.bind(str(path))
    listening.listen()
    task = asyncio.create_task(_serve(tmp_path / "unused.sock", None, 1, listening))
    present, _ = await HelperExecutor(path).which("ping")
    assert isinstance(present, bool)
    await _stop_serving(task)
    # systemd owns the socket: the helper must neither replace nor remove it.
    assert path.exists()
    assert not (tmp_path / "unused.sock").exists()


async def test_serve_creates_and_removes_its_own_socket(tmp_path: Path) -> None:
    path = tmp_path / "run" / "h.sock"
    task = asyncio.create_task(_serve(path, None, 1))
    for _ in range(200):
        if path.exists():
            break
        await asyncio.sleep(0.01)
    assert path.stat().st_mode & 0o777 == 0o660
    present, _ = await HelperExecutor(path).which("ping")
    assert isinstance(present, bool)
    await _stop_serving(task)
    assert not path.exists()


def _sleeper(directory: Path, name: str) -> Path:
    """A stand-in scanner that records its pid and then runs for a long time."""
    pidfile = directory / f"{name}.pid"
    script = directory / name
    script.write_text(f'#!/bin/sh\necho $$ > "{pidfile}"\nexec sleep 300\n')
    script.chmod(0o755)
    return pidfile


async def _wait_until_gone(pidfile: Path) -> bool:
    """True once the process whose pid is in pidfile has exited (or is a reaped zombie)."""
    for _ in range(300):
        if pidfile.exists() and pidfile.read_text().strip():
            stat = Path(f"/proc/{pidfile.read_text().strip()}/stat")
            try:
                if stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                    return True
            except FileNotFoundError:
                return True
        await asyncio.sleep(0.01)
    return False


async def _wait_for_pid(pidfile: Path) -> None:
    for _ in range(300):
        if pidfile.exists() and pidfile.read_text().strip():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the command never started")


async def test_run_cmd_kills_the_command_when_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pidfile = _sleeper(tmp_path, "nmap")
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    task = asyncio.create_task(run_cmd(["nmap"], 600))
    await _wait_for_pid(pidfile)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await _wait_until_gone(pidfile)


async def test_helper_cancels_the_command_when_its_client_disconnects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pidfile = _sleeper(tmp_path, "ping")
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    path = tmp_path / "h.sock"
    listening = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listening.bind(str(path))
    listening.listen()
    policies = Policies(nets=HELPER_POLICY.nets)  # the test target is not a real attached network
    serving = asyncio.create_task(_serve(path, None, 1, listening, policies))

    # What lanwatch.service does when it is stopped or killed mid-scan: the request is out,
    # no reply has come, and the connection closes.
    _, writer = await asyncio.open_unix_connection(str(path))
    request = {"op": "run", "argv": ["ping", "-c", "1", "-W", "1", "10.0.0.1"], "timeout": 600}
    writer.write(json.dumps(request).encode() + b"\n")
    await writer.drain()
    await _wait_for_pid(pidfile)
    writer.close()
    await writer.wait_closed()

    assert await _wait_until_gone(pidfile)
    # The one concurrency slot is free again: the next request is answered.
    present, _ = await HelperExecutor(path).which("ping")
    assert present is True
    await _stop_serving(serving)


def test_only_lanwatchs_own_nmap_scripts_run() -> None:
    reason = helper_refusal(
        ["nmap", "-oX", "-", "--script=ssl-cert,http-vuln-cve2017-5638", "10.0.0.1"]
    )
    assert reason is not None and "http-vuln-cve2017-5638" in reason
    assert "--allow-script http-vuln-cve2017-5638" in reason  # says how to allow it
    # nmap script categories are names too, and they are not on the list.
    for category in ("vuln", "exploit", "brute", "dos", "default", "all"):
        assert helper_refusal(["nmap", f"--script={category}", "10.0.0.1"]) is not None
    extended = Policy(HELPER_POLICY.scripts | {"http-headers"}, HELPER_POLICY.nets)
    assert validate_argv(["nmap", "--script=ssl-cert,http-headers", "10.0.0.1"], extended) is None


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",  # the internet
        "192.168.2.0/24",  # a neighbouring network this host is not on
        "192.168.0.0/16",  # wider than the attached /24, so it reaches beyond it
        "0.0.0.0/0",
        "2a00:1450::1",
        "::/0",
    ],
)
def test_targets_outside_attached_networks_are_refused(target: str) -> None:
    for argv in (
        ["nmap", "-sn", target],
        ["arp-scan", "--plain", target],
        ["ping", "-c", "1", target],
    ):
        reason = helper_refusal(argv)
        assert reason is not None and "outside the networks" in reason, argv
    # ...unless the administrator allowed that network on the helper.
    wider = Policy(
        HELPER_POLICY.scripts, (*HELPER_POLICY.nets, ipaddress.ip_network(target, False))
    )
    assert validate_argv(["nmap", "-sn", target], wider) is None


def test_no_known_networks_means_no_targets() -> None:
    # `ip` unavailable or unparsable: refuse rather than fall back to "anything goes".
    assert validate_argv(["nmap", "-sn", "10.0.0.1"], Policy(HELPER_POLICY.scripts, ())) is not None
    assert parse_attached("garbage") == () and parse_attached([{"addr_info": [{}]}]) == ()


def test_attached_networks_come_from_every_address() -> None:
    nets = {str(n) for n in parse_attached(json.loads(fixture_text("ip-addr.json")))}
    assert {"192.168.1.0/24", "10.8.0.0/24", "127.0.0.0/8"} <= nets
    v6 = parse_attached(
        [{"addr_info": [{"family": "inet6", "local": "2001:db8::5", "prefixlen": 64}]}]
    )
    assert [str(n) for n in v6] == ["2001:db8::/64"]


async def test_policies_refresh_attached_networks(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = [(ipaddress.ip_network("10.0.0.0/24"),), (ipaddress.ip_network("10.1.0.0/24"),)]

    async def fake_attached() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return seen.pop(0)

    monkeypatch.setattr(helper, "attached_networks", fake_attached)
    extra = ipaddress.ip_network("172.16.5.0/24")
    policies = Policies(scripts=["http-headers"], nets=[extra], ttl=0)
    first = await policies.current()
    assert "http-headers" in first.scripts and "ssl-cert" in first.scripts
    assert [str(n) for n in first.nets] == ["10.0.0.0/24", "172.16.5.0/24"]
    assert [str(n) for n in (await policies.current()).nets] == ["10.1.0.0/24", "172.16.5.0/24"]


async def test_heartbeat_reports_start_progress_and_end_only_when_verbose(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from lanwatch import logging_setup
    from lanwatch.logging_setup import with_heartbeat

    monkeypatch.setattr(logging_setup, "HEARTBEAT_S", 0.02)
    log = logging.getLogger("lanwatch.test-heartbeat")

    async def slow_scan() -> str:
        await asyncio.sleep(0.07)
        return "done"

    # Normal mode: just the result, nothing logged.
    with caplog.at_level(logging.INFO, logger=log.name):
        assert await with_heartbeat(slow_scan(), "nmap 10.0.0.1", log) == "done"
    assert caplog.records == []

    with caplog.at_level(logging.DEBUG, logger=log.name):
        assert await with_heartbeat(slow_scan(), "nmap 10.0.0.1", log) == "done"
    messages = [r.getMessage() for r in caplog.records]
    assert messages[0] == "started: nmap 10.0.0.1"
    assert any(m.startswith("still running after") for m in messages[1:-1])
    assert messages[-1].startswith("finished in") and messages[-1].endswith("nmap 10.0.0.1")

    # Cancelling the wait cancels the work too (this is how a stopped scan dies).
    cancelled = asyncio.Event()

    async def scan_for_ages() -> None:
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    with caplog.at_level(logging.DEBUG, logger=log.name):
        waiting = asyncio.create_task(with_heartbeat(scan_for_ages(), "nmap", log))
        await asyncio.sleep(0.03)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
    await asyncio.wait_for(cancelled.wait(), timeout=1)


async def test_verbose_shows_the_command_a_local_executor_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    _fake_binary(tmp_path, "nmap")
    monkeypatch.setenv("PATH", str(tmp_path))
    with caplog.at_level(logging.DEBUG, logger="lanwatch.collectors.base"):
        await LocalExecutor().run(["nmap", "-sn", "10.0.0.0/24"], 5)
    messages = [r.getMessage() for r in caplog.records]
    assert "started: nmap -sn 10.0.0.0/24" in messages
    assert any(m.startswith("finished in") for m in messages)
