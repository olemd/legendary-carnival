from __future__ import annotations

import asyncio
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
from lanwatch.helper import _serve, handle_request, systemd_socket_fd, validate_argv


def test_validate_allows_what_lanwatch_generates() -> None:
    cfg = ScanConfig()
    assert validate_argv(build_nmap_args(["10.0.0.1", "10.0.0.2"], cfg, deep=False)) is None
    assert (
        validate_argv(build_nmap_args(["10.0.0.0/24"], ScanConfig(profile="thorough"), True))
        is None
    )
    assert validate_argv(build_nmap_udp_args(["10.0.0.1"], cfg)) is None
    assert (
        validate_argv(["nmap", "-sn", "-oX", "-", "-T2", "--max-rate=100", "192.168.1.0/24"])
        is None
    )
    assert (
        validate_argv(
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
    assert validate_argv(["ip", "-j", "neigh", "show"]) is None
    assert validate_argv(["ping", "-c", "1", "-W", "1", "10.0.0.1"]) is None
    assert validate_argv(["ping", "-6", "-c", "1", "-W", "1", "ff02::1%eth0"]) is None
    assert validate_argv(["ip", "-j", "-6", "neigh", "show"]) is None
    assert validate_argv(["ip", "-j", "route", "show"]) is None
    assert (
        validate_argv(["nmap", "-oX", "-", "-e", "eth0", "--script=broadcast-dhcp-discover"])
        is None
    )
    assert (
        validate_argv(["nmap", "-6", "-oX", "-", "-n", "-Pn", "--top-ports=100", "2001:db8::1"])
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
    assert validate_argv(argv) is not None


async def test_handle_request_ops() -> None:
    sem = asyncio.Semaphore(1)
    assert "error" in await handle_request("nope", sem)
    assert "error" in await handle_request({"op": "run", "argv": ["bash"]}, sem)
    assert "error" in await handle_request({"op": "which", "binary": "bash"}, sem)
    r = await handle_request({"op": "which", "binary": "nmap"}, sem)
    assert set(r) == {"available", "root"}
    # A missing allowed binary is reported through rc, not as a refusal.
    r = await handle_request(
        {"op": "run", "argv": ["arp-scan", "--plain", "10.0.0.0/24"], "timeout": 5}, sem
    )
    assert "rc" in r


async def test_helper_executor_roundtrip(tmp_path: Path) -> None:
    sock = tmp_path / "h.sock"
    sem = asyncio.Semaphore(1)

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        payload = json.loads(await reader.readline())
        writer.write(json.dumps(await handle_request(payload, sem)).encode() + b"\n")
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
    r = await handle_request({"op": "which", "binary": "nmap"}, asyncio.Semaphore(1))
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
    serving = asyncio.create_task(_serve(path, None, 1, listening))

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
