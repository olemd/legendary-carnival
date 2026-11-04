from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from lanwatch.collectors.base import CommandError, HelperExecutor
from lanwatch.collectors.services import build_nmap_args, build_nmap_udp_args
from lanwatch.config import ScanConfig
from lanwatch.helper import handle_request, validate_argv


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
