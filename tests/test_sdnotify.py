"""sd_notify readiness for Type=notify units (lanwatch/sdnotify.py)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from lanwatch.sdnotify import notify_ready


def test_ready_is_sent_to_the_notify_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "notify"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.bind(str(path))
        sock.settimeout(2)
        monkeypatch.setenv("NOTIFY_SOCKET", str(path))
        notify_ready()
        assert sock.recv(64) == b"READY=1"


def test_outside_systemd_nothing_happens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    notify_ready()  # no socket, no error


def test_a_dead_socket_is_only_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "gone"))
    notify_ready()
    assert "could not tell systemd" in caplog.text
