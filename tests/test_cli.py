from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from lanwatch.cli import app

runner = CliRunner()


def test_config_show_and_devices_empty(tmp_path: Path, monkeypatch: object) -> None:
    import pytest

    assert isinstance(monkeypatch, pytest.MonkeyPatch)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("LANWATCH_CONFIG", raising=False)
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "config", "show"])
    assert r.exit_code == 0, r.output
    assert "[scan]" in r.output and 'profile = "gentle"' in r.output
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "devices"])
    assert r.exit_code == 0 and "no devices" in r.output
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "rules"])
    assert "inventory.new-device" in r.output


def test_bad_config_exits_2(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text("[scan]\nprofile = 'nope'\n")
    r = runner.invoke(app, ["--config", str(f), "version"])
    assert r.exit_code == 2
