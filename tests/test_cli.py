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


def test_devices_and_findings_json(tmp_path: Path) -> None:
    from lanwatch.config import Config
    from lanwatch.models import HostObservation
    from lanwatch.store import Store

    cfg = Config(data_dir=tmp_path)
    with Store(cfg.store_path) as store:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(
            sid, [HostObservation(ip="10.0.0.1", mac="aa:bb:cc:00:00:01", source="t")]
        )
        store.finish_snapshot(sid, 1)
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "devices", "--json"])
    assert r.exit_code == 0, r.output
    assert '"mac": "aa:bb:cc:00:00:01"' in r.output
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "findings", "--json", "--status", "all"])
    assert r.exit_code == 0 and r.output.strip() == "[]"
    r = runner.invoke(app, ["--data-dir", str(tmp_path), "services", "1"])
    assert r.exit_code == 0 and "no open services" in r.output
