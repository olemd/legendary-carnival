from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from lanwatch.config import Config, ConfigError, env_overrides, load_config


def test_defaults_without_any_file(tmp_path: Path) -> None:
    loaded = load_config(environ={"HOME": str(tmp_path)})
    assert loaded.config_file is None
    assert loaded.config.scan.profile == "gentle"
    assert loaded.config.network.subnets == "auto"
    assert loaded.config.schedule.digest_time == "07:00"


def test_layering_file_env_cli(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text('[scan]\nprofile = "normal"\nmax_parallel_hosts = 8\n[llm]\nmodel = "x"\n')
    env = {"LANWATCH_SCAN__PROFILE": "thorough", "LANWATCH_LLM__TIMEOUT_S": "7"}
    loaded = load_config(f, {"scan": {"max_parallel_hosts": 2}}, environ=env)
    cfg = loaded.config
    assert cfg.scan.profile == "thorough"  # env beats file
    assert cfg.scan.max_parallel_hosts == 2  # cli beats file
    assert cfg.llm.model == "x"  # file beats default
    assert cfg.llm.timeout_s == 7  # env parsed as int
    assert loaded.config_file == f
    assert sorted(loaded.env_keys) == sorted(env)


def test_unknown_key_is_an_error(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text("[scan]\nprofil = 1\n")
    with pytest.raises(ConfigError, match=r"scan\.profil"):
        load_config(f, environ={})


def test_explicit_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.toml", environ={})
    with pytest.raises(ConfigError):
        load_config(None, environ={"LANWATCH_CONFIG": str(tmp_path / "nope.toml")})


def test_env_override_parsing() -> None:
    data, used = env_overrides(
        {
            "LANWATCH_NETWORK__SUBNETS": '["192.168.1.0/24"]',
            "LANWATCH_LLM__ENABLED": "false",
            "LANWATCH_CONFIG": "/x",
            "OTHER": "1",
        }
    )
    assert data == {"network": {"subnets": ["192.168.1.0/24"]}, "llm": {"enabled": False}}
    assert "LANWATCH_CONFIG" not in used


def test_subnet_validation() -> None:
    cfg = load_config(None, {"network": {"subnets": ["192.168.1.5/24"]}}, environ={}).config
    assert cfg.network.subnets == ["192.168.1.0/24"]
    with pytest.raises(ConfigError, match="invalid subnet"):
        load_config(None, {"network": {"subnets": ["not-a-net"]}}, environ={})


def test_digest_time_must_be_24h() -> None:
    with pytest.raises(ConfigError):
        load_config(None, {"schedule": {"digest_time": "7am"}}, environ={})


def test_packaged_config_is_an_empty_stub() -> None:
    """The file installed as /etc/lanwatch/config.toml is the user's and must never need a
    merge on upgrade: comments only, pointing at the reference next to it."""
    text = (Path(__file__).parent.parent / "debian" / "config.toml").read_text()
    assert tomllib.loads(text) == {}
    assert "config.toml.default" in text


def test_reference_config_is_valid_and_complete() -> None:
    """deploy/config.example.toml is installed as /etc/lanwatch/config.toml.default. It must
    load as is, and name every section, so a reader finds each setting there."""
    text = (Path(__file__).parent.parent / "deploy" / "config.example.toml").read_text()
    data = tomllib.loads(text)
    cfg = Config.model_validate(data)
    assert set(Config.model_fields) - {"data_dir", "rules"} <= set(data)
    # Shipped defaults: nothing on, nothing leaving the LAN that is not on by default.
    assert not cfg.unifi.enabled and not cfg.exposure.enabled and cfg.web.password is None
    # Every section header the reference documents is explained, not just listed.
    for section in set(Config.model_fields) - {"data_dir", "rules"}:
        header = f"[{section}]"
        assert header in text, header
        idx = text.index(header)
        assert text[idx : idx + 400].count("#") >= 1, f"{header} has no comment"


def test_config_show_redacts_secrets(tmp_path: Path) -> None:
    from lanwatch.config import (
        HomeAssistantConfig,
        NotifyConfig,
        UnifiConfig,
        WebConfig,
        dump_effective,
    )

    cfg = Config(
        data_dir=tmp_path,
        unifi=UnifiConfig(enabled=True, url="https://c", api_key="s3cret"),
        web=WebConfig(password="hunter2"),
        notify=NotifyConfig(
            home_assistant=HomeAssistantConfig(enabled=True, token="t0k3n-long-value")
        ),
    )
    text = dump_effective(cfg)
    assert "s3cret" not in text and "hunter2" not in text and "t0k3n-long-value" not in text
    assert 'api_key = "***"' in text and 'password = "***"' in text and 'token = "***"' in text
    assert "password = null" in dump_effective(Config(data_dir=tmp_path))  # unset stays visible
