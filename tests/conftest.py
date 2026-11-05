from __future__ import annotations

from pathlib import Path

import pytest

from lanwatch.config import Config, LlmConfig
from lanwatch.store import Store

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_host_config(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the machine's own lanwatch configuration out of the tests: a per-user file under
    ~/.config, or /etc/lanwatch/config.toml when the Debian package is installed (which an
    ordinary user cannot even read). Tests that exercise the lookup set their own paths."""
    empty = tmp_path_factory.mktemp("no-config")
    monkeypatch.setattr("lanwatch.config.SYSTEM_CONFIG_PATH", empty / "system.toml")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(empty))
    monkeypatch.delenv("LANWATCH_CONFIG", raising=False)


@pytest.fixture
def store() -> Store:
    return Store.memory()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()
