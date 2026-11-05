from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from lanwatch.config import Config, LlmConfig
from lanwatch.helper import DEFAULT_SCRIPTS, Policy, validate_argv
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


# The helper policy the tests validate against: lanwatch's own scripts, and the networks the
# test fixtures use as if this host were attached to them.
HELPER_POLICY = Policy(
    DEFAULT_SCRIPTS,
    tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "192.168.1.0/24", "2001:db8::/64")),
)


def helper_refusal(argv: list[str]) -> str | None:
    """Why the helper would refuse argv under HELPER_POLICY; None when it is allowed."""
    return validate_argv(argv, HELPER_POLICY)
