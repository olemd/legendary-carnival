from __future__ import annotations

from pathlib import Path

import pytest

from lanwatch.config import Config, LlmConfig
from lanwatch.store import Store

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def store() -> Store:
    return Store.memory()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()
