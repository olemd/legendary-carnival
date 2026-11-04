"""Layered configuration: built-in defaults -> TOML file -> env LANWATCH_* -> CLI overrides.

Everything has a default. Nothing is required.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from lanwatch.models import Severity

ENV_PREFIX = "LANWATCH_"
ENV_CONFIG_PATH = "LANWATCH_CONFIG"


class ConfigError(Exception):
    pass


class StrictModel(BaseModel):
    """Unknown keys are errors: a typo in config must not silently do nothing."""

    model_config = ConfigDict(extra="forbid")


def default_data_dir() -> Path:
    if os.geteuid() == 0:
        return Path("/var/lib/lanwatch")
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "lanwatch"


def user_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "lanwatch" / "config.toml"


SYSTEM_CONFIG_PATH = Path("/etc/lanwatch/config.toml")


class NetworkConfig(StrictModel):
    subnets: Literal["auto"] | list[str] = "auto"
    # Auto-detected subnets wider than this prefix are skipped with a warning.
    max_auto_prefix: int = Field(default=22, ge=8, le=32)
    exclude_hosts: list[str] = Field(default_factory=list)
    exclude_interfaces: list[str] = Field(
        default_factory=lambda: ["lo", "docker*", "veth*", "br-*", "virbr*", "tun*", "tap*", "wg*"]
    )

    @field_validator("subnets")
    @classmethod
    def _check_subnets(cls, v: Literal["auto"] | list[str]) -> Literal["auto"] | list[str]:
        if v == "auto":
            return v
        out: list[str] = []
        for s in v:
            try:
                out.append(str(ipaddress.ip_network(s, strict=False)))
            except ValueError as e:
                raise ValueError(f"invalid subnet {s!r}: {e}") from e
        return out


class ScanConfig(StrictModel):
    profile: Literal["gentle", "normal", "thorough"] = "gentle"
    max_parallel_hosts: int = Field(default=4, ge=1, le=256)
    rate_limit_pps: int = Field(default=100, ge=1, le=10000)
    discovery_backend: Literal["auto", "arp-scan", "nmap", "ping"] = "auto"
    resolve_hostnames: bool = True


class ScheduleConfig(StrictModel):
    discovery_interval_s: int = Field(default=300, ge=10)
    inventory_interval_s: int = Field(default=3600, ge=60)
    deep_interval_s: int = Field(default=7 * 86400, ge=3600)
    infra_interval_s: int = Field(default=900, ge=60)
    digest_time: str = "07:00"

    @field_validator("digest_time")
    @classmethod
    def _hhmm(cls, v: str) -> str:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("digest_time must be HH:MM (24h)")
        return v


class LlmConfig(StrictModel):
    enabled: bool = True
    base_url: str = "http://localhost:11434"
    model: str = "qwen3:14b"
    timeout_s: int = Field(default=120, ge=1)
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    num_ctx: int = Field(default=8192, ge=512)


class StoreConfig(StrictModel):
    path: Path | None = None


class OverviewConfig(StrictModel):
    enabled: bool = True
    path: Path | None = None
    # Commit overview changes into a git repo at the overview's directory.
    git: bool = False


class NotifyConfig(StrictModel):
    log: bool = True
    report_dir: Path | None = None


class RuleOverride(StrictModel):
    enabled: bool | None = None
    severity: Severity | None = None


class Config(StrictModel):
    data_dir: Path = Field(default_factory=default_data_dir)
    network: NetworkConfig = NetworkConfig()
    scan: ScanConfig = ScanConfig()
    schedule: ScheduleConfig = ScheduleConfig()
    llm: LlmConfig = LlmConfig()
    store: StoreConfig = StoreConfig()
    overview: OverviewConfig = OverviewConfig()
    notify: NotifyConfig = NotifyConfig()
    rules: dict[str, RuleOverride] = Field(default_factory=dict)

    @property
    def store_path(self) -> Path:
        return self.store.path or self.data_dir / "lanwatch.db"

    @property
    def overview_path(self) -> Path:
        return self.overview.path or self.data_dir / "overview" / "overview.md"

    @property
    def report_dir(self) -> Path:
        return self.notify.report_dir or self.data_dir / "reports"


@dataclass(slots=True)
class LoadedConfig:
    config: Config
    config_file: Path | None
    env_keys: list[str] = field(default_factory=list)
    cli_overrides: dict[str, Any] = field(default_factory=dict)


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = dict(base)
    for k, v in override.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), Mapping):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def parse_env_value(raw: str) -> Any:
    """JSON if it parses (numbers, bools, lists), else the plain string."""
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def env_overrides(environ: Mapping[str, str]) -> tuple[dict[str, Any], list[str]]:
    """LANWATCH_SCAN__PROFILE=normal -> {"scan": {"profile": "normal"}}."""
    out: dict[str, Any] = {}
    used: list[str] = []
    for key, raw in environ.items():
        if not key.startswith(ENV_PREFIX) or key == ENV_CONFIG_PATH:
            continue
        path = key[len(ENV_PREFIX) :].lower().split("__")
        if not all(path):
            continue
        node = out
        for part in path[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                break
        else:
            node[path[-1]] = parse_env_value(raw)
            used.append(key)
    return out, used


def resolve_config_file(explicit: Path | None, environ: Mapping[str, str]) -> Path | None:
    """Explicit paths must exist. Otherwise first existing of user, then system config."""
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return explicit
    env_path = environ.get(ENV_CONFIG_PATH)
    if env_path:
        p = Path(env_path)
        if not p.is_file():
            raise ConfigError(f"{ENV_CONFIG_PATH} points to a missing file: {p}")
        return p
    for candidate in (user_config_path(), SYSTEM_CONFIG_PATH):
        if candidate.is_file():
            return candidate
    return None


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from e


def load_config(
    config_path: Path | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> LoadedConfig:
    env = os.environ if environ is None else environ
    file_path = resolve_config_file(config_path, env)
    merged: dict[str, Any] = {}
    if file_path is not None:
        merged = deep_merge(merged, load_toml(file_path))
    env_data, env_keys = env_overrides(env)
    merged = deep_merge(merged, env_data)
    cli = dict(cli_overrides or {})
    merged = deep_merge(merged, cli)
    try:
        cfg = Config.model_validate(merged)
    except ValidationError as e:
        raise ConfigError(format_validation_error(e, file_path)) from e
    return LoadedConfig(config=cfg, config_file=file_path, env_keys=env_keys, cli_overrides=cli)


def format_validation_error(e: ValidationError, file_path: Path | None) -> str:
    where = str(file_path) if file_path else "config"
    lines = [f"invalid configuration ({where}):"]
    for err in e.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        lines.append(f"  {loc}: {err['msg']}")
    return "\n".join(lines)


def dump_effective(cfg: Config) -> str:
    """Effective config as TOML-ish text for `config show`."""
    data = cfg.model_dump(mode="json")
    return _to_toml(data)


def _to_toml(data: dict[str, Any], prefix: str = "") -> str:
    scalars: list[str] = []
    tables: list[str] = []
    for k, v in data.items():
        if isinstance(v, dict):
            name = f"{prefix}.{k}" if prefix else k
            inner = _to_toml(v, name)
            if inner.strip() or not v:
                tables.append(f"[{name}]\n{inner}")
        else:
            scalars.append(f"{k} = {json.dumps(v)}")
    body = "\n".join(scalars)
    if body:
        body += "\n"
    if tables:
        body += ("\n" if body else "") + "\n".join(tables)
    return body
