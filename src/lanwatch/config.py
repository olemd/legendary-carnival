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
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

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
    # A watched device is reported offline after missing this many discovery rounds in a
    # row. One missed round is common (a dropped ARP reply), so the default waits for two.
    watch_offline_rounds: int = Field(default=2, ge=1, le=20)
    # Container bridges and VPN overlays are not LAN segments: nothing to discover there,
    # and arp-scan cannot run on point-to-point interfaces such as wg0 or tailscale0.
    exclude_interfaces: list[str] = Field(
        default_factory=lambda: [
            "lo",
            "docker*",
            "veth*",
            "br-*",
            "virbr*",
            "tun*",
            "tap*",
            "wg*",
            "tailscale*",
        ]
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
    # Service inventory (nmap). Light scans run hourly and on new devices; deep weekly.
    light_top_ports: int = Field(default=200, ge=10, le=65535)
    deep_udp_top_ports: int = Field(default=50, ge=0, le=1000)
    # Never probed. 9100 (raw printing) makes printers print probe garbage.
    exclude_ports: list[int] = Field(default_factory=lambda: [9100])
    # Devices (IP or MAC) that are discovered and tracked like any other, but never
    # port-scanned: some embedded gear crashes or reboots when nmap probes it. Empty by
    # default on purpose: a device that cannot take a scan is worth knowing about first.
    skip_hosts: list[str] = Field(default_factory=list)
    version_detection: bool = True
    # nmap scripts, all from the "safe" category, run only against open ports.
    scripts: list[str] = Field(
        default_factory=lambda: [
            "ssl-cert",
            "ssh2-enum-algos",
            "smb-protocols",
            "vnc-info",
            "http-title",
        ]
    )
    scan_new_devices_immediately: bool = True
    # A second, slower look each discovery round at addresses that stayed silent but should
    # be there: devices online in the previous round, and clients the UniFi controller lists
    # on a scanned subnet. A few pings with a longer wait; only a reply counts. Catches
    # power-saving Wi-Fi devices that sleep through arp-scan without trusting anyone's word.
    recheck_silent: bool = True
    # Forward privileged commands to lanwatch-helper (root) over this unix socket.
    # Needed for rootless containers. Unset = run commands locally.
    helper_socket: Path | None = None
    # Infra probes (every schedule.infra_interval_s): DHCP servers, mDNS, UPnP, IPv6.
    # Ask the DHCP-announced DNS resolver for a few test names that filtering resolvers
    # block, to see whether it filters ads or malicious domains. Off by default: the
    # lookups go out to the internet through that resolver.
    dns_filter_check: bool = False
    # Listen to ARP traffic between scans (needs the same raw-socket privilege as arp-scan).
    arp_watch: bool = True
    # Ask the local segment for a name that does not exist (LLMNR, mDNS, NetBIOS). Anything
    # that answers is a poisoning tool. Local broadcast only.
    name_poisoning_check: bool = True
    upnp: bool = True
    ipv6: bool = True
    ipv6_top_ports: int = Field(default=100, ge=10, le=65535)
    # nmap "vulners" script: matches service versions against vulners.com. This is the
    # one feature that talks to the internet, hence off by default.
    vulners: bool = False
    vulners_min_cvss: float = Field(default=7.0, ge=0.0, le=10.0)


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
    model: str = "qwen3.8:27b"
    timeout_s: int = Field(default=120, ge=1)
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    num_ctx: int = Field(default=8192, ge=512)
    # Language for explanations, digests and suggestions (ISO 639-1).
    language: str = "nb"
    # Cap on LLM calls per scan round; the rest is picked up next round.
    max_calls_per_round: int = Field(default=25, ge=0)
    keep_alive: str = "30m"
    # Context window for the inventory chat (the whole inventory is pasted in).
    chat_num_ctx: int = Field(default=16384, ge=2048)


class StoreConfig(StrictModel):
    path: Path | None = None
    # How many days of history a daily maintenance job keeps. 0 keeps everything.
    # Rounds: which devices answered in each discovery round (one row per device every five
    # minutes, by far the fastest-growing data). Devices, services and findings are never
    # pruned; they are current state, not history.
    keep_rounds_days: int = Field(default=30, ge=0)
    keep_events_days: int = Field(default=365, ge=0)
    keep_notifications_days: int = Field(default=90, ge=0)


class OverviewConfig(StrictModel):
    enabled: bool = True
    path: Path | None = None
    # Commit overview changes into a git repo at the overview's directory.
    git: bool = False


class NtfyConfig(StrictModel):
    enabled: bool = False
    url: str = "https://ntfy.sh"
    topic: str = ""
    token: str | None = None
    min_severity: Severity | None = None  # None = notify.min_severity

    @model_validator(mode="after")
    def _topic_required(self) -> NtfyConfig:
        if self.enabled and not self.topic:
            raise ValueError("notify.ntfy.topic is required when enabled")
        return self


class WebhookConfig(StrictModel):
    enabled: bool = False
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    min_severity: Severity | None = None

    @model_validator(mode="after")
    def _url_required(self) -> WebhookConfig:
        if self.enabled and not self.url.startswith(("http://", "https://")):
            raise ValueError("notify.webhook.url must be an http(s) URL when enabled")
        return self


class HomeAssistantConfig(StrictModel):
    enabled: bool = False
    url: str = "http://homeassistant.local:8123"
    token: str = ""  # long-lived access token
    service: str = "notify.notify"  # e.g. notify.mobile_app_my_phone
    publish_sensors: bool = True  # sensor.lanwatch_* via the states API
    min_severity: Severity | None = None
    # lanwatch's web UI as a phone on the LAN reaches it, e.g. "http://192.168.1.10:8321".
    # When set, a notification opens the device or finding in lanwatch when tapped, and
    # carries an "Open" button; see docs/home-assistant.md for the "Accept" button.
    lanwatch_url: str | None = None

    @model_validator(mode="after")
    def _token_required(self) -> HomeAssistantConfig:
        if self.enabled and not self.token:
            raise ValueError("notify.home_assistant.token is required when enabled")
        if "." not in self.service:
            raise ValueError("notify.home_assistant.service must be domain.service")
        if self.lanwatch_url is not None and not self.lanwatch_url.startswith(
            ("http://", "https://")
        ):
            raise ValueError("notify.home_assistant.lanwatch_url must be an http(s) URL")
        return self


class EmailConfig(StrictModel):
    enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = Field(default=587, ge=1, le=65535)
    starttls: bool = True
    username: str | None = None
    password: str | None = None
    sender: str = "lanwatch@localhost"
    to: list[str] = Field(default_factory=list)
    min_severity: Severity | None = None

    @model_validator(mode="after")
    def _to_required(self) -> EmailConfig:
        if self.enabled and not self.to:
            raise ValueError("notify.email.to is required when enabled")
        return self


class NotifyConfig(StrictModel):
    log: bool = True
    report_dir: Path | None = None
    # Findings at or above this severity are pushed (channels may raise their own bar).
    min_severity: Severity = Severity.MEDIUM
    resolved: bool = False  # also push when findings auto-resolve
    digest: bool = True  # push the daily digest
    ntfy: NtfyConfig = NtfyConfig()
    webhook: WebhookConfig = WebhookConfig()
    home_assistant: HomeAssistantConfig = HomeAssistantConfig()
    email: EmailConfig = EmailConfig()


class WebConfig(StrictModel):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = Field(default=8321, ge=1, le=65535)
    # Required when host is not loopback. Basic auth, user "lanwatch".
    password: str | None = None


class DecoyConfig(StrictModel):
    """Listeners on ports nothing here uses; a connection to one is a finding."""

    enabled: bool = True
    # Classic targets of scanners and worms that a Linux box running lanwatch rarely uses
    # itself. A port that is already in use when lanwatch starts is skipped. Remove a
    # port here before installing a real service on it.
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=lambda: [23, 1433, 3389, 5555]
    )
    # Source addresses never reported, e.g. another scanner of your own.
    ignore: list[str] = Field(default_factory=list)


class FirmwareConfig(StrictModel):
    """Daily check of what version devices run; see lanwatch/firmware.py for the products."""

    # Read running versions from devices: mDNS, and one unauthenticated GET to a few
    # well-known local URLs on devices that have that port open. Stays on the LAN.
    enabled: bool = True
    # Also ask vendors and GitHub what the latest release is. Leaves the network (public
    # version lists, nothing about your devices); off, only devices that compare for
    # themselves report updates.
    online: bool = True


class ExposureConfig(StrictModel):
    """Daily lookup of the public address in Shodan's InternetDB; see lanwatch/exposure.py."""

    # Off by default: it is the one check that tells a third party something about this
    # network (its public address). Turn it on to learn which ports answer from the internet.
    enabled: bool = False
    # Asked for the public address when no UPnP gateway reports it. Plain text, one line.
    ip_lookup_url: str = "https://api.ipify.org"


class UnifiConfig(StrictModel):
    """Read-only link to a UniFi Network controller (Integration API); see docs/unifi.md."""

    enabled: bool = False
    # The UniFi OS console. lanwatch appends the Integration API path itself.
    url: str = "https://192.168.1.1"
    # Settings -> Integrations in the Network app, https://<console>/network/default/integrations
    # (Network 9.3 or later).
    api_key: str = ""
    # Site id or name; None takes the first (normally the only) site.
    site: str | None = None
    # Consoles ship a self-signed certificate: either export it and point ca_file at it,
    # or set verify_tls = false and accept that the LAN link is unauthenticated.
    verify_tls: bool = True
    ca_file: Path | None = None
    # Give unnamed lanwatch devices the name the controller has for them. Never overwrites
    # a name set in lanwatch.
    adopt_names: bool = True

    @model_validator(mode="after")
    def _check(self) -> UnifiConfig:
        if self.enabled and not self.api_key:
            raise ValueError("unifi.api_key is required when enabled")
        if not self.url.startswith("https://"):
            raise ValueError("unifi.url must be an https URL (the console only speaks TLS)")
        if self.ca_file is not None and not self.verify_tls:
            raise ValueError("unifi.ca_file and verify_tls = false contradict each other")
        return self


class SnmpConfig(StrictModel):
    """Read-only SNMPv3 link to the router; see docs/snmp.md.

    SNMPv3 with authentication and encryption (authPriv) only: v1/v2c send the community
    in clear text and give anyone who learns it the same view, so lanwatch does not speak
    them. MD5 and DES are refused as well. SHA-1 is allowed: SNMPv3 uses it as an HMAC,
    which the known SHA-1 collision attacks do not break, and UniFi gateways and switches
    offer nothing else. SHA-256 is the default."""

    enabled: bool = False
    # The router's address. None: this host's default gateway.
    host: str | None = None
    user: str = "lanwatch"
    # "SHA" is SHA-1 (HMAC-SHA-96): the weakest allowed, for agents that have nothing newer.
    auth_protocol: Literal["SHA-256", "SHA-384", "SHA-512", "SHA"] = "SHA-256"
    auth_password: str = ""
    # "AES" is AES-128, the one AES variant every SNMPv3 agent has (Junos has no other).
    priv_protocol: Literal["AES", "AES-256"] = "AES"
    priv_password: str = ""
    timeout_s: int = Field(default=5, ge=1, le=60)

    @model_validator(mode="after")
    def _check(self) -> SnmpConfig:
        if not self.enabled:
            return self
        for key in ("auth_password", "priv_password"):
            value: str = getattr(self, key)
            if len(value) < 8:
                # RFC 3414: agents refuse shorter passphrases.
                raise ValueError(f"snmp.{key} must be at least 8 characters")
            if any(c.isspace() or c == "#" for c in value):
                # net-snmp reads them from a config file where these end the value.
                raise ValueError(f"snmp.{key} must not contain spaces or '#'")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", self.user):
            raise ValueError("snmp.user must be 1-32 letters, digits, '.', '_' or '-'")
        if self.host is not None and not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", self.host):
            raise ValueError("snmp.host must be an IP address or a host name")
        return self


class LatencyConfig(StrictModel):
    """Round-trip time and packet loss, measured with a few pings every discovery round."""

    enabled: bool = True
    # "gateway" stands for this host's default gateways. Anything else is pinged as written,
    # so add an internet address (say "1.1.1.1") yourself if you want the internet path too.
    targets: list[str] = Field(default_factory=lambda: ["gateway"])
    count: int = Field(default=4, ge=1, le=20)
    # A finding when this share of probes (or more) is lost in each of the last three rounds.
    loss_threshold: float = Field(default=0.25, ge=0.01, le=1.0)


class OuiConfig(StrictModel):
    """Vendor names for MAC addresses; see lanwatch/oui.py."""

    # Download the IEEE registry (standards-oui.ieee.org) once a week, so devices with a
    # prefix newer than the lists arp-scan and nmap ship get a vendor name. Leaves the
    # network (a public list, nothing about your devices); off, the copy installed with
    # nmap is used instead.
    online: bool = True


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
    web: WebConfig = WebConfig()
    decoy: DecoyConfig = DecoyConfig()
    firmware: FirmwareConfig = FirmwareConfig()
    oui: OuiConfig = OuiConfig()
    latency: LatencyConfig = LatencyConfig()
    exposure: ExposureConfig = ExposureConfig()
    unifi: UnifiConfig = UnifiConfig()
    snmp: SnmpConfig = SnmpConfig()
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
    if cfg.web.enabled and not cfg.web.password and not _is_loopback(cfg.web.host):
        raise ConfigError(
            f"web.host={cfg.web.host!r} is reachable from the network; set web.password"
            " or bind to 127.0.0.1"
        )
    return LoadedConfig(config=cfg, config_file=file_path, env_keys=env_keys, cli_overrides=cli)


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def format_validation_error(e: ValidationError, file_path: Path | None) -> str:
    where = str(file_path) if file_path else "config"
    lines = [f"invalid configuration ({where}):"]
    for err in e.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        lines.append(f"  {loc}: {err['msg']}")
    return "\n".join(lines)


# Keys whose values are secrets: `config show` prints whether they are set, not what.
SECRET_KEYS = frozenset({"api_key", "token", "password", "auth_password", "priv_password"})


def dump_effective(cfg: Config) -> str:
    """Effective config as TOML-ish text for `config show`, secrets redacted."""
    data = cfg.model_dump(mode="json")
    return _to_toml(_redact(data))


def _redact(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, dict):
            out[k] = _redact(v)
        elif k in SECRET_KEYS and v:
            out[k] = "***"
        else:
            out[k] = v
    return out


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
