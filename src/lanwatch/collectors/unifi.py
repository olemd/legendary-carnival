"""Read-only link to a UniFi Network controller through its Integration API.

The controller knows what no scan from one host can see: which access point or switch a
client hangs off, wired or wireless, guest or not, the name its owner gave it, which
networks (VLANs) exist and, through the subnet, which one a client is on, and the state and
firmware of the UniFi devices themselves. This module fetches all of that with an API key
(UniFi OS console, Settings -> Control Plane -> Integrations; Network 9.3 or later) and turns
it into plain dataclasses. For each online UniFi device it also reads the latest statistics:
uptime, CPU and memory use, and the rate on its uplink at that moment. It reads only: none
of the API's write endpoints are used.

What the API key does not give, and so nothing here pretends to: the SSID and signal
strength of a wireless client, the switch port of a wired one, or traffic per client or
per port. The network a client is on is derived from its address against the
gateway-managed subnets.

Everything coming back is third-party data and is checked field by field before use; the
rules and templates trust what is stored. Nothing raised here reaches the infra round:
the pipeline logs a failed fetch and keeps the previous state.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx2

from lanwatch import __version__
from lanwatch.config import UnifiConfig
from lanwatch.firmware import Firmware
from lanwatch.models import iso, normalize_mac, now_utc

log = logging.getLogger(__name__)

INTEGRATION_PATH = "/proxy/network/integration/v1"
PAGE_LIMIT = 200
MAX_PAGES = 50
MAX_DEVICE_DETAILS = 32
MAX_NETWORK_DETAILS = 32
TIMEOUT_S = 10
TOTAL_TIMEOUT_S = 60
CLIENT_TYPES = {"WIRED", "WIRELESS", "VPN", "TELEPORT"}
DEVICE_STATES = {
    "ONLINE",
    "OFFLINE",
    "PENDING_ADOPTION",
    "UPDATING",
    "GETTING_READY",
    "ADOPTING",
    "DELETING",
    "CONNECTION_INTERRUPTED",
    "ISOLATED",
    "U5G_INCORRECT_TOPOLOGY",
}
OFFLINE_STATES = {"OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED"}
MANAGEMENTS = {"UNMANAGED", "GATEWAY", "SWITCH"}
SSID_TYPES = {"STANDARD", "IOT_OPTIMIZED"}
MAX_TEXT = 80
# A port that can do a gigabit or more but has negotiated this or less: a 10/100 device, or
# a cable with a broken pair (gigabit needs all four).
SLOW_LINK_MBPS = 100
GIGABIT_MBPS = 1000


class UnifiError(Exception):
    """The controller could not be read. The message names the path and status, never
    the key."""


class UnifiAuthError(UnifiError):
    """401 or 403: the API key is wrong, revoked, or lacks rights."""


# -- data ---------------------------------------------------------------------


@dataclass(slots=True)
class UnifiClient:
    id: str = ""
    name: str | None = None
    type: str = "WIRED"  # WIRED | WIRELESS | VPN | TELEPORT
    mac: str | None = None
    ip: str | None = None
    connected_at: str | None = None
    uplink_device_id: str | None = None
    guest: bool = False

    @property
    def wired(self) -> bool:
        return self.type == "WIRED"


@dataclass(slots=True)
class UnifiPort:
    idx: int = 0
    state: str = "UNKNOWN"
    connector: str | None = None
    max_speed_mbps: int | None = None
    speed_mbps: int | None = None
    poe_state: str | None = None

    @property
    def slow(self) -> bool:
        """Up at 100 Mbit/s or less on a port that can do a gigabit or more."""
        return (
            self.state == "UP"
            and self.speed_mbps is not None
            and self.max_speed_mbps is not None
            and self.speed_mbps <= SLOW_LINK_MBPS
            and self.max_speed_mbps >= GIGABIT_MBPS
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "idx": self.idx,
            "state": self.state,
            "connector": self.connector,
            "speed": self.speed_mbps,
            "max_speed": self.max_speed_mbps,
            "poe": self.poe_state,
            "slow": self.slow,
        }


@dataclass(slots=True)
class UnifiRadio:
    standard: str | None = None
    frequency_ghz: float | None = None
    channel: int | None = None
    width_mhz: int | None = None
    tx_power: str | None = None


@dataclass(slots=True)
class UnifiRadioStats:
    frequency_ghz: float
    tx_retries_pct: float | None = None


@dataclass(slots=True)
class UnifiStats:
    """The controller's latest statistics for one device. Rates are what the device sent
    (tx) and received (rx) on its uplink when the controller last heard from it: a sample,
    not an average."""

    uptime_s: int | None = None
    cpu_pct: float | None = None
    mem_pct: float | None = None
    load_1: float | None = None
    uplink_tx_bps: int | None = None
    uplink_rx_bps: int | None = None
    radios: list[UnifiRadioStats] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "uptime_s": self.uptime_s,
            "cpu_pct": self.cpu_pct,
            "mem_pct": self.mem_pct,
            "load_1": self.load_1,
            "uplink_tx_bps": self.uplink_tx_bps,
            "uplink_rx_bps": self.uplink_rx_bps,
            "radios": [
                {"band": r.frequency_ghz, "tx_retries_pct": r.tx_retries_pct} for r in self.radios
            ],
        }

    def metrics(self) -> dict[str, float]:
        """What is kept over time (Store.add_snmp_series), by metric name."""
        values = {
            "unifi.uplink_tx_bps": self.uplink_tx_bps,
            "unifi.uplink_rx_bps": self.uplink_rx_bps,
            "unifi.cpu_pct": self.cpu_pct,
            "unifi.mem_pct": self.mem_pct,
            **{f"unifi.tx_retries_pct.{r.frequency_ghz:g}": r.tx_retries_pct for r in self.radios},
        }
        return {k: float(v) for k, v in values.items() if v is not None}


@dataclass(slots=True)
class UnifiDevice:
    id: str = ""
    mac: str | None = None
    ip: str | None = None
    name: str | None = None
    model: str = ""
    state: str = "OFFLINE"
    supported: bool = True
    firmware_version: str | None = None
    firmware_updatable: bool = False
    features: list[str] = field(default_factory=list)
    uplink_device_id: str | None = None
    ports: list[UnifiPort] = field(default_factory=list)
    radios: list[UnifiRadio] = field(default_factory=list)
    adopted_at: str | None = None
    stats: UnifiStats | None = None

    @property
    def is_gateway(self) -> bool:
        return "gateway" in self.features

    @property
    def is_access_point(self) -> bool:
        return "accessPoint" in self.features or bool(self.radios)

    @property
    def offline(self) -> bool:
        return self.state in OFFLINE_STATES

    def ports_summary(self) -> dict[str, int]:
        return {
            "total": len(self.ports),
            "up": sum(1 for p in self.ports if p.state == "UP"),
            "poe": sum(1 for p in self.ports if p.poe_state and p.poe_state != "DISABLED"),
        }

    def radios_summary(self) -> list[dict[str, Any]]:
        return [
            {
                "band": r.frequency_ghz,
                "channel": r.channel,
                "width": r.width_mhz,
                "standard": r.standard,
            }
            for r in self.radios
        ]


@dataclass(slots=True)
class UnifiPendingDevice:
    """UniFi gear the controller has seen on the network but that nobody has adopted: new
    out of the box, factory reset, or somebody else's."""

    mac: str
    ip: str | None = None
    model: str = ""
    state: str = "PENDING_ADOPTION"
    firmware_version: str | None = None


@dataclass(slots=True)
class UnifiNetwork:
    id: str = ""
    name: str = ""
    enabled: bool = True
    vlan_id: int | None = None
    management: str = "GATEWAY"
    default: bool = False
    subnet: str | None = None
    gateway_ip: str | None = None
    isolation: bool | None = None
    internet_access: bool | None = None


@dataclass(slots=True)
class UnifiSsid:
    id: str = ""
    name: str = ""
    enabled: bool = True
    type: str = "STANDARD"
    network_type: str | None = None  # NATIVE | SPECIFIC
    network_id: str | None = None


@dataclass(slots=True)
class UnifiSnapshot:
    version: str | None = None
    site_id: str = ""
    site_name: str = ""
    clients: list[UnifiClient] = field(default_factory=list)
    devices: list[UnifiDevice] = field(default_factory=list)
    networks: list[UnifiNetwork] = field(default_factory=list)
    ssids: list[UnifiSsid] = field(default_factory=list)
    pending: list[UnifiPendingDevice] = field(default_factory=list)
    fetched_at: str = field(default_factory=lambda: iso(now_utc()))

    @property
    def devices_by_id(self) -> dict[str, UnifiDevice]:
        return {d.id: d for d in self.devices}

    @property
    def default_network(self) -> UnifiNetwork | None:
        return next((n for n in self.networks if n.default), None)

    def network_for_ip(self, ip: str | None) -> UnifiNetwork | None:
        """The enabled network whose subnet contains the address; longest prefix wins."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best: tuple[int, UnifiNetwork] | None = None
        for n in self.networks:
            if not n.subnet or not n.enabled:
                continue
            try:
                net = ipaddress.ip_network(n.subnet)
            except ValueError:
                continue
            if addr in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, n)
        return best[1] if best else None

    def ssids_for_network(self, network_id: str | None) -> list[str]:
        """Names of the enabled SSIDs that put clients on the given network. NATIVE means
        the site's default network."""
        default = self.default_network
        out = []
        for s in self.ssids:
            if not s.enabled:
                continue
            target = default.id if default and s.network_type == "NATIVE" else s.network_id
            if target and target == network_id:
                out.append(s.name)
        return sorted(out)


# -- parsing ------------------------------------------------------------------


def _text(v: Any, limit: int = MAX_TEXT) -> str | None:
    return str(v).strip()[:limit] or None if isinstance(v, str | int | float) else None


def _bool(v: Any, default: bool = False) -> bool:
    return v if isinstance(v, bool) else default


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _num(v: Any) -> float | None:
    """A finite, non-negative number, else None."""
    if isinstance(v, bool) or not isinstance(v, int | float):
        return None
    return float(v) if math.isfinite(v) and v >= 0 else None


def _enum(v: Any, allowed: set[str], default: str) -> str:
    return v if isinstance(v, str) and v in allowed else default


def parse_page(data: Any) -> tuple[list[Any], int]:
    """A paged answer -> (items, totalCount). A bare list is taken as the whole set."""
    if isinstance(data, list):
        return data, len(data)
    if not isinstance(data, dict):
        return [], 0
    items = data.get("data")
    items = items if isinstance(items, list) else []
    total = data.get("totalCount")
    return items, total if isinstance(total, int) else len(items)


def parse_client(data: Any) -> UnifiClient | None:
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        return None
    access = data.get("access")
    return UnifiClient(
        id=data["id"],
        name=_text(data.get("name")),
        type=_enum(data.get("type"), CLIENT_TYPES, "WIRED"),
        mac=normalize_mac(data.get("macAddress"))
        if isinstance(data.get("macAddress"), str)
        else None,
        ip=_text(data.get("ipAddress"), 45),
        connected_at=_text(data.get("connectedAt"), 40),
        uplink_device_id=_text(data.get("uplinkDeviceId"), 64),
        guest=isinstance(access, dict) and access.get("type") == "GUEST",
    )


def _parse_port(data: Any) -> UnifiPort | None:
    if not isinstance(data, dict):
        return None
    poe = data.get("poe")
    return UnifiPort(
        idx=_int(data.get("idx")) or 0,
        state=_enum(data.get("state"), {"UP", "DOWN", "UNKNOWN"}, "UNKNOWN"),
        connector=_text(data.get("connector"), 16),
        max_speed_mbps=_int(data.get("maxSpeedMbps")),
        speed_mbps=_int(data.get("speedMbps")),
        poe_state=_text(poe.get("state"), 16) if isinstance(poe, dict) else None,
    )


def _parse_radio(data: Any) -> UnifiRadio | None:
    if not isinstance(data, dict):
        return None
    freq = data.get("frequencyGHz")
    return UnifiRadio(
        standard=_text(data.get("wlanStandard"), 16),
        frequency_ghz=float(freq)
        if isinstance(freq, int | float) and not isinstance(freq, bool)
        else None,
        channel=_int(data.get("channel")),
        width_mhz=_int(data.get("channelWidthMHz")),
        tx_power=_text(data.get("txPowerMode"), 16),
    )


def parse_stats(data: Any) -> UnifiStats | None:
    """The answer of .../statistics/latest. Every field is optional in the API."""
    if not isinstance(data, dict):
        return None

    def whole(v: Any) -> int | None:
        n = _num(v)
        return int(n) if n is not None else None

    def pct(v: Any) -> float | None:
        n = _num(v)
        return round(n, 1) if n is not None and n <= 100 else None

    uplink = data.get("uplink")
    uplink = uplink if isinstance(uplink, dict) else {}
    interfaces = data.get("interfaces")
    radios_raw = interfaces.get("radios") if isinstance(interfaces, dict) else None
    radios = []
    for r in radios_raw if isinstance(radios_raw, list) else []:
        band = _num(r.get("frequencyGHz")) if isinstance(r, dict) else None
        if band is not None:
            radios.append(UnifiRadioStats(band, pct(r.get("txRetriesPct"))))
    load = _num(data.get("loadAverage1Min"))
    return UnifiStats(
        uptime_s=whole(data.get("uptimeSec")),
        cpu_pct=pct(data.get("cpuUtilizationPct")),
        mem_pct=pct(data.get("memoryUtilizationPct")),
        load_1=round(load, 2) if load is not None else None,
        uplink_tx_bps=whole(uplink.get("txRateBps")),
        uplink_rx_bps=whole(uplink.get("rxRateBps")),
        radios=radios,
    )


def parse_device(overview: Any, details: Any = None, stats: Any = None) -> UnifiDevice | None:
    """An adopted device from the list, enriched with the detail answer when given (uplink,
    ports, radios) and the statistics answer. All are checked; the detail answer may be
    missing on older releases."""
    if not isinstance(overview, dict) or not isinstance(overview.get("id"), str):
        return None
    details = details if isinstance(details, dict) else {}
    features_raw = overview.get("features")
    if isinstance(features_raw, list):
        features = sorted(str(f) for f in features_raw if isinstance(f, str))
    else:
        # The detail endpoint lists features as an object keyed by feature name.
        fdet = details.get("features")
        features = (
            sorted(k for k, v in fdet.items() if v is not None) if isinstance(fdet, dict) else []
        )
    uplink = details.get("uplink")
    interfaces = details.get("interfaces")
    ports_raw = interfaces.get("ports") if isinstance(interfaces, dict) else None
    radios_raw = interfaces.get("radios") if isinstance(interfaces, dict) else None
    return UnifiDevice(
        id=overview["id"],
        mac=normalize_mac(overview.get("macAddress"))
        if isinstance(overview.get("macAddress"), str)
        else None,
        ip=_text(overview.get("ipAddress"), 45),
        name=_text(overview.get("name")),
        model=_text(overview.get("model"), 40) or "",
        state=_enum(overview.get("state"), DEVICE_STATES, "OFFLINE"),
        supported=_bool(overview.get("supported"), True),
        firmware_version=_text(overview.get("firmwareVersion"), 40),
        firmware_updatable=_bool(overview.get("firmwareUpdatable")),
        features=features,
        uplink_device_id=_text(uplink.get("deviceId"), 64) if isinstance(uplink, dict) else None,
        ports=[p for p in (_parse_port(x) for x in ports_raw or []) if p is not None],
        radios=[r for r in (_parse_radio(x) for x in radios_raw or []) if r is not None],
        adopted_at=_text(details.get("adoptedAt"), 40),
        stats=parse_stats(stats),
    )


def parse_pending(data: Any) -> UnifiPendingDevice | None:
    if not isinstance(data, dict) or not isinstance(data.get("macAddress"), str):
        return None
    mac = normalize_mac(data["macAddress"])
    if not mac:
        return None
    return UnifiPendingDevice(
        mac=mac,
        ip=_text(data.get("ipAddress"), 45),
        model=_text(data.get("model"), 40) or "",
        state=_enum(data.get("state"), DEVICE_STATES, "PENDING_ADOPTION"),
        firmware_version=_text(data.get("firmwareVersion"), 40),
    )


def parse_network(overview: Any, details: Any = None) -> UnifiNetwork | None:
    """A network from the list, with subnet and isolation from the detail answer when it is
    gateway-managed (the only kind that carries an IPv4 configuration)."""
    if not isinstance(overview, dict) or not isinstance(overview.get("id"), str):
        return None
    details = details if isinstance(details, dict) else {}
    subnet = gateway_ip = None
    ipv4 = details.get("ipv4Configuration")
    if isinstance(ipv4, dict):
        host, prefix = ipv4.get("hostIpAddress"), ipv4.get("prefixLength")
        if isinstance(host, str) and isinstance(prefix, int):
            try:
                subnet = str(ipaddress.ip_network(f"{host}/{prefix}", strict=False))
                gateway_ip = host
            except ValueError:
                subnet = None
    isolation = details.get("isolationEnabled")
    internet = details.get("internetAccessEnabled")
    return UnifiNetwork(
        id=overview["id"],
        name=_text(overview.get("name")) or "",
        enabled=_bool(overview.get("enabled"), True),
        vlan_id=_int(overview.get("vlanId")),
        management=_enum(overview.get("management"), MANAGEMENTS, "GATEWAY"),
        default=_bool(overview.get("default")),
        subnet=subnet,
        gateway_ip=gateway_ip,
        isolation=isolation if isinstance(isolation, bool) else None,
        internet_access=internet if isinstance(internet, bool) else None,
    )


def parse_ssid(data: Any) -> UnifiSsid | None:
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        return None
    network = data.get("network")
    net_type = net_id = None
    if isinstance(network, dict):
        net_type = _enum(network.get("type"), {"NATIVE", "SPECIFIC"}, "NATIVE")
        net_id = _text(network.get("networkId"), 64)
    return UnifiSsid(
        id=data["id"],
        name=_text(data.get("name")) or "",
        enabled=_bool(data.get("enabled"), True),
        type=_enum(data.get("type"), SSID_TYPES, "STANDARD"),
        network_type=net_type,
        network_id=net_id,
    )


# -- HTTP -----------------------------------------------------------------------


def tls_verify(cfg: UnifiConfig) -> bool | str:
    """What httpx2 gets as `verify`: the console's own certificate file when given, else the
    switch. Consoles ship a self-signed certificate, so one of the two has to give."""
    return str(cfg.ca_file) if cfg.ca_file else cfg.verify_tls


def make_client(cfg: UnifiConfig) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        base_url=cfg.url.rstrip("/") + INTEGRATION_PATH,
        headers={
            "X-API-Key": cfg.api_key,
            "Accept": "application/json",
            "User-Agent": f"lanwatch/{__version__}",
        },
        verify=tls_verify(cfg),
        timeout=TIMEOUT_S,
        follow_redirects=False,
        # A proxy from the environment must never sit between us and a LAN controller.
        trust_env=False,
    )


class UnifiApi:
    """Thin wrapper: one GET per method, paging where the API pages."""

    def __init__(self, client: httpx2.AsyncClient) -> None:
        self._client = client

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        r = await self._client.get(path, params=params)
        if r.status_code in (401, 403):
            raise UnifiAuthError(f"{path}: HTTP {r.status_code}, the API key was not accepted")
        if r.status_code >= 400:
            raise UnifiError(f"{path}: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as e:
            raise UnifiError(f"{path}: not JSON") from e

    async def paged(self, path: str) -> list[Any]:
        items: list[Any] = []
        offset = 0
        for _ in range(MAX_PAGES):
            page, total = parse_page(await self.get(path, {"offset": offset, "limit": PAGE_LIMIT}))
            items.extend(page)
            offset += len(page)
            if not page or offset >= total:
                break
        return items

    async def info(self) -> Any:
        return await self.get("/info")

    async def sites(self) -> list[Any]:
        return await self.paged("/sites")

    async def clients(self, site: str) -> list[Any]:
        return await self.paged(f"/sites/{site}/clients")

    async def devices(self, site: str) -> list[Any]:
        return await self.paged(f"/sites/{site}/devices")

    async def device(self, site: str, device_id: str) -> Any:
        return await self.get(f"/sites/{site}/devices/{device_id}")

    async def device_statistics(self, site: str, device_id: str) -> Any:
        return await self.get(f"/sites/{site}/devices/{device_id}/statistics/latest")

    async def pending_devices(self) -> list[Any]:
        return await self.paged("/pending-devices")

    async def networks(self, site: str) -> list[Any]:
        return await self.paged(f"/sites/{site}/networks")

    async def network(self, site: str, network_id: str) -> Any:
        return await self.get(f"/sites/{site}/networks/{network_id}")

    async def wifi_broadcasts(self, site: str) -> list[Any]:
        return await self.paged(f"/sites/{site}/wifi/broadcasts")


def _pick_site(sites: list[Any], wanted: str | None) -> tuple[str, str]:
    """(id, name) of the configured site, matched on id, name or the old-API internal
    reference, else the first one."""
    rows = [s for s in sites if isinstance(s, dict) and isinstance(s.get("id"), str)]
    if not rows:
        raise UnifiError("the controller lists no sites")
    chosen = rows[0]
    if wanted:
        for s in rows:
            if wanted in (s.get("id"), s.get("name"), s.get("internalReference")):
                chosen = s
                break
        else:
            raise UnifiError(f"no site called {wanted!r} on the controller")
    return str(chosen["id"]), _text(chosen.get("name")) or str(chosen["id"])


async def fetch_unifi(cfg: UnifiConfig, client: httpx2.AsyncClient | None = None) -> UnifiSnapshot:
    """Everything lanwatch uses, in a handful of GETs: info, sites, clients, devices (with
    details for the first MAX_DEVICE_DETAILS, and statistics for those that are online),
    networks (details for gateway-managed ones), SSIDs, and the devices waiting for
    adoption. A failed detail call keeps the overview; anything else raises UnifiError."""
    own = client is None
    client = client or make_client(cfg)
    try:
        api = UnifiApi(client)
        info = await api.info()
        version = _text(info.get("applicationVersion"), 40) if isinstance(info, dict) else None
        site_id, site_name = _pick_site(await api.sites(), cfg.site)

        clients = [c for c in (parse_client(x) for x in await api.clients(site_id)) if c]

        devices: list[UnifiDevice] = []
        for i, raw in enumerate(await api.devices(site_id)):
            details = stats = None
            if i < MAX_DEVICE_DETAILS and isinstance(raw, dict) and isinstance(raw.get("id"), str):
                try:
                    details = await api.device(site_id, raw["id"])
                except UnifiError as e:
                    log.debug("unifi: device details unavailable: %s", e)
                if raw.get("state") == "ONLINE":  # the others have nothing current to say
                    try:
                        stats = await api.device_statistics(site_id, raw["id"])
                    except UnifiError as e:
                        log.debug("unifi: device statistics unavailable: %s", e)
            if (dev := parse_device(raw, details, stats)) is not None:
                devices.append(dev)

        networks: list[UnifiNetwork] = []
        detailed = 0
        for raw in await api.networks(site_id):
            details = None
            if (
                isinstance(raw, dict)
                and raw.get("management") == "GATEWAY"
                and isinstance(raw.get("id"), str)
                and detailed < MAX_NETWORK_DETAILS
            ):
                detailed += 1
                try:
                    details = await api.network(site_id, raw["id"])
                except UnifiError as e:
                    log.debug("unifi: network details unavailable: %s", e)
            if (net := parse_network(raw, details)) is not None:
                networks.append(net)

        ssids = [s for s in (parse_ssid(x) for x in await api.wifi_broadcasts(site_id)) if s]

        # Not per site, and newer than the rest (Network 10): an older controller answers
        # 404, which is taken as nothing pending.
        pending: list[UnifiPendingDevice] = []
        try:
            pending = [p for p in (parse_pending(x) for x in await api.pending_devices()) if p]
        except UnifiError as e:
            log.debug("unifi: pending devices unavailable: %s", e)
    except httpx2.HTTPError as e:
        # TLS failures, refused connections, timeouts: say what, not the key.
        raise UnifiError(f"{type(e).__name__}: {str(e)[:200]}") from e
    finally:
        if own:
            await client.aclose()
    return UnifiSnapshot(
        version=version,
        site_id=site_id,
        site_name=site_name,
        clients=clients,
        devices=devices,
        networks=networks,
        ssids=ssids,
        pending=pending,
    )


# -- what goes into lanwatch --------------------------------------------------------


def _uplink(snap: UnifiSnapshot, device_id: str | None) -> dict[str, Any] | None:
    dev = snap.devices_by_id.get(device_id or "")
    if dev is None:
        return None
    return {"id": dev.id, "name": dev.name or dev.model, "model": dev.model, "mac": dev.mac}


def _network(snap: UnifiSnapshot, ip: str | None) -> dict[str, Any] | None:
    net = snap.network_for_ip(ip)
    if net is None:
        return None
    return {"id": net.id, "name": net.name, "vlan": net.vlan_id, "default": net.default}


def client_attrs(c: UnifiClient, snap: UnifiSnapshot) -> dict[str, Any]:
    """attrs["unifi"] for a LAN device the controller lists as a client."""
    network = _network(snap, c.ip)
    out: dict[str, Any] = {
        "name": c.name,
        "wired": c.wired,
        "guest": c.guest,
        "connected_at": c.connected_at,
        "uplink": _uplink(snap, c.uplink_device_id),
        "network": network,
        "seen": snap.fetched_at,
    }
    if not c.wired:
        out["ssids_on_network"] = snap.ssids_for_network(network["id"]) if network else []
    return out


def device_attrs(dev: UnifiDevice, snap: UnifiSnapshot) -> dict[str, Any]:
    """attrs["unifi_device"] for a LAN device that is itself UniFi gear."""
    return {
        "id": dev.id,
        "mac": dev.mac,
        "name": dev.name,
        "model": dev.model,
        "state": dev.state,
        "firmware_version": dev.firmware_version,
        "firmware_updatable": dev.firmware_updatable,
        "features": dev.features,
        "uplink": _uplink(snap, dev.uplink_device_id),
        "network": _network(snap, dev.ip),
        "ports": dev.ports_summary(),
        "port_list": [p.as_dict() for p in sorted(dev.ports, key=lambda p: p.idx)],
        "radios": dev.radios_summary(),
        "adopted_at": dev.adopted_at,
        "stats": dev.stats.as_dict() if dev.stats else None,
        "seen": snap.fetched_at,
    }


def firmware_attrs(dev: UnifiDevice, checked: str) -> dict[str, Any]:
    """attrs["firmware"] in the shape lanwatch.firmware writes, so the existing
    device.firmware-outdated rule covers UniFi gear. The controller says whether an update
    exists but not which version, so `latest` stays None."""
    fw = Firmware(
        product=f"UniFi {dev.model}".strip(),
        version=dev.firmware_version or "?",
        latest=None,
        update=dev.firmware_updatable,
        source="unifi",
        model="",  # already in the product name; the device page would print it twice
    )
    return {**asdict(fw), "checked": checked}


def infra_rows(
    snap: UnifiSnapshot, known: Callable[[str], bool]
) -> dict[str, dict[str, dict[str, Any]]]:
    """The five infra kinds, keyed as the rules and pages look them up. `known(mac)` says
    whether lanwatch's own discovery has a device for the address."""
    networks = {
        n.id: {
            "id": n.id,
            "name": n.name,
            "enabled": n.enabled,
            "vlan": n.vlan_id,
            "subnet": n.subnet,
            "gateway_ip": n.gateway_ip,
            "management": n.management,
            "default": n.default,
            "isolation": n.isolation,
            "internet_access": n.internet_access,
            "ssids": snap.ssids_for_network(n.id),
        }
        for n in snap.networks
    }
    default = snap.default_network
    ssids = {
        s.id: {
            "id": s.id,
            "name": s.name,
            "enabled": s.enabled,
            "type": s.type,
            "network_type": s.network_type,
            "network_id": (default.id if default and s.network_type == "NATIVE" else s.network_id),
            "network_name": next(
                (
                    n.name
                    for n in snap.networks
                    if n.id
                    == (default.id if default and s.network_type == "NATIVE" else s.network_id)
                ),
                None,
            ),
        }
        for s in snap.ssids
    }
    clients_per_device: dict[str, int] = {}
    for c in snap.clients:
        if c.uplink_device_id:
            clients_per_device[c.uplink_device_id] = (
                clients_per_device.get(c.uplink_device_id, 0) + 1
            )
    devices = {
        d.mac: {
            **device_attrs(d, snap),
            "ip": d.ip,
            "mac": d.mac,
            "is_gateway": d.is_gateway,
            "is_access_point": d.is_access_point,
            "clients": clients_per_device.get(d.id, 0),
        }
        for d in snap.devices
        if d.mac
    }
    clients = {}
    for c in snap.clients:
        if not c.mac:
            continue  # VPN and Teleport connections have no address on the LAN
        network = _network(snap, c.ip)
        uplink = _uplink(snap, c.uplink_device_id)
        clients[c.mac] = {
            "id": c.id,
            "name": c.name,
            "type": c.type,
            "ip": c.ip,
            "mac": c.mac,
            "guest": c.guest,
            "uplink_id": c.uplink_device_id,
            "uplink_name": uplink["name"] if uplink else None,
            "uplink_mac": uplink["mac"] if uplink else None,
            "network_id": network["id"] if network else None,
            "network_name": network["name"] if network else None,
            "vlan": network["vlan"] if network else None,
            "connected_at": c.connected_at,
            "known": known(c.mac),
        }
    return {
        "unifi-network": networks,
        "unifi-ssid": ssids,
        "unifi-device": devices,
        "unifi-client": clients,
        "unifi-pending": {
            p.mac: {
                "mac": p.mac,
                "ip": p.ip,
                "model": p.model,
                "state": p.state,
                "firmware_version": p.firmware_version,
            }
            for p in snap.pending
        },
    }
