"""Firmware check: what version is a device running, and is there a newer one?

There is no vendor-independent way to ask that, so this is a short list of products that
answer the question themselves, each read the way its maker documents:

  product          running version from                     newer version from
  Home Assistant   mDNS _home-assistant._tcp, TXT version   version.home-assistant.io (online)
  ESPHome          mDNS _esphomelib._tcp, TXT version       GitHub releases (online)
  Shelly Gen2+     GET /shelly                              device: /rpc/Shelly.CheckForUpdate
  Shelly Gen1      GET /shelly                              device: /ota, else Shelly index (online)
  Tasmota          GET /cm?cmnd=Status 2                    GitHub releases (online)
  Pi-hole          GET /admin/api.php?versions (v5),        the device itself
                   /api/info/version (v6)
  Jellyfin         GET :8096/System/Info/Public             GitHub releases (online)

Reading the running version stays on the LAN: an mDNS question, or one unauthenticated GET
to a device that already has that port open. "(online)" lookups ask the vendor or GitHub
what the latest release is; they are the only part that leaves the network (public version
lists, nothing about your devices) and stop with [firmware] online = false. Shelly and
Pi-hole compare for themselves, so they need no online lookup from here. A device that
requires a password is left alone.

Never requested: anything that changes a device. In particular Shelly's /ota takes
parameters that start an update, and only the bare path is ever fetched.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
from dataclasses import asdict, dataclass
from typing import Any

import httpx2

from lanwatch import __version__, dnswire
from lanwatch.models import Device, iso, now_utc
from lanwatch.store import Store

log = logging.getLogger(__name__)

MDNS = ("224.0.0.251", 5353)
HA_SERVICE = "_home-assistant._tcp.local"
ESPHOME_SERVICE = "_esphomelib._tcp.local"
HA_LATEST_URL = "https://version.home-assistant.io/stable.json"
SHELLY_GEN1_INDEX = "https://api.shelly.cloud/files/firmware"
GITHUB_LATEST = "https://api.github.com/repos/{repo}/releases/latest"
# GitHub rejects requests without a User-Agent.
ONLINE_HEADERS = {
    "User-Agent": f"lanwatch/{__version__}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


@dataclass(slots=True)
class Firmware:
    product: str
    version: str
    latest: str | None = None
    update: bool | None = None  # None: could not tell
    source: str = ""  # mdns | http
    model: str = ""


def version_key(text: str) -> tuple[int, ...]:
    """The first dotted number in a version string, for comparing: "v16.0.0" -> (16, 0, 0),
    "2026.11.0b1" -> (2026, 11, 0), "20230913-113421/v1.14.0-gcb84623" -> (1, 14, 0)."""
    m = re.search(r"\d+(?:\.\d+)+", text or "")
    return tuple(int(x) for x in m.group().split(".")) if m else ()


def is_older(current: str, latest: str | None) -> bool | None:
    """True when `current` is behind `latest`; None when either cannot be read."""
    a, b = version_key(current), version_key(latest or "")
    return a < b if a and b else None


# -- mDNS ----------------------------------------------------------------------------------


def parse_txt(datagram: bytes) -> dict[str, str]:
    """The key=value pairs of every TXT record in an mDNS response."""
    out: dict[str, str] = {}
    with contextlib.suppress(ValueError):
        r = dnswire.parse_response(datagram)
        for record in (*r.answers, *r.extra):
            if record.rtype != dnswire.TYPE_TXT:
                continue
            for item in record.text.split("\n"):
                key, sep, value = item.partition("=")
                if sep and key:
                    out[key.lower()] = value
    return out


class _Collector(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.datagrams: list[tuple[bytes, str]] = []

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.datagrams.append((data, addr[0]))


async def mdns_txt(
    service: str, bind_ips: list[str], timeout: float = 2.5
) -> dict[str, dict[str, str]]:
    """Ask who offers `service`; return each answering address with its TXT pairs."""
    loop = asyncio.get_running_loop()
    packet = dnswire.build_query(service, dnswire.TYPE_PTR, recursion=False, unicast_reply=True)
    open_: list[tuple[_Collector, asyncio.DatagramTransport]] = []
    for local in bind_ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            sock.bind((local, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            transport, collector = await loop.create_datagram_endpoint(_Collector, sock=sock)
            transport.sendto(packet, MDNS)
        except OSError as e:
            log.debug("mDNS query from %s failed: %s", local, e)
            sock.close()
            continue
        open_.append((collector, transport))
    try:
        await asyncio.sleep(timeout)
    finally:
        for _, transport in open_:
            with contextlib.suppress(Exception):
                transport.close()
    found: dict[str, dict[str, str]] = {}
    for collector, _ in open_:
        for data, responder in collector.datagrams:
            txt = parse_txt(data)
            if txt:
                found.setdefault(responder, {}).update(txt)
    return found


# -- one GET, JSON or nothing ----------------------------------------------------------------


async def _get_json(client: httpx2.AsyncClient, url: str, **kwargs: Any) -> Any:
    """The decoded JSON body of a 200 answer; None for everything else, including a login
    prompt, a redirect, a timeout and a body that is not JSON."""
    try:
        r = await client.get(url, **kwargs)
        return r.json() if r.status_code == 200 else None
    except (httpx2.HTTPError, ValueError):
        return None


# -- local probes: what is this device running? -----------------------------------------------


async def probe_shelly(client: httpx2.AsyncClient, ip: str) -> Firmware | None:
    info = await _get_json(client, f"http://{ip}/shelly")
    if not isinstance(info, dict) or "mac" not in info:
        return None
    if "gen" in info and info.get("ver"):  # Gen2 and later
        fw = Firmware("Shelly", str(info["ver"]), source="http", model=str(info.get("model", "")))
        if not info.get("auth_en"):
            check = await _get_json(client, f"http://{ip}/rpc/Shelly.CheckForUpdate")
            if isinstance(check, dict):  # {} means up to date
                stable = check.get("stable")
                if isinstance(stable, dict) and stable.get("version"):
                    fw.latest, fw.update = str(stable["version"]), True
                else:
                    fw.latest, fw.update = fw.version, False
        return fw
    if info.get("type") and info.get("fw"):  # Gen1
        fw = Firmware("Shelly", str(info["fw"]), source="http", model=str(info["type"]))
        if not info.get("auth"):
            ota = await _get_json(client, f"http://{ip}/ota")  # the bare path only, see above
            if isinstance(ota, dict) and "has_update" in ota:
                fw.update = bool(ota["has_update"])
                fw.latest = str(ota.get("new_version") or fw.version)
        return fw
    return None


async def probe_tasmota(client: httpx2.AsyncClient, ip: str) -> Firmware | None:
    status = await _get_json(client, f"http://{ip}/cm", params={"cmnd": "Status 2"})
    version = status.get("StatusFWR", {}).get("Version") if isinstance(status, dict) else None
    return Firmware("Tasmota", str(version), source="http") if version else None


async def probe_pihole(client: httpx2.AsyncClient, ip: str) -> Firmware | None:
    v5 = await _get_json(client, f"http://{ip}/admin/api.php", params={"versions": ""})
    if isinstance(v5, dict) and v5.get("core_current"):
        latest = str(v5.get("core_latest") or "") or None
        fw = Firmware("Pi-hole", str(v5["core_current"]), latest, source="http")
        fw.update = is_older(fw.version, latest)
        return fw
    v6 = await _get_json(client, f"http://{ip}/api/info/version")  # open only without a password
    core = v6.get("version", {}).get("core", {}) if isinstance(v6, dict) else {}
    local = (core.get("local") or {}).get("version") if isinstance(core, dict) else None
    if local:
        latest = (core.get("remote") or {}).get("version")
        fw = Firmware("Pi-hole", str(local), str(latest) if latest else None, source="http")
        fw.update = is_older(fw.version, fw.latest)
        return fw
    return None


async def probe_jellyfin(client: httpx2.AsyncClient, ip: str) -> Firmware | None:
    info = await _get_json(client, f"http://{ip}:8096/System/Info/Public")
    if not isinstance(info, dict):
        return None
    lowered = {str(k).lower(): v for k, v in info.items()}
    if "jellyfin" not in str(lowered.get("productname", "")).lower() or not lowered.get("version"):
        return None
    return Firmware("Jellyfin", str(lowered["version"]), source="http")


# -- online: what is the latest release? ------------------------------------------------------


class LatestVersions:
    """Vendor answers to "what is the latest release", fetched at most once per run and
    only for products that were actually found on the network."""

    def __init__(self, client: httpx2.AsyncClient | None) -> None:
        self._client = client  # None: online lookups are switched off
        self._cache: dict[str, Any] = {}

    async def _fetch(self, url: str) -> Any:
        if self._client is None:
            return None
        if url not in self._cache:
            self._cache[url] = await _get_json(self._client, url, headers=ONLINE_HEADERS)
            if self._cache[url] is None:
                log.debug("no answer from %s", url)
        return self._cache[url]

    async def home_assistant(self) -> str | None:
        data = await self._fetch(HA_LATEST_URL)
        core = data.get("homeassistant") if isinstance(data, dict) else None
        return str(core["default"]) if isinstance(core, dict) and core.get("default") else None

    async def github(self, repo: str) -> str | None:
        data = await self._fetch(GITHUB_LATEST.format(repo=repo))
        return str(data["tag_name"]) if isinstance(data, dict) and data.get("tag_name") else None

    async def shelly_gen1(self, model: str) -> str | None:
        data = await self._fetch(SHELLY_GEN1_INDEX)
        entry = data.get("data", {}).get(model) if isinstance(data, dict) else None
        return str(entry["version"]) if isinstance(entry, dict) and entry.get("version") else None

    async def fill(self, fw: Firmware) -> None:
        """Add `latest` and `update` where the device did not say itself."""
        if fw.update is not None:
            return
        latest: str | None = None
        if fw.product == "Home Assistant":
            latest = await self.home_assistant()
        elif fw.product == "ESPHome":
            latest = await self.github("esphome/esphome")
        elif fw.product == "Tasmota":
            latest = await self.github("arendst/Tasmota")
        elif fw.product == "Jellyfin":
            latest = await self.github("jellyfin/jellyfin")
        elif fw.product == "Shelly" and fw.model.startswith("SH") and "/" in fw.version:
            latest = await self.shelly_gen1(fw.model)
        if latest:
            fw.latest = latest
            fw.update = is_older(fw.version, latest)


# -- the whole check --------------------------------------------------------------------------


async def check_firmware(
    store: Store,
    bind_ips: list[str],
    *,
    online: bool,
    local_client: httpx2.AsyncClient | None = None,
    online_client: httpx2.AsyncClient | None = None,
    mdns: Any = mdns_txt,
) -> list[tuple[Device, Firmware]]:
    """Find what can be found, store it on the devices, and return it."""
    found: dict[int, Firmware] = {}
    by_ip = {d.ip: d for d in store.devices() if d.ip}

    for service, product in ((HA_SERVICE, "Home Assistant"), (ESPHOME_SERVICE, "ESPHome")):
        for ip, txt in (await mdns(service, bind_ips)).items():
            device = by_ip.get(ip)
            if device is not None and txt.get("version"):
                model = txt.get("board", "") if product == "ESPHome" else ""
                found[device.id] = Firmware(product, txt["version"], source="mdns", model=model)

    own_local = local_client is None
    client = local_client or httpx2.AsyncClient(timeout=3, follow_redirects=False)
    try:
        open_ports = store.open_services()
        for device in by_ip.values():
            if device.id in found or not device.online or not device.ip:
                continue
            ports = {s.port for s in open_ports.get(device.id, []) if s.proto == "tcp"}
            probes = []
            if 80 in ports:
                probes += [probe_shelly, probe_tasmota, probe_pihole]
            if 8096 in ports:
                probes.append(probe_jellyfin)
            for probe in probes:
                fw = await probe(client, device.ip)
                if fw is not None:
                    found[device.id] = fw
                    break
    finally:
        if own_local:
            await client.aclose()

    own_online = online and online_client is None
    lookup_client = (online_client or httpx2.AsyncClient(timeout=10)) if online else None
    try:
        latest = LatestVersions(lookup_client)
        for fw in found.values():
            await latest.fill(fw)
    finally:
        if own_online and lookup_client is not None:
            await lookup_client.aclose()

    results: list[tuple[Device, Firmware]] = []
    checked = iso(now_utc())
    for device_id, fw in found.items():
        device = store.device(device_id)
        if device is None:
            continue
        store.merge_device_attrs(device_id, {"firmware": {**asdict(fw), "checked": checked}})
        results.append((device, fw))
        log.debug(
            "%s: %s %s%s",
            device.label,
            fw.product,
            fw.version,
            f" -> {fw.latest}" if fw.update else "",
        )
    return results
