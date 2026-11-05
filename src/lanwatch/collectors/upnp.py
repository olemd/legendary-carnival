"""UPnP: SSDP discovery of devices on the segment, and for Internet Gateway Devices the
list of active port mappings (what the router forwards from the internet to the LAN).

Pure Python, unprivileged. SSDP is multicast UDP; the rest is plain HTTP/SOAP."""

from __future__ import annotations

import asyncio
import logging
import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx2

log = logging.getLogger(__name__)

SSDP_GROUP = ("239.255.255.250", 1900)
MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 2\r\n"
    b"ST: ssdp:all\r\n\r\n"
)
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
MAX_MAPPINGS = 200


@dataclass(slots=True)
class SsdpResponse:
    addr: str
    location: str
    st: str = ""
    usn: str = ""
    server: str = ""


@dataclass(slots=True)
class PortMapping:
    external_port: int
    protocol: str
    internal_client: str
    internal_port: int
    description: str = ""
    enabled: bool = True
    remote_host: str = ""
    lease_seconds: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "external_port": self.external_port,
            "protocol": self.protocol,
            "internal_client": self.internal_client,
            "internal_port": self.internal_port,
            "description": self.description,
            "enabled": self.enabled,
            "remote_host": self.remote_host,
            "lease_seconds": self.lease_seconds,
        }


@dataclass(slots=True)
class UpnpDevice:
    addr: str
    location: str
    friendly_name: str = ""
    manufacturer: str = ""
    model: str = ""
    device_type: str = ""
    server: str = ""
    is_igd: bool = False
    control_url: str | None = None
    service_type: str | None = None
    external_ip: str | None = None
    mappings: list[PortMapping] = field(default_factory=list)

    def info(self) -> dict[str, Any]:
        return {
            "friendly_name": self.friendly_name,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "device_type": self.device_type.rsplit(":", 2)[-2]
            if self.device_type.count(":") >= 2
            else self.device_type,
            "server": self.server,
        }


# -- SSDP --------------------------------------------------------------------------


class _SsdpProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.responses: list[SsdpResponse] = []

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        r = parse_ssdp_response(data, addr[0])
        if r is not None:
            self.responses.append(r)


def parse_ssdp_response(data: bytes, addr: str) -> SsdpResponse | None:
    try:
        text = data.decode(errors="replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines or "200" not in lines[0]:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    loc = headers.get("location")
    if not loc:
        return None
    return SsdpResponse(
        addr=addr,
        location=loc,
        st=headers.get("st", ""),
        usn=headers.get("usn", ""),
        server=headers.get("server", ""),
    )


async def ssdp_discover(bind_ip: str = "0.0.0.0", timeout: float = 3.0) -> list[SsdpResponse]:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    if bind_ip != "0.0.0.0":
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
    sock.bind((bind_ip, 0))
    sock.setblocking(False)
    transport, proto = await loop.create_datagram_endpoint(_SsdpProtocol, sock=sock)
    try:
        for _ in range(2):
            transport.sendto(MSEARCH, SSDP_GROUP)
            await asyncio.sleep(0.3)
        await asyncio.sleep(timeout)
    finally:
        transport.close()
    seen: set[str] = set()
    out: list[SsdpResponse] = []
    for r in proto.responses:
        if r.location not in seen:
            seen.add(r.location)
            out.append(r)
    return out


# -- device description ----------------------------------------------------------------


def _strip(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def _find(el: ET.Element, name: str) -> ET.Element | None:
    for child in el.iter():
        if _strip(child.tag) == name:
            return child
    return None


def parse_device_description(xml_text: str, location: str, addr: str) -> UpnpDevice:
    root = ET.fromstring(xml_text)
    base = _text(_find(root, "URLBase")) or location
    dev_el = _find(root, "device")
    d = UpnpDevice(addr=addr, location=location)
    if dev_el is None:
        return d
    d.friendly_name = _text(_find(dev_el, "friendlyName"))[:80]
    d.manufacturer = _text(_find(dev_el, "manufacturer"))[:80]
    d.model = (
        _text(_find(dev_el, "modelName")) + " " + _text(_find(dev_el, "modelNumber"))
    ).strip()[:80]
    d.device_type = _text(_find(dev_el, "deviceType"))
    d.is_igd = "InternetGatewayDevice" in d.device_type
    for svc in dev_el.iter():
        if _strip(svc.tag) != "service":
            continue
        st = _text(_find(svc, "serviceType"))
        if any(w in st for w in WAN_SERVICES):
            d.service_type = st
            d.control_url = urljoin(base, _text(_find(svc, "controlURL")))
            d.is_igd = True
            break
    return d


# -- SOAP ---------------------------------------------------------------------------


def _soap(action: str, service_type: str, args: dict[str, str]) -> tuple[str, dict[str, str]]:
    body_args = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:{action} xmlns:u="{service_type}">{body_args}</u:{action}>'
        "</s:Body></s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#{action}"',
    }
    return envelope, headers


def parse_mapping_response(xml_text: str) -> PortMapping | None:
    root = ET.fromstring(xml_text)
    vals = {_strip(el.tag): (el.text or "").strip() for el in root.iter()}
    if "NewExternalPort" not in vals:
        return None
    try:
        return PortMapping(
            external_port=int(vals.get("NewExternalPort", "0")),
            protocol=vals.get("NewProtocol", ""),
            internal_client=vals.get("NewInternalClient", ""),
            internal_port=int(vals.get("NewInternalPort", "0") or 0),
            description=vals.get("NewPortMappingDescription", "")[:80],
            enabled=vals.get("NewEnabled", "1") == "1",
            remote_host=vals.get("NewRemoteHost", ""),
            lease_seconds=int(vals.get("NewLeaseDuration", "0") or 0),
        )
    except ValueError:
        return None


async def fetch_mappings(client: httpx2.AsyncClient, d: UpnpDevice) -> None:
    if not d.control_url or not d.service_type:
        return
    body, headers = _soap("GetExternalIPAddress", d.service_type, {})
    try:
        r = await client.post(d.control_url, content=body, headers=headers)
        if r.is_success:
            d.external_ip = _text(_find(ET.fromstring(r.text), "NewExternalIPAddress")) or None
    except (httpx2.HTTPError, ET.ParseError):
        pass
    for index in range(MAX_MAPPINGS):
        body, headers = _soap(
            "GetGenericPortMappingEntry", d.service_type, {"NewPortMappingIndex": str(index)}
        )
        try:
            r = await client.post(d.control_url, content=body, headers=headers)
        except httpx2.HTTPError as e:
            log.debug("upnp mapping query failed at %d: %s", index, e)
            break
        if not r.is_success:
            break  # 500 with error 713 = end of list
        try:
            m = parse_mapping_response(r.text)
        except ET.ParseError:
            break
        if m is None:
            break
        d.mappings.append(m)


async def discover_upnp(bind_ips: list[str], timeout: float = 3.0) -> list[UpnpDevice]:
    """SSDP on each interface, fetch descriptions, enumerate IGD port mappings."""
    responses: dict[str, SsdpResponse] = {}
    for ip in bind_ips or ["0.0.0.0"]:
        try:
            for r in await ssdp_discover(ip, timeout):
                responses.setdefault(r.location, r)
        except OSError as e:
            log.warning("ssdp on %s failed: %s", ip, e)
    devices: list[UpnpDevice] = []
    async with httpx2.AsyncClient(timeout=5, follow_redirects=False) as client:
        for r in responses.values():
            host = urlparse(r.location).hostname or r.addr
            try:
                resp = await client.get(r.location)
                resp.raise_for_status()
                d = parse_device_description(resp.text, r.location, host)
            except (httpx2.HTTPError, ET.ParseError) as e:
                log.debug("upnp description %s failed: %s", r.location, e)
                d = UpnpDevice(addr=host, location=r.location)
            d.server = r.server[:80]
            if d.is_igd:
                await fetch_mappings(client, d)
            devices.append(d)
    return devices
