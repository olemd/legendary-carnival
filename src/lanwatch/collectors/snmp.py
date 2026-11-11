"""Read-only SNMPv3 queries to the router, through net-snmp's snmpbulkwalk.

Only SNMPv3 with authentication and encryption (authPriv): see SnmpConfig for why. The
credentials never appear on a command line, where any local user could read them in the
process list: each call writes them to a snmp.conf in a private temporary directory and
points net-snmp at it with SNMPCONFPATH. The same directory takes net-snmp's persistent
state (engine boots, cached keys), so nothing is left behind in the service's home.

Output is requested in a form that parses without MIB files: numeric OIDs (-On), every
octet string as hex (-Ox, so a MAC address whose bytes happen to be printable is not
shown as text), enums as numbers (-Oe) and timeticks as a plain count (-Ot).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from lanwatch.config import SnmpDeviceConfig

log = logging.getLogger(__name__)

BINARY = "snmpbulkwalk"
MAX_REPETITIONS = 25
# A walk of a large table (a busy ARP table) is many round trips; this bounds one walk.
WALK_TIMEOUT_S = 60

SYSTEM = "1.3.6.1.2.1.1"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# IP-MIB neighbour table (ARP and IPv6 neighbours), and the older IPv4-only one for agents
# that only have that. Type 2 is invalid in both; ipNetToPhysical adds 5, the router's own
# addresses. 4 is static in both.
NET_TO_PHYSICAL_MAC = "1.3.6.1.2.1.4.35.1.4"
NET_TO_PHYSICAL_TYPE = "1.3.6.1.2.1.4.35.1.6"
NET_TO_MEDIA_MAC = "1.3.6.1.2.1.4.22.1.2"
NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"
NEIGH_INVALID, NEIGH_STATIC, NEIGH_LOCAL = 2, 4, 5
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
# The router's own interface MACs. Some agents (Junos) list the router's own addresses
# as static entries instead of type 5, so these are what tells them apart.
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
# JUNIPER-JDHCP-MIB jnxJdhcpLocalServerBindingsTable, indexed by the client's IPv4 address.
# Columns: 2 MAC, 3 state, 4 lease expiry, 6 lease start (both "YYYY-MM-DD hh:mm:ss TZ").
JNX_DHCP_BINDINGS = "1.3.6.1.4.1.2636.3.61.61.1.2.1.1"

# IANA enterprise numbers, the first arc after 1.3.6.1.4.1 in sysObjectID.
VENDORS = {
    "9": "Cisco",
    "318": "APC",
    "2011": "Huawei",
    "2636": "Juniper",
    "4413": "Broadcom",
    "8072": "net-snmp",
    "12356": "Fortinet",
    "14988": "MikroTik",
    "25461": "Palo Alto Networks",
    "41112": "Ubiquiti",
}

Value = int | str | bytes


class SnmpError(Exception):
    """The router could not be read: no answer, wrong credentials, or no snmpbulkwalk."""


@dataclass(slots=True)
class SystemInfo:
    descr: str
    object_id: str
    uptime_s: float
    name: str
    location: str
    contact: str

    @property
    def vendor(self) -> str | None:
        m = re.match(r"\.?1\.3\.6\.1\.4\.1\.(\d+)", self.object_id)
        return VENDORS.get(m.group(1)) if m else None

    def as_dict(self) -> dict[str, object]:
        return {
            "descr": self.descr,
            "object_id": self.object_id,
            "vendor": self.vendor,
            "uptime_s": self.uptime_s,
            "name": self.name,
            "location": self.location,
            "contact": self.contact,
        }


@dataclass(slots=True)
class Neighbour:
    """One entry of the router's ARP (or IPv6 neighbour) table."""

    ip: str
    mac: str
    interface: str | None
    static: bool

    def as_dict(self) -> dict[str, object]:
        return {"ip": self.ip, "mac": self.mac, "interface": self.interface, "static": self.static}


@dataclass(slots=True)
class DhcpLease:
    """A lease the router's own DHCP server has handed out. Times are as the router
    prints them, in its local time zone."""

    ip: str
    mac: str
    since: str | None
    expires: str | None

    def as_dict(self) -> dict[str, object]:
        return {"ip": self.ip, "mac": self.mac, "since": self.since, "expires": self.expires}


def conf_text(cfg: SnmpDeviceConfig) -> str:
    """snmp.conf for one session. The config validator keeps the values free of the
    whitespace and '#' that would end them early."""
    return (
        "defVersion 3\n"
        "defSecurityLevel authPriv\n"
        f"defSecurityName {cfg.user}\n"
        f"defAuthType {cfg.auth_protocol}\n"
        f"defAuthPassphrase {cfg.auth_password}\n"
        f"defPrivType {cfg.priv_protocol}\n"
        f"defPrivPassphrase {cfg.priv_password}\n"
    )


def walk_args(host: str, oid: str, timeout_s: int) -> list[str]:
    target = f"udp6:[{host}]" if _is_ipv6(host) else host
    return [
        BINARY,
        "-On",
        "-Ox",
        "-Oe",
        "-Ot",
        "-t",
        str(timeout_s),
        "-r",
        "1",
        f"-Cr{MAX_REPETITIONS}",
        target,
        oid,
    ]


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


_START = re.compile(r"^\.?(\d+(?:\.\d+)+) = ?(.*)$")
_NO_VALUE = ("No Such Object", "No Such Instance", "No more variables")


def parse_walk(text: str) -> dict[str, Value]:
    """snmpbulkwalk output (-On -Ox -Oe -Ot) -> {oid without leading dot: value}.

    Octet strings come back as bytes, numbers as int, OIDs and IP addresses as str. A hex
    string longer than 16 bytes continues on the following lines."""
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        m = _START.match(line)
        if m:
            rows.append((m.group(1), m.group(2)))
        elif rows and re.fullmatch(r"[0-9A-Fa-f ]+", line.strip() or "x"):
            oid, raw = rows[-1]
            rows[-1] = (oid, f"{raw} {line.strip()}")
    out: dict[str, Value] = {}
    for oid, raw in rows:
        value = _value(raw.strip())
        if value is not None:
            out[oid] = value
    return out


def _value(raw: str) -> Value | None:
    if raw.startswith(_NO_VALUE):
        return None
    if raw == '""':
        return b""
    typ, sep, rest = raw.partition(": ")
    if not sep:
        # -Ot prints timeticks without a type; anything else untyped is kept as text.
        return int(raw) if raw.isdigit() else raw
    if typ == "Hex-STRING":
        return bytes.fromhex(rest.replace(" ", ""))
    if typ == "STRING":
        return rest.strip('"').encode()
    if typ in ("INTEGER", "Gauge32", "Counter32", "Counter64", "Unsigned32", "Timeticks"):
        num = re.match(r"-?\d+", rest)
        return int(num.group()) if num else None
    if typ == "OID":
        return rest.lstrip(".")
    if typ == "IpAddress":
        return rest
    return rest


def text(v: Value | None) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace").strip("\x00").strip()
    return "" if v is None else str(v)


def mac(v: Value | None) -> str | None:
    """A 6-byte octet string as aa:bb:cc:dd:ee:ff, else None."""
    if isinstance(v, bytes) and len(v) == 6 and any(v):
        return ":".join(f"{b:02x}" for b in v)
    return None


def parse_system(values: dict[str, Value]) -> SystemInfo:
    if SYS_OBJECT_ID not in values and SYS_DESCR not in values:
        raise SnmpError("the router answered, but without its system group (MIB view?)")
    uptime = values.get(SYS_UPTIME)
    return SystemInfo(
        descr=text(values.get(SYS_DESCR)),
        object_id=text(values.get(SYS_OBJECT_ID)),
        uptime_s=uptime / 100 if isinstance(uptime, int) else 0.0,
        name=text(values.get(SYS_NAME)),
        location=text(values.get(SYS_LOCATION)),
        contact=text(values.get(SYS_CONTACT)),
    )


def _suffix(oid: str, prefix: str) -> list[str] | None:
    if not oid.startswith(prefix + "."):
        return None
    return oid[len(prefix) + 1 :].split(".")


def _address(parts: list[str]) -> str | None:
    """An InetAddressType.length.bytes index as an address; None for anything else."""
    try:
        kind, length, raw = int(parts[0]), int(parts[1]), bytes(int(p) for p in parts[2:])
        if kind == 1 and length == 4 == len(raw):
            return str(ipaddress.IPv4Address(raw))
        if kind == 2 and length == 16 == len(raw):
            return str(ipaddress.IPv6Address(raw))
    except (ValueError, IndexError):
        return None
    return None


def parse_neighbours(
    macs: dict[str, Value],
    types: dict[str, Value],
    if_names: dict[str, Value],
    own: dict[str, Value] | None = None,
) -> list[Neighbour]:
    """ipNetToPhysical (index ifIndex.type.length.address) or, when the agent only has
    that, ipNetToMedia (index ifIndex.a.b.c.d). The router's own addresses (type 5, or
    any entry with one of its interface MACs in `own`) and invalid entries are left out."""
    own_macs = {m for v in (own or {}).values() if (m := mac(v))}
    out: list[Neighbour] = []
    for oid, value in macs.items():
        hw = mac(value)
        if hw is None or hw in own_macs:
            continue
        if (parts := _suffix(oid, NET_TO_PHYSICAL_MAC)) is not None:
            ip = _address(parts[1:])
            kind = types.get(f"{NET_TO_PHYSICAL_TYPE}.{'.'.join(parts)}")
        elif (parts := _suffix(oid, NET_TO_MEDIA_MAC)) is not None and len(parts) == 5:
            ip = ".".join(parts[1:])
            kind = types.get(f"{NET_TO_MEDIA_TYPE}.{'.'.join(parts)}")
        else:
            continue
        if ip is None or kind in (NEIGH_INVALID, NEIGH_LOCAL):
            continue
        name = text(if_names.get(f"{IF_NAME}.{parts[0]}")) or None
        out.append(Neighbour(ip=ip, mac=hw, interface=name, static=kind == NEIGH_STATIC))
    return sorted(out, key=lambda n: (n.interface or "", _sort_key(n.ip)))


def parse_juniper_leases(values: dict[str, Value]) -> list[DhcpLease]:
    out: list[DhcpLease] = []
    for oid, value in values.items():
        parts = _suffix(oid, JNX_DHCP_BINDINGS)
        if parts is None or parts[0] != "2" or len(parts) != 5:
            continue
        hw = mac(value)
        if hw is None:
            continue
        ip = ".".join(parts[1:])

        def col(n: int, ip: str = ip) -> str | None:
            return text(values.get(f"{JNX_DHCP_BINDINGS}.{n}.{ip}")) or None

        out.append(DhcpLease(ip=ip, mac=hw, since=col(6), expires=col(4)))
    return sorted(out, key=lambda lease: _sort_key(lease.ip))


def _sort_key(ip: str) -> tuple[int, int]:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return (9, 0)
    return (a.version, int(a))


def explain(rc: int, stderr: str) -> str:
    """net-snmp's message, shortened and with the usual causes named."""
    # net-snmp announces each state directory it creates in the fresh temporary directory.
    lines = [ln for ln in stderr.splitlines() if not ln.startswith("Created directory:")]
    msg = " ".join(" ".join(lines).split())[:300] or f"{BINARY} exited with {rc}"
    low = msg.lower()
    if "timeout" in low:
        return (
            f"{msg} (no answer: wrong address, SNMP off, a firewall, or credentials the"
            " agent drops without a reply)"
        )
    if "unknown user" in low:
        return f"{msg} (the router has no SNMPv3 user by that name)"
    if "authentication failure" in low or "wrong digest" in low:
        return f"{msg} (auth_protocol or auth_password does not match the router)"
    if "decryption error" in low:
        return f"{msg} (priv_protocol or priv_password does not match the router)"
    return msg


class SnmpClient:
    """Walks against one host. Use as an async context manager: the private config
    directory lives as long as the client."""

    def __init__(self, cfg: SnmpDeviceConfig, host: str) -> None:
        self.cfg = cfg
        self.host = host
        self._dir: tempfile.TemporaryDirectory[str] | None = None

    async def __aenter__(self) -> SnmpClient:
        self._dir = tempfile.TemporaryDirectory(prefix="lanwatch-snmp-")
        path = Path(self._dir.name) / "snmp.conf"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(conf_text(self.cfg))
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _env(self) -> dict[str, str]:
        assert self._dir is not None, "use SnmpClient as an async context manager"
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "SNMPCONFPATH": self._dir.name,
            "SNMP_PERSISTENT_DIR": self._dir.name,
            # No MIB files: output is numeric anyway, and loading them only adds noise.
            "MIBS": "",
            "MIBDIRS": "",
        }

    async def walk(self, oid: str) -> dict[str, Value]:
        args = walk_args(self.host, oid, self.cfg.timeout_s)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._env(),
            )
        except FileNotFoundError as e:
            raise SnmpError(f"{BINARY} not found: install the snmp package") from e
        try:
            out, err = await asyncio.wait_for(proc.communicate(), WALK_TIMEOUT_S)
        except TimeoutError as e:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            raise SnmpError(f"walk of {oid} took longer than {WALK_TIMEOUT_S}s") from e
        stderr = err.decode("utf-8", "replace")
        if proc.returncode != 0:
            raise SnmpError(explain(proc.returncode or 0, stderr))
        log.debug("snmp: %s %s: %d bytes", self.host, oid, len(out))
        return parse_walk(out.decode("utf-8", "replace"))

    async def system(self) -> SystemInfo:
        return parse_system(await self.walk(SYSTEM))

    async def neighbours(self) -> list[Neighbour]:
        macs = await self.walk(NET_TO_PHYSICAL_MAC)
        if macs:
            types = await self.walk(NET_TO_PHYSICAL_TYPE)
        else:
            macs = await self.walk(NET_TO_MEDIA_MAC)
            types = await self.walk(NET_TO_MEDIA_TYPE) if macs else {}
        if_names = await self.walk(IF_NAME) if macs else {}
        own = await self.walk(IF_PHYS_ADDRESS) if macs else {}
        return parse_neighbours(macs, types, if_names, own)

    async def juniper_leases(self) -> list[DhcpLease]:
        return parse_juniper_leases(await self.walk(JNX_DHCP_BINDINGS))
