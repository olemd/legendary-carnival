"""Read-only link to Ubiquiti airMAX radios (airOS 6 and 8) through their local web API.

The radios have no read-only API key, but they have a read-only web account (System ->
Read-Only Account). lanwatch logs in with that account, reads two JSON pages, status.cgi
(the radio itself and its wireless settings) and sta.cgi (the stations it is linked with,
including what the far end reports), and logs out again. Nothing else is requested, and
the account could not change anything if it were.

Two things make this more careful than a plain HTTPS client:

- **Certificate pinning.** airOS serves a self-signed certificate, so there is nothing to
  verify it against. lanwatch takes the certificate it sees on first contact and from then
  on lets TLS accept only that exact certificate, on every connection, before the password
  is sent. A changed certificate stops the read: either the radio was reset or replaced,
  or something sits between lanwatch and the radio. `lanwatch airos --accept-cert HOST`
  accepts a new one. The certificates have 1024-bit RSA keys, which OpenSSL 3 refuses by
  default; the security level is lowered for this one pinned certificate only.

- **One login attempt.** airOS 6.3.14 and later lock the account after three failed
  logins. Anything but a clear success after the password is sent counts as a rejection:
  lanwatch then remembers that these credentials failed (as a salted hash, not the
  password) and does not try that radio again until the password in the config changes.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
import secrets
import ssl
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx2

from lanwatch import __version__
from lanwatch.config import AirosConfig

PORT = 443
# Rounds of PBKDF2 for the remembered "these credentials failed" tag. It is checked once
# per radio per round, so it can afford to be slow for anyone trying to reverse it.
TAG_ROUNDS = 200_000


class AirosError(Exception):
    """The radio could not be read: no answer, an unexpected reply."""


class AirosAuthError(AirosError):
    """The radio did not accept the login. Never retried with the same credentials."""


class AirosPinError(AirosError):
    """The radio presented another certificate than the one pinned on first contact."""


@dataclass(slots=True)
class AirosInterface:
    name: str
    mac: str | None
    speed: int | None  # Mbit/s; None when down or not a wired port
    full_duplex: bool | None
    plugged: bool


@dataclass(slots=True)
class AirosStation:
    """One radio this one is linked with, as both ends see it."""

    mac: str | None
    name: str
    ip: str | None
    signal: int | None  # dBm
    noise: int | None  # dBm
    ccq: int | None  # percent
    tx_mbps: float | None
    rx_mbps: float | None
    uptime_s: int | None
    airmax_quality: int | None  # percent
    airmax_capacity: int | None  # percent
    remote_hostname: str | None
    remote_model: str | None
    remote_version: str | None
    remote_signal: int | None
    remote_noise: int | None


@dataclass(slots=True)
class AirosStatus:
    host: str
    hostname: str
    model: str
    firmware: str
    uptime_s: int
    netrole: str  # bridge | router
    mode: str  # ap | sta (and the -ptp / -ptmp variants on airOS 8)
    essid: str
    frequency_mhz: int | None
    channel_width_mhz: int | None
    signal: int | None
    noise: int | None
    ccq: int | None  # percent
    tx_power: int | None  # dBm
    security: str
    ap_mac: str | None
    airmax_quality: int | None
    airmax_capacity: int | None
    interfaces: list[AirosInterface] = field(default_factory=list)
    stations: list[AirosStation] = field(default_factory=list)
    # The firmware family Ubiquiti publishes releases under: XM, XW (airOS 6), XC, WA (8).
    platform: str = ""

    @property
    def mac(self) -> str | None:
        """The radio's own address on the LAN: its bridge, else its wireless interface."""
        for name in ("br0", "ath0", "wlan0"):
            for i in self.interfaces:
                if i.name == name and i.mac:
                    return i.mac
        return None

    @property
    def ethernet(self) -> AirosInterface | None:
        return next((i for i in self.interfaces if i.name in ("eth0", "eth1") and i.plugged), None)

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "mac": self.mac}


# -- parsing --------------------------------------------------------------------------------


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int | float):
        return int(v)
    if isinstance(v, str):
        digits = "".join(c for c in v.strip().split(" ")[0] if c.isdigit() or c == "-")
        try:
            return int(digits)
        except ValueError:
            return None
    return None


def _float(v: Any) -> float | None:
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else None


def _text(v: Any, limit: int = 120) -> str:
    return str(v).strip()[:limit] if isinstance(v, str | int | float) else ""


def _mac(v: Any) -> str | None:
    text = _text(v).lower()
    parts = text.split(":")
    if len(parts) == 6 and all(len(p) == 2 for p in parts) and text != "00:00:00:00:00:00":
        return text
    return None


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def parse_station(data: Any) -> AirosStation | None:
    d = _dict(data)
    if not d:
        return None
    airmax, remote = _dict(d.get("airmax")), _dict(d.get("remote"))
    return AirosStation(
        mac=_mac(d.get("mac")),
        name=_text(d.get("name")),
        ip=_text(d.get("lastip")) or None,
        signal=_int(d.get("signal")),
        noise=_int(d.get("noisefloor")),
        ccq=_int(d.get("ccq")),
        tx_mbps=_float(d.get("tx")),
        rx_mbps=_float(d.get("rx")),
        uptime_s=_int(d.get("uptime")),
        airmax_quality=_int(airmax.get("quality")),
        airmax_capacity=_int(airmax.get("capacity")),
        remote_hostname=_text(remote.get("hostname")) or None,
        remote_model=_text(remote.get("platform")) or None,
        remote_version=_text(remote.get("version")) or None,
        remote_signal=_int(remote.get("signal")),
        remote_noise=_int(remote.get("noisefloor")),
    )


def parse_status(host: str, status: Any, stations: Any) -> AirosStatus:
    """status.cgi and sta.cgi as airOS 6 (XM/XW) and 8 (XC) return them."""
    s = _dict(status)
    h, w = _dict(s.get("host")), _dict(s.get("wireless"))
    if not h or not w:
        raise AirosError("status.cgi has no host or wireless section; not an airOS radio?")
    polling = _dict(w.get("polling"))
    prefix = _text(h.get("fwprefix"))
    quality, capacity = _int(polling.get("quality")), _int(polling.get("capacity"))
    ccq = _int(w.get("ccq"))
    interfaces = []
    for i in s.get("interfaces") or []:
        i = _dict(i)
        st = _dict(i.get("status"))
        name = _text(i.get("ifname"))
        if not name or name == "lo":
            continue
        speed = _int(st.get("speed"))
        duplex = _int(st.get("duplex"))  # 1 full, 0 half, 255 not applicable
        interfaces.append(
            AirosInterface(
                name=name,
                mac=_mac(i.get("hwaddr")),
                speed=speed or None,
                full_duplex={0: False, 1: True}.get(duplex) if duplex is not None else None,
                plugged=bool(_int(st.get("plugged"))),
            )
        )
    return AirosStatus(
        host=host,
        hostname=_text(h.get("hostname")),
        model=_text(h.get("devmodel")),
        firmware=_text(h.get("fwversion")),
        uptime_s=_int(h.get("uptime")) or 0,
        netrole=_text(h.get("netrole")),
        mode=_text(w.get("mode")),
        essid=_text(w.get("essid")),
        frequency_mhz=_int(w.get("frequency")),
        channel_width_mhz=_int(w.get("chwidth") or w.get("chanbw")),
        signal=_int(w.get("signal")),
        noise=_int(w.get("noisef")),
        # airOS 6 reports CCQ in tenths of a percent here, and in percent in sta.cgi.
        ccq=round(ccq / 10) if ccq is not None and ccq > 100 else ccq,
        tx_power=_int(w.get("txpower")),
        security=_text(w.get("security")),
        ap_mac=_mac(w.get("apmac")),
        airmax_quality=quality,
        airmax_capacity=capacity,
        interfaces=interfaces,
        platform=prefix if re.fullmatch(r"[A-Z0-9]{1,8}", prefix) else "",
        stations=[
            _with_link_airmax(x, quality, capacity)
            for x in map(parse_station, stations if isinstance(stations, list) else [])
            if x is not None
        ],
    )


def _with_link_airmax(st: AirosStation, quality: int | None, capacity: int | None) -> AirosStation:
    """A station radio lists its access point with airMAX quality and capacity 0 (only the
    AP measures them per station); its own status.cgi has the figures for its one link."""
    if not st.airmax_quality and quality:
        st.airmax_quality, st.airmax_capacity = quality, capacity
    return st


# -- credentials that failed ------------------------------------------------------------------


def credentials_tag(username: str, password: str, salt: str | None = None) -> str:
    """'salt$hash' for remembering that a username/password pair was rejected without
    keeping the password: the same pair gives the same tag under the same salt."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", f"{username}\0{password}".encode(), bytes.fromhex(salt), TAG_ROUNDS
    )
    return f"{salt}${digest.hex()}"


def same_credentials(tag: str, username: str, password: str) -> bool:
    salt, sep, _ = tag.partition("$")
    if not sep:
        return False
    try:
        return secrets.compare_digest(credentials_tag(username, password, salt), tag)
    except ValueError:
        return False


# -- TLS ------------------------------------------------------------------------------------


def _weak_ok(ctx: ssl.SSLContext) -> ssl.SSLContext:
    # airOS certificates have 1024-bit RSA keys; OpenSSL's default level refuses them.
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


def pinned_context(pem: str) -> ssl.SSLContext:
    """TLS that accepts exactly this self-signed certificate and nothing else. The host
    name is not checked: airOS names its certificate after its MAC, not its address."""
    ctx = ssl.create_default_context(cadata=pem)
    ctx.check_hostname = False
    return _weak_ok(ctx)


async def fetch_certificate(host: str, timeout: float, port: int = PORT) -> str:
    """The certificate the radio presents, as PEM, for pinning on first contact."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_weak_ok(ctx)), timeout
        )
    except (OSError, TimeoutError, ssl.SSLError) as e:
        raise AirosError(f"no TLS connection to {host}:{port}: {e}") from e
    try:
        obj = writer.get_extra_info("ssl_object")
        der = obj.getpeercert(binary_form=True) if obj is not None else None
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
    if not der:
        raise AirosError(f"{host} presented no certificate")
    return ssl.DER_cert_to_PEM_cert(der)


def fingerprint(pem: str) -> str:
    """SHA-256 of the certificate, as shown next to it in a browser."""
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


# -- HTTP -----------------------------------------------------------------------------------


def make_client(host: str, pem: str, timeout: float) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        base_url=f"https://{host}",
        verify=pinned_context(pem),
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": f"lanwatch/{__version__}"},
        # A proxy from the environment must never sit between us and a LAN radio.
        trust_env=False,
    )


def _json(r: httpx2.Response, page: str) -> Any:
    # Judged by the body: airOS 6 sends sta.cgi as JSON under a text/html content type.
    # A session that ran out answers 302 to the login page.
    if r.status_code != 200:
        raise AirosError(f"{page}: HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as e:
        raise AirosError(f"{page}: not JSON") from e


async def read_radio(cfg: AirosConfig, client: httpx2.AsyncClient, host: str) -> AirosStatus:
    """Log in once, read status.cgi and sta.cgi, log out. Raises AirosAuthError when the
    login was not clearly accepted, AirosPinError when TLS refused the certificate."""
    try:
        # The login page sets the session cookie the login form is checked against.
        await client.get("/login.cgi")
        r = await client.post(
            "/login.cgi",
            files={
                "uri": (None, "/status.cgi"),
                "username": (None, cfg.username),
                "password": (None, cfg.password),
            },
        )
        # Success is a redirect to the page asked for. Anything else after the password
        # was sent counts as a rejection, so an unfamiliar reply can never add up to the
        # three failures that lock the account.
        if r.status_code != 302 or not r.headers.get("location", "").endswith("/status.cgi"):
            hint = " (Invalid credentials)" if "Invalid credentials" in r.text else ""
            raise AirosAuthError(
                f"login not accepted: HTTP {r.status_code}{hint}; lanwatch will not try "
                "again until airos.password (or username) changes"
            )
        status = _json(await client.get("/status.cgi"), "status.cgi")
        stations = _json(await client.get("/sta.cgi"), "sta.cgi")
        with contextlib.suppress(httpx2.HTTPError):  # the session times out by itself
            await client.get("/logout.cgi")
    except httpx2.ConnectError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            raise AirosPinError(
                f"{host} presents another TLS certificate than the one lanwatch pinned: the "
                "radio was reset or replaced, or something is in between. Check, then run "
                f"`lanwatch airos --accept-cert {host}`"
            ) from e
        raise AirosError(f"{host}: {e}") from e
    except httpx2.HTTPError as e:
        raise AirosError(f"{host}: {type(e).__name__}: {e}") from e
    return parse_status(host, status, stations)


# -- link history -----------------------------------------------------------------------------

# A link's normal is an exponential moving average over about a day of reads (one per
# infra round, 15 minutes by default), learned for half a day before anything is judged
# against it. While the link is worse than normal the average is not updated, so a
# lasting fault stays a fault instead of becoming the new normal.
BASELINE_ALPHA = 1 / 96
BASELINE_WARMUP = 48
DEGRADED_SIGNAL_DB = 6
DEGRADED_CCQ_POINTS = 20
POOR_CCQ = 60
# A station missing from a read (the link dropped, the far end restarted) keeps what was
# learned about it for about a week of reads. A link that comes back worse is then judged
# against its old normal instead of teaching lanwatch a new one.
LINK_MEMORY_READS = 96 * 7


def track_links(previous: dict[str, Any] | None, radio: AirosStatus) -> dict[str, Any]:
    """Counters the link rules read, carried from one read of the radio to the next:
    reads in a row without a link, and per station its learned normal and how many reads
    in a row it was below that normal, or below POOR_CCQ. A station that is not linked in
    this read keeps its entry untouched, with a count of the reads it was away."""
    prev = _dict(previous)
    prev_links = _dict(prev.get("links"))
    links: dict[str, Any] = {}
    for st in radio.stations:
        if not st.mac or st.signal is None or st.ccq is None:
            continue
        p = _dict(prev_links.get(st.mac))
        reads = int(p.get("reads") or 0)
        signal_n, ccq_n = p.get("normal_signal"), p.get("normal_ccq")
        degraded = (
            reads >= BASELINE_WARMUP
            and isinstance(signal_n, int | float)
            and isinstance(ccq_n, int | float)
            and (st.signal < signal_n - DEGRADED_SIGNAL_DB or st.ccq < ccq_n - DEGRADED_CCQ_POINTS)
        )
        if not degraded:
            signal_n = (
                float(st.signal)
                if not isinstance(signal_n, int | float)
                else signal_n + BASELINE_ALPHA * (st.signal - signal_n)
            )
            ccq_n = (
                float(st.ccq)
                if not isinstance(ccq_n, int | float)
                else ccq_n + BASELINE_ALPHA * (st.ccq - ccq_n)
            )
            reads += 1
        links[st.mac] = {
            "reads": reads,
            "normal_signal": signal_n,
            "normal_ccq": ccq_n,
            "degraded_reads": int(p.get("degraded_reads") or 0) + 1 if degraded else 0,
            "poor_reads": int(p.get("poor_reads") or 0) + 1 if st.ccq < POOR_CCQ else 0,
        }
    for mac, p in prev_links.items():
        absent = int(_dict(p).get("absent_reads") or 0) + 1
        if mac not in links and absent <= LINK_MEMORY_READS:
            links[mac] = {**_dict(p), "absent_reads": absent}
    return {
        "no_link_reads": int(prev.get("no_link_reads") or 0) + 1 if not radio.stations else 0,
        "links": links,
    }
