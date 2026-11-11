"""SNMP audit probe: does a device answer SNMP with well-known default credentials?

lanwatch polls devices with SNMPv3 authPriv only (collectors/snmp.py). This module is the
one place it speaks SNMPv1/v2c, and only to test the defaults everybody knows: a device
that answers `public` or `private` lets anyone on the LAN read it (and `private` is
usually a write community). The only reliable test is to ask; a community table read
over v3 is no proof (an APC card lists `public` as active with SNMPv1 switched off).

What is sent, per device:
  - v1 and v2c: one GET of sysDescr.0 with `public`, then `private`. One try each.
  - When one answered: one more GET with that community, of sysName.0 and sysObjectID.0,
    so the finding says which device it is. Nothing beyond the system group: reading
    more over v1/v2c would be the polling lanwatch refuses.
  - v3: one unauthenticated GET with a user name no agent has. An agent answers
    "unknown user name"; that only tells that an SNMPv3 agent is there (inventory).
  - v3 defaults: one authPriv GET of sysDescr.0 per entry in V3_DEFAULTS.
Never a SET and never a walk. An agent drops a request with an unknown community without
a word, so silence does not prove v1/v2c is off; the result says what was tested.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

BINARY = "snmpget"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
COMMUNITIES = ("public", "private")
VERSIONS = ("1", "2c")
TIMEOUT_S = 2
# Concurrent devices; each has a handful of requests with a short timeout.
PARALLEL = 16
# A user name no real agent has: the v3 presence check must never log in.
PROBE_USER = "lanwatch-audit-probe"


@dataclass(frozen=True, slots=True)
class V3Default:
    """A vendor's documented default SNMPv3 login."""

    vendor: str
    user: str
    auth_protocol: str
    auth_password: str
    priv_protocol: str
    priv_password: str
    source: str  # where the vendor documents it


# Vendor default SNMPv3 users. Every entry needs a cited source (vendor documentation
# that states the default); no guessing beyond this list. Empty until one is confirmed.
V3_DEFAULTS: tuple[V3Default, ...] = ()


@dataclass(slots=True)
class AuditResult:
    ip: str
    # community -> SNMP versions that answered with it, e.g. {"public": ["1", "2c"]}
    communities: dict[str, list[str]] = field(default_factory=dict)
    # True: an SNMPv3 agent answered; False: silence; None: could not tell.
    v3_agent: bool | None = None
    v3_defaults: list[str] = field(default_factory=list)  # "vendor: user" that worked
    # What the device says it is, read with a community that answered.
    sys_descr: str = ""
    sys_name: str = ""
    sys_object_id: str = ""

    def as_dict(self, checked: str) -> dict[str, Any]:
        return {
            "checked": checked,
            "communities": self.communities,
            "v3_agent": self.v3_agent,
            "v3_defaults": self.v3_defaults,
            "sys_descr": self.sys_descr,
            "sys_name": self.sys_name,
            "sys_object_id": self.sys_object_id,
        }


def identity(a: dict[str, Any], label: str = "") -> str:
    """A short "what is it" from a stored result: its sysName (unless the label already
    has it) and the start of its sysDescr. Empty when it said nothing."""
    name = str(a.get("sys_name") or "").strip()
    descr = " ".join(str(a.get("sys_descr") or "").split())
    parts = [p for p in (name if name.lower() not in label.lower() else "", descr) if p]
    text = ", ".join(parts)
    return text if len(text) <= 80 else text[:79] + "…"


@dataclass(slots=True)
class _Answer:
    rc: int
    out: str
    err: str


async def _snmpget(args: list[str], env: dict[str, str]) -> _Answer | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            BINARY,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        return None
    try:
        out, err = await asyncio.wait_for(proc.communicate(), TIMEOUT_S * 3 + 5)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.wait()
        return _Answer(1, "", "Timeout")
    return _Answer(
        proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    )


def _value(out: str) -> str:
    """The value of a `-Oqv` answer, without quotes."""
    return out.strip().strip('"')


def _known(value: str) -> str:
    """A value, or empty for v2c's "No Such Object/Instance" in its place."""
    return "" if value.startswith("No Such ") else value


def _answered(a: _Answer | None) -> bool:
    # An answer for sysDescr (even "No Such Object") means the agent accepted the request.
    return a is not None and a.rc == 0 and bool(a.out.strip())


def _base(timeout: int = TIMEOUT_S) -> list[str]:
    return ["-t", str(timeout), "-r", "0", "-Oqv"]


async def probe(ip: str, env: dict[str, str]) -> AuditResult:
    res = AuditResult(ip=ip)
    for community in COMMUNITIES:
        for version in VERSIONS:
            a = await _snmpget([*_base(), "-v", version, "-c", community, ip, SYS_DESCR], env)
            if _answered(a):
                assert a is not None
                res.communities.setdefault(community, []).append(version)
                res.sys_descr = res.sys_descr or _known(_value(a.out))
    if res.communities:
        community, versions = next(iter(res.communities.items()))
        a = await _snmpget(
            [*_base(), "-On", "-v", versions[-1], "-c", community, ip, SYS_NAME, SYS_OBJECT_ID],
            env,
        )
        if _answered(a):
            assert a is not None
            lines = [_known(_value(x)) for x in a.out.splitlines()]
            if len(lines) == 2:
                res.sys_name, res.sys_object_id = lines[0], lines[1].lstrip(".")
    a = await _snmpget(
        [*_base(), "-v", "3", "-l", "noAuthNoPriv", "-u", PROBE_USER, ip, SYS_DESCR], env
    )
    if a is not None:
        text = (a.err + a.out).lower()
        if "unknown user name" in text or "unknown security name" in text or a.rc == 0:
            res.v3_agent = True
        elif "timeout" in text:
            res.v3_agent = False
    for d in V3_DEFAULTS:
        a = await _snmpget(
            [
                *_base(),
                "-v",
                "3",
                "-l",
                "authPriv",
                "-u",
                d.user,
                "-a",
                d.auth_protocol,
                "-A",
                d.auth_password,
                "-x",
                d.priv_protocol,
                "-X",
                d.priv_password,
                ip,
                SYS_DESCR,
            ],
            env,
        )
        if _answered(a):
            res.v3_defaults.append(f"{d.vendor}: {d.user}")
    return res


async def audit(ips: list[str]) -> list[AuditResult]:
    """Probe every address, a few at a time. An empty config directory keeps the user's
    and the system's snmp.conf (default communities, users) out of it."""
    if not ips:
        return []
    with tempfile.TemporaryDirectory(prefix="lanwatch-snmp-audit-") as tmp:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "SNMPCONFPATH": tmp,
            "SNMP_PERSISTENT_DIR": tmp,
            "MIBS": "",
            "MIBDIRS": "",
        }
        sem = asyncio.Semaphore(PARALLEL)

        async def one(ip: str) -> AuditResult:
            async with sem:
                return await probe(ip, env)

        return list(await asyncio.gather(*(one(ip) for ip in ips)))


def available() -> bool:
    import shutil

    return shutil.which(BINARY) is not None
