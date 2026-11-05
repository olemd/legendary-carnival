"""Just enough of the DNS wire format (RFC 1035) to ask a question and read the answer.

Used for name lookups lanwatch sends itself: DNS to a chosen resolver, LLMNR and mDNS
(both DNS-shaped), and NetBIOS name queries. Standard library only; pulling in a DNS
package for forty lines of packing would be a poor trade.
"""

from __future__ import annotations

import ipaddress
import secrets
import struct
from dataclasses import dataclass, field

TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_AAAA, TYPE_SRV, TYPE_NB = 1, 12, 16, 28, 33, 32
RCODE_OK, RCODE_NXDOMAIN = 0, 3


@dataclass(slots=True)
class Record:
    name: str
    rtype: int
    data: bytes  # raw RDATA
    text: str = ""  # decoded: an address for A/AAAA, a name for PTR, strings for TXT


@dataclass(slots=True)
class Response:
    ident: int
    is_response: bool
    rcode: int
    answers: list[Record] = field(default_factory=list)
    extra: list[Record] = field(default_factory=list)  # authority and additional sections

    def addresses(self) -> list[str]:
        return [r.text for r in self.answers if r.rtype in (TYPE_A, TYPE_AAAA) and r.text]


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna") if label.isascii() is False else label.encode()
        if not 0 < len(raw) < 64:
            raise ValueError(f"bad DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(
    name: str,
    qtype: int = TYPE_A,
    *,
    ident: int | None = None,
    recursion: bool = True,
    unicast_reply: bool = False,
) -> bytes:
    """One question. `unicast_reply` sets mDNS's QU bit: answer me directly, not the group."""
    flags = 0x0100 if recursion else 0
    qclass = 0x8001 if unicast_reply else 0x0001
    header = struct.pack(
        "!HHHHHH", secrets.randbits(16) if ident is None else ident, flags, 1, 0, 0, 0
    )
    return header + encode_name(name) + struct.pack("!HH", qtype, qclass)


def netbios_query(name: str, *, ident: int | None = None) -> bytes:
    """A NetBIOS name query (RFC 1002) for the workstation name, sent to the broadcast
    address. The name is padded to 15 bytes plus a type byte and spread over 32 letters."""
    padded = name.upper().encode("ascii")[:15].ljust(15, b" ") + b"\x00"
    encoded = bytes(b for c in padded for b in (0x41 + (c >> 4), 0x41 + (c & 0x0F)))
    header = struct.pack(
        "!HHHHHH", secrets.randbits(16) if ident is None else ident, 0x0110, 1, 0, 0, 0
    )
    return header + b"\x20" + encoded + b"\x00" + struct.pack("!HH", TYPE_NB, 1)


def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    """A possibly compressed name starting at pos -> (name, position after it)."""
    labels: list[str] = []
    end = -1
    for _ in range(64):  # a pointer loop cannot run away
        if pos >= len(data):
            raise ValueError("truncated name")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("truncated pointer")
            if end < 0:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            continue
        labels.append(data[pos + 1 : pos + 1 + length].decode("utf-8", "replace"))
        pos += 1 + length
    else:
        raise ValueError("name too long or looping")
    return ".".join(labels), (end if end >= 0 else pos)


def _decode(rtype: int, data: bytes, message: bytes, offset: int) -> str:
    try:
        if rtype == TYPE_A and len(data) == 4:
            return str(ipaddress.IPv4Address(data))
        if rtype == TYPE_AAAA and len(data) == 16:
            return str(ipaddress.IPv6Address(data))
        if rtype == TYPE_PTR:
            return _read_name(message, offset)[0]
        if rtype == TYPE_TXT:
            parts, i = [], 0
            while i < len(data):
                n = data[i]
                parts.append(data[i + 1 : i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            return "\n".join(parts)
    except ValueError:
        pass
    return ""


def parse_response(data: bytes) -> Response:
    """Raises ValueError for anything that is not a well-formed DNS message."""
    if len(data) < 12:
        raise ValueError("shorter than a DNS header")
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    out = Response(ident=ident, is_response=bool(flags & 0x8000), rcode=flags & 0x000F)
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(data, pos)
        pos += 4
    for index in range(an + ns + ar):
        name, pos = _read_name(data, pos)
        if pos + 10 > len(data):
            raise ValueError("truncated record")
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
        pos += 10
        rdata = data[pos : pos + rdlen]
        if len(rdata) != rdlen:
            raise ValueError("truncated record data")
        record = Record(name, rtype, rdata, _decode(rtype, rdata, data, pos))
        (out.answers if index < an else out.extra).append(record)
        pos += rdlen
    return out
