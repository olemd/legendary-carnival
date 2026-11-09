"""MAC vendor lookup from the IEEE registry.

arp-scan and nmap name the vendor behind a MAC from the IEEE OUI lists they ship, and those
age with the package: Debian's arp-scan 1.10.0 carries a list from March 2024, so every
prefix assigned since (e4:65:b8 is Espressif, for one) comes back "(Unknown)". This module
names the hosts the discovery backend could not, from a fresher copy of the registry.

Sources, longest prefix wins (MA-S, 36 bit, over MA-M, 28 bit, over MA-L, 24 bit):

  1. The registry downloaded by the weekly "oui" job into <data_dir>/oui/: the MA-L, MA-M
     and MA-S CSV files published at standards-oui.ieee.org. The download is the one thing
     this module sends off the LAN (a public list, nothing about your devices); it stops
     with [oui] online = false.
  2. Otherwise nmap's nmap-mac-prefixes, which Debian refreshes with each nmap release and
     which is already installed (nmap is a dependency).

A downloaded file replaces the previous copy only after it parsed as the registry, so a
captive portal or an outage never leaves lanwatch with an empty list.
"""

from __future__ import annotations

import csv
import io
import logging
import os
from pathlib import Path

import httpx2

from lanwatch import __version__
from lanwatch.config import Config
from lanwatch.models import HostObservation

log = logging.getLogger(__name__)

# Registry name -> URL. The file is kept under <data_dir>/oui/<name>.csv.
IEEE_REGISTRIES = {
    "oui": "https://standards-oui.ieee.org/oui/oui.csv",
    "mam": "https://standards-oui.ieee.org/oui28/mam.csv",
    "oui36": "https://standards-oui.ieee.org/oui36/oui36.csv",
}
IEEE_CSV_HEADER = "Registry,Assignment,Organization Name,Organization Address"
NMAP_PREFIXES = Path("/usr/share/nmap/nmap-mac-prefixes")
# Entries that name no vendor: a block the IEEE hands out in smaller pieces (the MA-M/MA-S
# files have the real holder), or a company that paid not to be listed.
UNNAMED = {"IEEE Registration Authority", "Private"}
# Prefix lengths in hex digits for MA-S, MA-M and MA-L, tried in that order.
PREFIX_LENGTHS = (9, 7, 6)
DOWNLOAD_HEADERS = {"User-Agent": f"lanwatch/{__version__}"}


def oui_dir(config: Config) -> Path:
    return config.data_dir / "oui"


class Registry:
    """Hex prefix (upper case, no separators) -> organisation."""

    def __init__(self, prefixes: dict[str, str] | None = None) -> None:
        self.prefixes = prefixes or {}

    def __len__(self) -> int:
        return len(self.prefixes)

    def lookup(self, mac: str) -> str | None:
        digits = mac.replace(":", "").replace("-", "").upper()
        for n in PREFIX_LENGTHS:
            if (name := self.prefixes.get(digits[:n])) is not None:
                return name
        return None


def parse_ieee_csv(text: str) -> dict[str, str]:
    """The CSV the IEEE publishes: Registry,Assignment,Organization Name,Organization Address."""
    out: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text.lstrip("﻿"))):
        prefix = (row.get("Assignment") or "").strip().upper()
        name = (row.get("Organization Name") or "").strip()
        if prefix and name and name not in UNNAMED:
            out[prefix] = name
    return out


def parse_nmap_prefixes(text: str) -> dict[str, str]:
    """nmap-mac-prefixes: one "HEXPREFIX Vendor" per line, # comments."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        prefix, _, name = line.partition(" ")
        if prefix and name.strip():
            out[prefix.upper()] = name.strip()
    return out


def load(data_dir: Path, system_file: Path = NMAP_PREFIXES) -> Registry:
    """The downloaded registry when there is one, else nmap's copy, else nothing."""
    files = sorted((data_dir / "oui").glob("*.csv"))
    prefixes: dict[str, str] = {}
    for f in files:
        try:
            prefixes.update(parse_ieee_csv(f.read_text(encoding="utf-8", errors="replace")))
        except OSError as e:
            log.warning("cannot read %s: %s", f, e)
    if prefixes:
        return Registry(prefixes)
    try:
        return Registry(parse_nmap_prefixes(system_file.read_text(errors="replace")))
    except OSError:
        return Registry()


def fill_vendors(hosts: list[HostObservation], registry: Registry) -> list[HostObservation]:
    """Name the vendor on hosts the backend left unnamed. Hosts without a MAC stay as is."""
    if not registry:
        return hosts
    out = []
    for h in hosts:
        vendor = registry.lookup(h.mac) if h.mac and h.vendor is None else None
        out.append(h.model_copy(update={"vendor": vendor}) if vendor else h)
    return out


async def refresh(config: Config, client: httpx2.AsyncClient | None = None) -> int:
    """Download the IEEE registry files into <data_dir>/oui/. Returns the prefix count.

    Each file is written next to the old one and renamed over it only after it parsed, so a
    failed or garbled download leaves the previous copy in place. Raises on the first
    registry that cannot be fetched, which the scheduler records as a failed run and retries
    with backoff.
    """
    target = oui_dir(config)
    target.mkdir(parents=True, exist_ok=True)
    own_client = client is None
    client = client or httpx2.AsyncClient(timeout=60, follow_redirects=True)
    total = 0
    try:
        for name, url in IEEE_REGISTRIES.items():
            r = await client.get(url, headers=DOWNLOAD_HEADERS)
            r.raise_for_status()
            text = r.text
            if not text.lstrip("﻿").startswith(IEEE_CSV_HEADER):
                raise RuntimeError(f"{url} did not return the IEEE registry CSV")
            parsed = parse_ieee_csv(text)
            if not parsed:
                raise RuntimeError(f"{url} returned an empty registry")
            tmp = target / f".{name}.csv.part"
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, target / f"{name}.csv")
            total += len(parsed)
    finally:
        if own_client:
            await client.aclose()
    log.info("OUI registry refreshed: %d prefixes in %s", total, target)
    return total
