"""Extra reads per kind of SNMP device, on top of the system group every target gets.

A reader says which devices it is for (from their system group) and reads what it wants
with the target's SnmpClient. Readers live in their own modules, named
`lanwatch/collectors/snmp_<something>.py`, each with a module-level `READERS` list; they
are found by name, so adding one needs no edit here or in the pipeline. The collector
stores each reader's facts in the target's row (infra kind snmp-target) under
facts[<reader name>], where rules and the web pick them up.

A reader that fails is logged and skipped; its previous facts stay, and the system
read still counts as a good read of the target.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from lanwatch import collectors
from lanwatch.collectors.snmp import SnmpClient, SystemInfo

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ReaderResult:
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SnmpReader:
    # Unique and stable: the key the facts are stored under.
    name: str
    matches: Callable[[SystemInfo], bool]
    read: Callable[[SnmpClient, SystemInfo], Awaitable[ReaderResult]]


def find_readers() -> list[SnmpReader]:
    """Every reader in the collector modules named snmp_*, in module-name order."""
    out: list[SnmpReader] = []
    names: set[str] = set()
    for info in sorted(pkgutil.iter_modules(collectors.__path__), key=lambda m: m.name):
        if not info.name.startswith("snmp_") or info.name == "snmp_kinds":
            continue
        module = importlib.import_module(f"{collectors.__name__}.{info.name}")
        for reader in getattr(module, "READERS", []):
            if reader.name in names:
                raise RuntimeError(f"two SNMP readers named {reader.name!r}")
            names.add(reader.name)
            out.append(reader)
    return out


async def run_readers(
    client: SnmpClient,
    system: SystemInfo,
    readers: list[SnmpReader],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Run the readers that match this device. Returns (facts per reader, error per
    reader that failed)."""
    facts: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    for reader in readers:
        try:
            if not reader.matches(system):
                continue
            facts[reader.name] = (await reader.read(client, system)).facts
        except Exception as e:
            log.warning("snmp: reader %s failed on %s: %s", reader.name, client.host, e)
            errors[reader.name] = f"{type(e).__name__}: {str(e)[:200]}"
    return facts, errors
