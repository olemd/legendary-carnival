from __future__ import annotations

from pathlib import Path

import httpx2
import pytest

from lanwatch import oui
from lanwatch.config import Config
from lanwatch.models import HostObservation

IEEE_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,E465B8,Espressif Inc.,"Room 204, Building 2, 690 Bibo Road Shanghai CN 201203"\n'
    "MA-L,8C1F64,IEEE Registration Authority,445 Hoes Lane Piscataway NJ US 08554\n"
    "MA-L,0050C2,Private,\n"
)
MAM_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-M,8C1F64A,Acme Sensors,Somewhere\n"
)
NMAP_TXT = "# comment\n000000 Xerox\nE465B8 Espressif\n8C1F64A Acme Sensors (nmap)\n"


def test_parse_ieee_csv_skips_unnamed_blocks() -> None:
    assert oui.parse_ieee_csv("﻿" + IEEE_CSV) == {"E465B8": "Espressif Inc."}


def test_parse_nmap_prefixes() -> None:
    assert oui.parse_nmap_prefixes(NMAP_TXT) == {
        "000000": "Xerox",
        "E465B8": "Espressif",
        "8C1F64A": "Acme Sensors (nmap)",
    }


def test_lookup_prefers_the_longest_prefix() -> None:
    reg = oui.Registry({"E465B8": "Espressif Inc.", "8C1F64A": "Acme Sensors"})
    assert reg.lookup("e4:65:b8:d9:33:3b") == "Espressif Inc."
    assert reg.lookup("8c:1f:64:a1:22:33") == "Acme Sensors"
    assert reg.lookup("8c:1f:64:b1:22:33") is None  # the holder of the block is not a vendor
    assert reg.lookup("00-11-22-33-44-55") is None


def test_fill_vendors_only_where_missing() -> None:
    reg = oui.Registry({"E465B8": "Espressif Inc."})
    hosts = [
        HostObservation(ip="10.0.0.1", mac="e4:65:b8:d9:33:3b", source="arp-scan"),
        HostObservation(ip="10.0.0.2", mac="e4:65:b8:00:00:01", vendor="Kept", source="nmap"),
        HostObservation(ip="10.0.0.3", source="ping"),
    ]
    out = oui.fill_vendors(hosts, reg)
    assert [h.vendor for h in out] == ["Espressif Inc.", "Kept", None]
    assert out[1] is hosts[1] and out[2] is hosts[2]
    assert oui.fill_vendors(hosts, oui.Registry()) is hosts


def test_load_prefers_download_over_nmap(tmp_path: Path) -> None:
    nmap = tmp_path / "nmap-mac-prefixes"
    nmap.write_text(NMAP_TXT)
    reg = oui.load(tmp_path, system_file=nmap)
    assert reg.lookup("e4:65:b8:d9:33:3b") == "Espressif"

    (tmp_path / "oui").mkdir()
    (tmp_path / "oui" / "oui.csv").write_text(IEEE_CSV)
    (tmp_path / "oui" / "mam.csv").write_text(MAM_CSV)
    reg = oui.load(tmp_path, system_file=nmap)
    assert reg.lookup("e4:65:b8:d9:33:3b") == "Espressif Inc."
    assert reg.lookup("8c:1f:64:a1:22:33") == "Acme Sensors"

    assert len(oui.load(tmp_path / "none", system_file=tmp_path / "missing")) == 0


def _client(bodies: dict[str, str | int]) -> httpx2.AsyncClient:
    def handle(request: httpx2.Request) -> httpx2.Response:
        body = bodies[str(request.url)]
        return httpx2.Response(body) if isinstance(body, int) else httpx2.Response(200, text=body)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handle))


async def test_refresh_writes_registry_files(tmp_path: Path) -> None:
    cfg = Config(data_dir=tmp_path)
    urls = oui.IEEE_REGISTRIES
    client = _client({urls["oui"]: IEEE_CSV, urls["mam"]: MAM_CSV, urls["oui36"]: MAM_CSV})
    assert await oui.refresh(cfg, client) == 3
    assert sorted(p.name for p in (tmp_path / "oui").iterdir()) == [
        "mam.csv",
        "oui.csv",
        "oui36.csv",
    ]
    assert oui.load(tmp_path).lookup("e4:65:b8:d9:33:3b") == "Espressif Inc."


async def test_refresh_keeps_old_copy_on_bad_download(tmp_path: Path) -> None:
    cfg = Config(data_dir=tmp_path)
    urls = oui.IEEE_REGISTRIES
    good = _client({urls["oui"]: IEEE_CSV, urls["mam"]: MAM_CSV, urls["oui36"]: MAM_CSV})
    await oui.refresh(cfg, good)

    portal = _client(
        {urls["oui"]: "<html>Please log in</html>", urls["mam"]: 503, urls["oui36"]: 503}
    )
    with pytest.raises(RuntimeError):
        await oui.refresh(cfg, portal)
    assert (tmp_path / "oui" / "oui.csv").read_text() == IEEE_CSV
    assert not list((tmp_path / "oui").glob(".*.part"))

    down = _client({urls["oui"]: 503, urls["mam"]: 503, urls["oui36"]: 503})
    with pytest.raises(httpx2.HTTPStatusError):
        await oui.refresh(cfg, down)
    assert oui.load(tmp_path).lookup("e4:65:b8:d9:33:3b") == "Espressif Inc."
