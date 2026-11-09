from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from lanwatch.config import Config
from lanwatch.models import HostObservation, iso, now_utc
from lanwatch.store import Store
from lanwatch.web.app import _presence_grid, create_app

PHONE = HostObservation(ip="10.0.0.2", mac="a8:bb:cc:00:00:02", source="t")
ROUTER = HostObservation(ip="10.0.0.1", mac="a8:bb:cc:00:00:01", source="t")


def _round(store: Store, hosts: list[HostObservation], ago: timedelta) -> None:
    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(sid, hosts)
    store.finish_snapshot(sid, len(rec.seen_device_ids))
    store._db.execute(
        "UPDATE snapshots SET finished_at = ?, started_at = ? WHERE id = ?",
        (iso(now_utc() - ago), iso(now_utc() - ago), sid),
    )


def test_presence_rows_cover_every_round(store: Store) -> None:
    _round(store, [ROUTER, PHONE], timedelta(hours=2))
    _round(store, [ROUTER], timedelta(hours=1))
    _round(store, [ROUTER, PHONE], timedelta(minutes=1))
    phone = store.device_by_key(PHONE.mac or "")
    assert phone is not None
    rows = store.presence(phone.id, iso(now_utc() - timedelta(days=28)))
    assert [a for _, a in rows] == [True, False, True]
    # Rounds older than the window are left out.
    _round(store, [ROUTER, PHONE], timedelta(days=40))
    assert len(store.presence(phone.id, iso(now_utc() - timedelta(days=28)))) == 3


def test_presence_grid_shares_and_quietest_hour() -> None:
    assert _presence_grid([]) is None
    # Three rounds in one local hour: there twice, away once. Build the timestamps from a
    # local wall-clock time so the weekday/hour the grid reports is predictable.
    base = now_utc().astimezone().replace(hour=3, minute=0, second=0, microsecond=0)
    rows = [
        (iso(base), True),
        (iso(base + timedelta(minutes=5)), False),
        (iso(base + timedelta(minutes=10)), True),
    ]
    rows.append((iso(base + timedelta(hours=5)), True))
    g = _presence_grid(rows)
    assert g is not None and g["rounds"] == 4 and g["share"] == 0.75
    d = base.weekday()
    assert g["grid"][d][3] == 2 / 3 and g["grid"][d][8] == 1.0 and g["grid"][d][9] is None
    assert g["quietest"] == {"day": g["days"][d], "hour": 3, "share": 2 / 3}
    # A device that never missed a round has no quietest hour.
    assert _presence_grid([(iso(base), True)])["quietest"] is None  # type: ignore[index]


def test_device_page_shows_presence(config: Config, tmp_path: Path) -> None:
    with Store(config.store_path) as store:
        _round(store, [ROUTER, PHONE], timedelta(hours=1))
        _round(store, [ROUTER], timedelta(minutes=1))
        phone = store.device_by_key(PHONE.mac or "")
        assert phone is not None
        device_id = phone.id
    html = TestClient(create_app(config)).get(f"/devices/{device_id}").text
    assert "Presence, last 4 weeks" in html and "Answered 50% of 2 discovery rounds" in html
    assert 'class="heat"' in html and "there 0% of the time" in html
