"""airOS link history and the rules over it. Rows are written directly; no radio."""

from __future__ import annotations

from typing import Any

import pytest

from lanwatch.collectors import airos
from lanwatch.config import AirosConfig, Config, UnifiConfig
from lanwatch.models import Finding
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store

A, B = "192.168.1.5", "192.168.1.6"
MAC_A, MAC_B = "02:00:00:00:0a:01", "02:00:00:00:0b:01"


def _station(mac: str, name: str, signal: int = -65, ccq: int = 80) -> airos.AirosStation:
    return airos.AirosStation(
        mac=mac,
        name=name,
        ip=None,
        signal=signal,
        noise=-96,
        ccq=ccq,
        tx_mbps=240.0,
        rx_mbps=240.0,
        uptime_s=600,
        airmax_quality=80,
        airmax_capacity=60,
        remote_hostname=name,
        remote_model=None,
        remote_version=None,
        remote_signal=None,
        remote_noise=None,
    )


def _radio(host: str, stations: list[airos.AirosStation], mode: str = "ap") -> airos.AirosStatus:
    return airos.AirosStatus(
        host=host,
        hostname=f"radio-{host[-1]}",
        model="NanoStation loco M2",
        firmware="v6.3.26",
        uptime_s=600,
        netrole="bridge",
        mode=mode,
        essid="link",
        frequency_mhz=2449,
        channel_width_mhz=20,
        signal=-65,
        noise=-96,
        ccq=80,
        tx_power=9,
        security="WPA2",
        ap_mac=None,
        airmax_quality=80,
        airmax_capacity=60,
        stations=stations,
        interfaces=[airos.AirosInterface("br0", MAC_A if host == A else MAC_B, None, None, True)],
    )


def test_track_links_learns_a_normal_and_holds_it_while_worse() -> None:
    track: dict[str, Any] | None = None
    for _ in range(airos.BASELINE_WARMUP):
        track = airos.track_links(track, _radio(A, [_station(MAC_B, "b", -65, 80)]))
    assert track is not None
    link = track["links"][MAC_B]
    assert link["reads"] == airos.BASELINE_WARMUP and link["degraded_reads"] == 0
    assert link["normal_signal"] == pytest.approx(-65) and link["normal_ccq"] == pytest.approx(80)
    # 8 dB weaker: degraded, and the normal is not dragged down with it.
    for n in (1, 2, 3):
        track = airos.track_links(track, _radio(A, [_station(MAC_B, "b", -73, 80)]))
        assert track["links"][MAC_B]["degraded_reads"] == n
    assert track["links"][MAC_B]["normal_signal"] == pytest.approx(-65)
    # Back to normal: the count resets.
    track = airos.track_links(track, _radio(A, [_station(MAC_B, "b", -65, 80)]))
    assert track["links"][MAC_B]["degraded_reads"] == 0


def test_track_links_judges_nothing_while_learning() -> None:
    track = airos.track_links(None, _radio(A, [_station(MAC_B, "b", -65, 80)]))
    track = airos.track_links(track, _radio(A, [_station(MAC_B, "b", -90, 10)]))
    assert track["links"][MAC_B]["degraded_reads"] == 0  # too early to know what normal is
    assert track["links"][MAC_B]["poor_reads"] == 1  # but a CCQ of 10% is poor regardless


def test_track_links_counts_reads_without_a_link() -> None:
    track = airos.track_links(None, _radio(A, []))
    track = airos.track_links(track, _radio(A, []))
    assert track["no_link_reads"] == 2
    assert airos.track_links(track, _radio(A, [_station(MAC_B, "b")]))["no_link_reads"] == 0


def test_track_links_remembers_the_normal_across_a_dropped_link() -> None:
    """The link drops and comes back 15 dB weaker: that is judged against what was learned
    before the drop, not taken as a new normal."""
    track: dict[str, Any] | None = None
    for _ in range(airos.BASELINE_WARMUP):
        track = airos.track_links(track, _radio(A, [_station(MAC_B, "b", -65, 80)]))
    track = airos.track_links(track, _radio(A, []))
    assert track["no_link_reads"] == 1
    assert track["links"][MAC_B]["normal_signal"] == pytest.approx(-65)
    for n in (1, 2):
        track = airos.track_links(track, _radio(A, [_station(MAC_B, "b", -80, 80)]))
        assert track["links"][MAC_B]["degraded_reads"] == n
    assert track["links"][MAC_B]["normal_signal"] == pytest.approx(-65)
    assert "absent_reads" not in track["links"][MAC_B]


def test_track_links_forgets_a_station_that_stays_away() -> None:
    track = airos.track_links(None, _radio(A, [_station(MAC_B, "b")]))
    for _ in range(airos.LINK_MEMORY_READS):
        track = airos.track_links(track, _radio(A, []))
    assert track["links"][MAC_B]["absent_reads"] == airos.LINK_MEMORY_READS
    assert airos.track_links(track, _radio(A, []))["links"] == {}


def _store_rows(store: Store, rows: dict[str, dict[str, Any]]) -> int:
    sid = store.begin_snapshot("infra", "t")
    store.replace_infra("airos", rows, sid)
    return sid


def _row(radio: airos.AirosStatus, **extra: Any) -> dict[str, Any]:
    return {**radio.as_dict(), "read_at": "2026-11-10T12:00:00+00:00", "error": None, **extra}


def _findings(store: Store, config: Config, sid: int, rule: str) -> list[Finding]:
    ctx = RuleContext(store, config, sid, None, is_baseline=False)
    return [f for f in Engine(config).run(ctx).emitted if f.rule_id == rule]


@pytest.fixture
def on(config: Config) -> Config:
    config.airos = AirosConfig(enabled=True, hosts=[A, B], username="u", password="p")
    return config


def test_link_down_after_two_reads(store: Store, on: Config) -> None:
    row = _row(_radio(A, []), no_link_reads=1, links={})
    assert _findings(store, on, _store_rows(store, {A: row}), "airos.link-down") == []
    row["no_link_reads"] = 2
    (f,) = _findings(store, on, _store_rows(store, {A: row}), "airos.link-down")
    assert f.title == "radio-5: radio link down"
    # Off: no airOS findings at all.
    on.airos = AirosConfig()
    assert _findings(store, on, _store_rows(store, {A: row}), "airos.link-down") == []


def test_poor_link_is_reported_once_with_the_worse_end(store: Store, on: Config) -> None:
    ap = _row(
        _radio(A, [_station(MAC_B, "radio-6", ccq=55)]),
        links={MAC_B: {"poor_reads": 4}},
        no_link_reads=0,
    )
    sta = _row(
        _radio(B, [_station(MAC_A, "radio-5", ccq=44)], mode="sta"),
        links={MAC_A: {"poor_reads": 5}},
        no_link_reads=0,
    )
    (f,) = _findings(store, on, _store_rows(store, {A: ap, B: sta}), "airos.link-poor")
    assert "radio-5 ↔ radio-6" in f.title and "CCQ 44% at radio-6" in f.title
    assert f.evidence["ccq"] == {"radio-5": 55, "radio-6": 44}


def test_degraded_link_names_its_normal(store: Store, on: Config) -> None:
    track = {MAC_B: {"degraded_reads": 2, "normal_signal": -65.2, "normal_ccq": 81.0}}
    row = _row(_radio(A, [_station(MAC_B, "radio-6", signal=-74, ccq=78)]), links=track)
    (f,) = _findings(store, on, _store_rows(store, {A: row}), "airos.link-degraded")
    assert "signal -74 dBm (normally -65)" in f.title and "CCQ 78% (normally 81%)" in f.title


def _unifi_aps(store: Store, sid: int) -> None:
    store.replace_infra(
        "unifi-device",
        {
            "u1": {
                "name": "hall",
                "radios": [{"band": 2.4, "channel": 6}, {"band": 5.0, "channel": 36}],
            },
            "u2": {"name": "office", "radios": [{"band": 2.4, "channel": 6}]},
            "u3": {"name": "kitchen", "radios": [{"band": 2.4, "channel": 1}]},
            "u4": {"name": "living", "radios": [{"band": 2.4, "channel": 11}]},
        },
        sid,
    )


def test_channel_between_6_and_11_suggests_the_quietest_common_channel(
    store: Store, on: Config
) -> None:
    rows = {
        A: _row(_radio(A, [_station(MAC_B, "radio-6", ccq=77)])),
        B: _row(_radio(B, [_station(MAC_A, "radio-5", ccq=50)], mode="sta")),
    }
    # Without UniFi: generic advice, once for the link, with the worse end's CCQ.
    (f,) = _findings(store, on, _store_rows(store, rows), "airos.channel-overlap")
    assert "(CCQ 50%) on 2449 MHz overlaps Wi-Fi channels 6 and 11 partly" in f.title
    assert "channel 1, 6 or 11" in f.title
    # With the user's own APs: who is in the way, and the channel fewest of them use.
    on.unifi = UnifiConfig(enabled=True, url="https://c", api_key="k")
    sid = _store_rows(store, rows)
    _unifi_aps(store, sid)
    (f,) = _findings(store, on, sid, "airos.channel-overlap")
    assert "(hall, living, office)" in f.title
    assert "channel 1 (2412 MHz) is used by 1 of your access points" in f.title
    assert "Site Survey" in f.title and f.evidence["suggested_channel"] == 1
    # The same overlap on a link that gets its frames through: nothing to advise.
    good = {
        A: _row(_radio(A, [_station(MAC_B, "radio-6", ccq=93)])),
        B: _row(_radio(B, [_station(MAC_A, "radio-5", ccq=89)], mode="sta")),
    }
    sid = _store_rows(store, good)
    _unifi_aps(store, sid)
    assert _findings(store, on, sid, "airos.channel-overlap") == []


def test_channel_rule_is_quiet_on_a_clean_or_5_ghz_channel(store: Store, on: Config) -> None:
    on.unifi = UnifiConfig(enabled=True, url="https://c", api_key="k")
    clean = _radio(A, [_station(MAC_B, "radio-6")])
    clean.frequency_mhz = 2412  # exactly channel 1, and none of the user's APs use 1
    sid = _store_rows(store, {A: _row(clean)})
    store.replace_infra(
        "unifi-device", {"u1": {"name": "hall", "radios": [{"band": 2.4, "channel": 6}]}}, sid
    )
    assert _findings(store, on, sid, "airos.channel-overlap") == []
    five = _radio(A, [_station(MAC_B, "radio-6")])
    five.frequency_mhz = 5745
    assert _findings(store, on, _store_rows(store, {A: _row(five)}), "airos.channel-overlap") == []
    # Exactly on a channel the user's own AP uses: shared, reported.
    shared = _radio(A, [_station(MAC_B, "radio-6", ccq=60)])
    shared.frequency_mhz = 2437
    sid = _store_rows(store, {A: _row(shared)})
    store.replace_infra(
        "unifi-device", {"u1": {"name": "hall", "radios": [{"band": 2.4, "channel": 6}]}}, sid
    )
    (f,) = _findings(store, on, sid, "airos.channel-overlap")
    assert "shares Wi-Fi channel 6 with your access points (hall)" in f.title


def test_certificate_and_login_problems_are_findings(store: Store, on: Config) -> None:
    rows = {
        A: {
            "host": A,
            "hostname": "radio-5",
            "error": "another TLS certificate",
            "pin_failed": True,
        },
        B: {"host": B, "hostname": "radio-6", "error": "login not accepted", "rejected": True},
    }
    sid = _store_rows(store, rows)
    (cert,) = _findings(store, on, sid, "airos.certificate-changed")
    (login,) = _findings(store, on, sid, "airos.login-rejected")
    assert "radio-5 (192.168.1.5) presents another TLS certificate" in cert.title
    assert "radio-6 (192.168.1.6) rejected" in login.title
    # A radio that was not read is not judged on stale link data.
    assert _findings(store, on, sid, "airos.link-down") == []
