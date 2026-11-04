from __future__ import annotations

from lanwatch.collectors.services import (
    PortObservation,
    PortSet,
    build_nmap_args,
    parse_nmap_xml_services,
)
from lanwatch.config import Config, ScanConfig
from lanwatch.models import FindingStatus, HostObservation
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store
from tests.conftest import fixture_text


def test_portset() -> None:
    ps = PortSet.from_spec("21-23,80, 443")
    assert 22 in ps and 443 in ps and 81 not in ps
    assert len(ps) == 5


def test_parse_services_xml() -> None:
    res = parse_nmap_xml_services(fixture_text("nmap-services.xml"))
    assert (
        22 in res.scanned["tcp"] and 8081 in res.scanned["tcp"] and 9100 not in res.scanned["tcp"]
    )
    assert [h.ip for h in res.hosts] == ["192.168.1.1", "192.168.1.40"]
    gw = res.hosts[0]
    assert gw.mac == "aa:bb:cc:00:00:01"
    assert [p.port for p in gw.ports] == [22, 23, 80, 443]  # closed 8080 dropped
    ssh = gw.ports[0]
    assert ssh.product == "OpenSSH" and ssh.version == "7.4"
    assert ssh.scripts["ssh2-enum-algos"]["data"]["kex_algorithms"] == [
        "curve25519-sha256",
        "diffie-hellman-group1-sha1",
    ]
    https = gw.ports[3]
    assert https.tunnel == "ssl"
    assert https.scripts["ssl-cert"]["data"]["validity"]["notAfter"] == "2021-01-01T00:00:00"
    assert gw.ports[2].scripts["http-title"]["data"] == {"title": "Router admin"}


def test_build_nmap_args_light_and_deep() -> None:
    cfg = ScanConfig()
    light = build_nmap_args(["10.0.0.1"], cfg, deep=False)
    assert "--top-ports=200" in light and "-T2" in light and "--exclude-ports=9100" in light
    assert "--version-intensity=0" in light and light[-1] == "10.0.0.1"
    deep = build_nmap_args(["10.0.0.1"], ScanConfig(profile="thorough"), deep=True)
    assert "-p-" in deep and "-T4" in deep and "--version-intensity=5" in deep
    bare = build_nmap_args(["10.0.0.1"], ScanConfig(version_detection=False, scripts=[]), False)
    assert "-sV" not in bare and not any(a.startswith("--script") for a in bare)


def _seed_device(store: Store, ip: str, mac: str) -> int:
    sid = store.begin_snapshot("discovery", "t")
    rec = store.record_hosts(sid, [HostObservation(ip=ip, mac=mac, source="t")])
    store.finish_snapshot(sid, 1)
    return rec.new_device_ids[0]


def test_record_services_open_close_and_scanned_scope(store: Store) -> None:
    dev = _seed_device(store, "10.0.0.1", "aa:bb:cc:00:00:01")
    top = {"tcp": PortSet.from_spec("1-1000")}
    sid = store.begin_snapshot("inventory", "t")
    ports = [
        PortObservation(port=22, proto="tcp", state="open", name="ssh"),
        PortObservation(port=8443, proto="tcp", state="open", name="https"),
    ]
    d1 = store.record_services(sid, dev, ports, {"tcp": PortSet.from_spec("1-65535")}, deep=True)
    assert d1.first_scan and sorted(d1.opened) == [(22, "tcp"), (8443, "tcp")]

    # Light scan (1-1000) sees only 22: 8443 was not scanned, so it must stay open.
    d2 = store.record_services(sid, dev, [ports[0]], top)
    assert not d2.first_scan and d2.opened == [] and d2.closed == []
    assert [s.port for s in store.services(dev)] == [22, 8443]

    # Light scan sees 80 instead of 22: 22 closes, 80 opens, 8443 untouched.
    d3 = store.record_services(sid, dev, [PortObservation(port=80, proto="tcp", state="open")], top)
    assert d3.opened == [(80, "tcp")] and d3.closed == [(22, "tcp")]
    assert [s.port for s in store.services(dev)] == [80, 8443]
    assert [s.port for s in store.services(dev, open_only=False)] == [22, 80, 8443]

    # Reopen 22: reported as opened again.
    d4 = store.record_services(sid, dev, ports[:1], top)
    assert d4.opened == [(22, "tcp")]
    assert store.last_inventory_at(dev) is not None
    assert store.devices_needing_deep_scan("9999-01-01T00:00:00+00:00") == [dev]


def test_service_rules_from_fixture(store: Store, config: Config) -> None:
    res = parse_nmap_xml_services(fixture_text("nmap-services.xml"))
    ids = {
        h.ip: _seed_device(store, h.ip, h.mac or f"00:00:00:00:00:{i:02x}")
        for i, h in enumerate(res.hosts)
    }
    sid = store.begin_snapshot("inventory", "t")
    diffs = {
        ids[h.ip]: store.record_services(sid, ids[h.ip], h.ports, res.scanned) for h in res.hosts
    }
    store.finish_snapshot(sid, len(res.hosts))
    ctx = RuleContext(
        store=store,
        config=config,
        snapshot_id=sid,
        previous_snapshot_id=None,
        is_baseline=False,
        service_diffs=diffs,
    )
    result = Engine(config).run(ctx)
    by_rule = {f.rule_id: f for f in result.emitted}
    assert set(by_rule) == {
        "service.cleartext-remote-access",
        "service.smb1-enabled",
        "service.vnc-no-auth",
        "service.database-exposed",
        "ssh.weak-algorithms",
        "tls.certificate",
    }
    assert by_rule["ssh.weak-algorithms"].evidence["weak"] == {
        "kex": ["diffie-hellman-group1-sha1"],
        "ciphers": ["3des-cbc"],
        "macs": ["hmac-md5"],
    }
    assert by_rule["tls.certificate"].title.startswith("TLS certificate expired")
    assert by_rule["service.cleartext-remote-access"].severity.value == "high"
    # First scan of a device never raises service-changed.
    assert "inventory.service-changed" not in by_rule

    # Telnet goes away on the next light scan: the finding auto-resolves.
    gw_ports = [p for p in res.hosts[0].ports if p.port != 23]
    sid2 = store.begin_snapshot("inventory", "t")
    diff = store.record_services(sid2, ids["192.168.1.1"], gw_ports, res.scanned)
    ctx2 = RuleContext(
        store=store,
        config=config,
        snapshot_id=sid2,
        previous_snapshot_id=sid,
        is_baseline=False,
        service_diffs={ids["192.168.1.1"]: diff},
    )
    r2 = Engine(config).run(ctx2)
    assert by_rule["service.cleartext-remote-access"].id in r2.resolved_ids
    open_rules = {f.rule_id for f in store.findings(FindingStatus.OPEN)}
    assert "service.cleartext-remote-access" not in open_rules
    assert "service.smb1-enabled" in open_rules  # other device untouched, still open

    # A new port on a known device raises service-changed.
    sid3 = store.begin_snapshot("inventory", "t")
    more = [*gw_ports, PortObservation(port=8081, proto="tcp", state="open", name="http")]
    diff3 = store.record_services(sid3, ids["192.168.1.1"], more, res.scanned)
    ctx3 = RuleContext(
        store=store,
        config=config,
        snapshot_id=sid3,
        previous_snapshot_id=sid2,
        is_baseline=False,
        service_diffs={ids["192.168.1.1"]: diff3},
    )
    r3 = Engine(config).run(ctx3)
    changed = [f for f in r3.emitted if f.rule_id == "inventory.service-changed"]
    assert len(changed) == 1 and changed[0].evidence["opened"] == ["8081/tcp"]
