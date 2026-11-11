"""Links between devices that belong together: a BMC and its server, and so on."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from lanwatch.collectors.services import PortObservation, PortSet
from lanwatch.config import Config
from lanwatch.links import (
    RELATIONS,
    bmc_type,
    managed_names,
    managing_bmc,
    parse_relation,
    phrase,
    suggest,
)
from lanwatch.models import Device, FindingStatus, HostObservation, ServiceRow
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import MIGRATIONS, Store
from lanwatch.web.app import create_app

HYDRA = HostObservation(ip="10.0.0.10", mac="00:11:22:00:00:10", hostname="hydra", source="t")
HYDRA_ILO = HostObservation(
    ip="10.0.0.20", mac="00:11:22:00:00:20", hostname="hydra-ilo", source="t"
)
MEDUSA = HostObservation(ip="10.0.0.11", mac="00:11:22:00:00:11", hostname="medusa", source="t")
TV = HostObservation(ip="10.0.0.30", mac="00:11:22:00:00:30", hostname="tv", source="t")


def _round(store: Store, config: Config, hosts: list[HostObservation]) -> RuleContext:
    baseline = store.finished_snapshot_count("discovery") == 0
    prev = store.latest_snapshot("discovery")
    sid = store.begin_snapshot("discovery", "test")
    rec = store.record_hosts(sid, hosts)
    store.finish_snapshot(sid, len(rec.seen_device_ids))
    return RuleContext(
        store=store,
        config=config,
        snapshot_id=sid,
        previous_snapshot_id=prev.id if prev else None,
        is_baseline=baseline,
        new_device_ids=rec.new_device_ids,
        ip_changes=rec.ip_changes,
    )


def _id(store: Store, h: HostObservation) -> int:
    d = store.device_by_key(h.mac or "")
    assert d is not None
    return d.id


def _device(id: int = 1, hostname: str | None = None, **kw: Any) -> Device:
    return Device(
        id=id,
        key=f"k{id}",
        mac=None,
        ip=None,
        hostname=hostname,
        vendor=None,
        name=kw.pop("name", None),
        kind=None,
        description=None,
        kind_confidence=None,
        first_seen="2026-11-11T00:00:00Z",
        last_seen="2026-11-11T00:00:00Z",
        online=kw.pop("online", True),
        attrs=kw.pop("attrs", {}),
    )


def _service(port: int = 443, **kw: Any) -> ServiceRow:
    return ServiceRow(
        id=1,
        device_id=1,
        port=port,
        proto="tcp",
        state="open",
        name=kw.pop("name", "https"),
        product=kw.pop("product", None),
        version=None,
        extrainfo=kw.pop("extrainfo", None),
        tunnel="ssl",
        details=kw.pop("details", {}),
        first_seen="",
        last_seen="",
    )


# -- store ---------------------------------------------------------------------


def test_add_remove_dismiss_and_readd(store: Store) -> None:
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, [HYDRA, HYDRA_ILO])
    server, ilo = _id(store, HYDRA), _id(store, HYDRA_ILO)

    assert store.add_link(ilo, ilo, "manages") is None
    assert store.add_link(ilo, 999, "manages") is None
    link_id = store.add_link(ilo, server, "manages")
    assert link_id is not None
    assert store.add_link(ilo, server, "manages") == link_id  # idempotent
    [link] = store.links(server)
    assert (link.a_id, link.b_id, link.kind, link.source) == (ilo, server, "manages", "manual")
    assert phrase(link, ilo) == "manages" and phrase(link, server) == "managed by"
    assert [e.kind for e in store.events(device_id=ilo)].count("device.linked") == 1

    assert store.remove_link(link_id)
    assert not store.remove_link(link_id)
    assert store.links(server) == []
    assert [x.id for x in store.links(server, dismissed=True)] == [link_id]
    assert (ilo, server, "manages") in store.link_keys()  # not suggested again

    assert store.add_link(ilo, server, "manages") == link_id  # by hand brings it back
    assert len(store.links(ilo)) == 1

    assert store.dismiss_link(server, ilo, "uplink", "unifi") is not None
    assert len(store.links(ilo)) == 1 and len(store.links(ilo, dismissed=True)) == 1


def test_forget_deletes_links_and_merge_moves_them(store: Store) -> None:
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, [HYDRA, HYDRA_ILO, MEDUSA, TV])
    hydra, ilo, medusa, tv = (_id(store, h) for h in (HYDRA, HYDRA_ILO, MEDUSA, TV))
    store.add_link(ilo, medusa, "manages")
    store.add_link(ilo, hydra, "manages")
    store.add_link(medusa, hydra, "uplink")
    store.add_link(tv, medusa, "powered-by")

    # medusa turns out to be hydra under another MAC: its links move over, except the one
    # that would now link hydra to itself and the one hydra already has.
    assert store.merge_devices(hydra, medusa)
    got = {(x.a_id, x.b_id, x.kind) for x in store.links()}
    assert got == {(ilo, hydra, "manages"), (tv, hydra, "powered-by")}
    assert {(x.a_id, x.b_id) for x in store.links(dismissed=True)} == set()

    assert store.delete_device(ilo)
    assert {(x.a_id, x.kind) for x in store.links()} == {(tv, "powered-by")}
    assert store.delete_device(hydra)
    assert store.links() == []


def test_links_migration_can_run_twice(store: Store) -> None:
    # Branches that add migrations may land in another order; this one must not care.
    store._db.executescript(next(m for m in MIGRATIONS if "device_links" in m))
    assert store.links() == []


# -- recognising BMCs and suggesting links -----------------------------------


def test_bmc_type_from_names_banners_and_snmp() -> None:
    assert bmc_type(_device(hostname="hydra-ilo.example.net"), []) == "iLO"
    assert bmc_type(_device(hostname="ilo-hydra"), []) == "iLO"
    assert bmc_type(_device(hostname="ILOCZJ12345XY"), []) == "iLO"
    assert bmc_type(_device(hostname="r740-idrac"), []) == "iDRAC"
    assert bmc_type(_device(name="Hydra iLO"), []) == "iLO"
    assert bmc_type(_device(name="nas-ipmi"), []) == "BMC"
    assert bmc_type(_device(hostname="hydra"), []) is None
    assert bmc_type(_device(hostname="milo"), []) is None
    assert bmc_type(_device(hostname="pilot"), [_service(product="nginx")]) is None

    title = {"http-title": {"data": {"title": "iLO 4 - hydra"}}}
    assert bmc_type(_device(hostname="hydra"), [_service(details=title)]) == "iLO"
    cert = {
        "ssl-cert": {
            "data": {
                "subject": {
                    "organizationName": "Hewlett Packard Enterprise",
                    "organizationalUnitName": "ISS",
                    "commonName": "hydra",
                },
                "issuer": {"commonName": "Default Issuer (Do not trust)"},
            }
        }
    }
    assert bmc_type(_device(), [_service(details=cert)]) is None  # HPE alone is not enough
    assert bmc_type(_device(), [_service(product="HP Integrated Lights-Out web server")]) == "iLO"
    assert bmc_type(_device(), [_service(product="Dell iDRAC9 httpd")]) == "iDRAC"
    assert bmc_type(_device(), [_service(port=623, name="asf-rmcp", extrainfo="IPMI")]) == "BMC"

    audit = {
        "snmp_audit": {"sys_name": "hydra.example.net", "sys_object_id": "1.3.6.1.4.1.232.9.4.10"}
    }
    assert bmc_type(_device(attrs=audit), []) == "iLO"
    descr = {"snmp_audit": {"sys_descr": "Integrated Lights-Out 4 2.82 Feb 06 2023"}}
    assert bmc_type(_device(attrs=descr), []) == "iLO"


def test_managed_names() -> None:
    assert managed_names(_device(hostname="hydra-ilo.example.net"), []) == {"hydra"}
    assert managed_names(_device(hostname="ilo-db-1"), []) == {"db-1"}
    assert managed_names(_device(name="Hydra iLO"), []) == {"hydra"}
    assert managed_names(_device(hostname="ILOCZJ12345XY"), []) == set()
    assert managed_names(_device(hostname="idrac-mgmt"), []) == set()
    # These iLOs report their server's name as their own.
    audit = {"snmp_audit": {"sys_name": "medusa.example.net"}}
    assert managed_names(_device(hostname="ILOCZJ12345XY", attrs=audit), []) == {"medusa"}
    cert = {"ssl-cert": {"data": {"subject": {"commonName": "hydra-ilo.example.net"}}}}
    assert managed_names(_device(), [_service(details=cert)]) == {"hydra"}


def test_suggest_one_server_per_bmc_and_nothing_known() -> None:
    hydra = _device(1, "hydra")
    ilo = _device(2, "hydra-ilo")
    tv = _device(3, "tv")
    [sg] = suggest([hydra, ilo, tv], {}, set())
    assert (sg.a_id, sg.b_id, sg.kind, sg.source) == (2, 1, "manages", "name-match")
    assert "hydra" in sg.reason and sg.as_dict()["kind"] == "manages"

    assert suggest([hydra, ilo, tv], {}, {(2, 1, "manages")}) == []  # linked or dismissed
    # Two devices called hydra: rather nothing than a guess.
    assert suggest([hydra, ilo, _device(4, "hydra.other.net")], {}, set()) == []
    # A BMC named after a server lanwatch does not know suggests nothing.
    assert suggest([ilo, tv], {}, set()) == []


def test_managing_bmc_only_when_it_answers(store: Store) -> None:
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(sid, [HYDRA, HYDRA_ILO])
    hydra, ilo = _id(store, HYDRA), _id(store, HYDRA_ILO)
    store.add_link(ilo, hydra, "manages")
    links = store.links()
    on = {hydra: _device(hydra, online=False), ilo: _device(ilo, online=True)}
    assert managing_bmc(hydra, links, on) is on[ilo]
    assert managing_bmc(ilo, links, on) is None  # the iLO is not managed by the server
    off = {**on, ilo: _device(ilo, online=False)}
    assert managing_bmc(hydra, links, off) is None


def test_relations() -> None:
    assert ("manages:out", "manages") in RELATIONS and ("manages:in", "managed by") in RELATIONS
    assert parse_relation("uplink:in") == ("uplink", False)
    assert parse_relation("powered-by:out") == ("powered-by", True)
    assert parse_relation("bogus:out") is None and parse_relation("manages") is None


# -- what links change ---------------------------------------------------------


def test_watched_server_powered_off_while_its_bmc_answers(store: Store, config: Config) -> None:
    engine = Engine(config)
    engine.run(_round(store, config, [HYDRA, HYDRA_ILO]))
    hydra, ilo = _id(store, HYDRA), _id(store, HYDRA_ILO)
    store.edit_device(hydra, name=None, kind=None, description=None, watch=True)
    store.add_link(ilo, hydra, "manages")

    engine.run(_round(store, config, [HYDRA_ILO]))
    result = engine.run(_round(store, config, [HYDRA_ILO]))
    [fid] = result.new_ids
    f = store.finding(fid)
    assert f is not None and f.title == "Watched device powered off: hydra (hydra-ilo answers)"
    assert f.evidence["managed_by"] == {"id": ilo, "label": "hydra-ilo", "ip": "10.0.0.20"}

    # The iLO goes too: now the server is simply offline. Same finding, new title.
    engine.run(_round(store, config, []))
    [f] = [
        x for x in store.findings(FindingStatus.OPEN) if x.rule_id == "inventory.watched-offline"
    ]
    assert f.id == fid and f.title == "Watched device offline: hydra"


def test_device_page_links_and_suggestions(config: Config) -> None:
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(sid, [HYDRA, HYDRA_ILO, TV])
        store.finish_snapshot(sid, 3)
        hydra, ilo, tv = (_id(store, h) for h in (HYDRA, HYDRA_ILO, TV))
        inv = store.begin_snapshot("inventory", "t")
        port = PortObservation(
            port=443,
            proto="tcp",
            state="open",
            name="https",
            product="HP Integrated Lights-Out web server",
        )
        store.record_services(inv, ilo, [port], {"tcp": PortSet.from_spec("443")})
        store.finish_snapshot(inv, 1)
    client = TestClient(create_app(config))

    page = client.get(f"/devices/{hydra}").text
    assert "Suggested links" in page and "iLO hydra-ilo goes by the name hydra" in page
    assert "Devices that belong with this one" in page
    assert "Suggested links" not in client.get(f"/devices/{tv}").text

    bad = {"a": ilo, "b": tv, "kind": "manages", "source": "name-match", "answer": "confirm"}
    assert client.post(f"/devices/{tv}/suggestions", data=bad).status_code == 404
    good = {**bad, "b": hydra}
    assert client.post(f"/devices/{tv}/suggestions", data=good).status_code == 404  # not its own
    assert (
        client.post(f"/devices/{hydra}/suggestions", data={**good, "answer": "x"}).status_code
        == 400
    )
    r = client.post(f"/devices/{hydra}/suggestions", data=good, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{hydra}"
    page = client.get(f"/devices/{hydra}").text
    assert "Suggested links" not in page
    assert "suggested by name-match" in page and f'href="/devices/{ilo}">hydra-ilo' in page

    # By hand: the TV hangs off the iLO (nonsense, but the form does what it is told).
    assert (
        client.post(f"/devices/{tv}/links", data={"other": ilo, "relation": "x"}).status_code == 400
    )
    assert (
        client.post(
            f"/devices/{tv}/links", data={"other": tv, "relation": "uplink:out"}
        ).status_code
        == 404
    )
    r = client.post(
        f"/devices/{tv}/links",
        data={"other": ilo, "relation": "uplink:out"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "hangs off <a" in client.get(f"/devices/{tv}").text
    assert "uplink of <a" in client.get(f"/devices/{ilo}").text

    with Store(config.store_path) as store:
        [link] = [x for x in store.links(tv)]
        manages = next(x for x in store.links(hydra) if x.kind == "manages")
    assert client.post(f"/devices/{hydra}/links/{link.id}/remove").status_code == 404
    r = client.post(f"/devices/{tv}/links/{link.id}/remove", follow_redirects=False)
    assert r.status_code == 303 and "hangs off <a" not in client.get(f"/devices/{tv}").text

    # Removing the confirmed suggestion does not bring the suggestion back.
    client.post(f"/devices/{hydra}/links/{manages.id}/remove")
    assert "Suggested links" not in client.get(f"/devices/{hydra}").text


def test_dismissed_suggestion_stays_away(config: Config) -> None:
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(sid, [HYDRA, HYDRA_ILO])
        store.finish_snapshot(sid, 2)
        hydra, ilo = _id(store, HYDRA), _id(store, HYDRA_ILO)
    client = TestClient(create_app(config))
    form = {"a": ilo, "b": hydra, "kind": "manages", "source": "name-match", "answer": "dismiss"}
    assert client.post(f"/devices/{ilo}/suggestions", data=form).status_code == 200
    page = client.get(f"/devices/{ilo}").text
    assert "Suggested links" not in page and "managed by" not in page.split("<h2>Links")[0]
