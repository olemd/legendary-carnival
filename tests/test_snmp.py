"""SNMPv3 reader: output parsing, credential handling, and the round that stores the result."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from lanwatch import pipeline
from lanwatch.cli import app
from lanwatch.collectors import snmp
from lanwatch.config import Config, SnmpConfig, dump_effective
from lanwatch.store import Store
from tests.conftest import FIXTURES

AUTH = "auth-secret-123"
PRIV = "priv-secret-456"


def snmp_config(**kw: object) -> SnmpConfig:
    base: dict[str, object] = {
        "enabled": True,
        "host": "192.0.2.1",
        "auth_password": AUTH,
        "priv_password": PRIV,
    }
    return SnmpConfig.model_validate(base | kw)


def fake_walker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str, rc: int = 0, stderr: str = ""
) -> Path:
    """Put a fake snmpbulkwalk first on PATH. It records its arguments (one line per call),
    environment and the config file it was given, then prints tmp_path/walks/<oid> when
    there is one, else `output`."""
    bin_dir = tmp_path / "bin"
    rec = tmp_path / "rec"
    bin_dir.mkdir()
    rec.mkdir()
    (tmp_path / "walks").mkdir()
    (tmp_path / "out.txt").write_text(output)
    (tmp_path / "err.txt").write_text(stderr)
    script = bin_dir / "snmpbulkwalk"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> {rec}/args\n'
        "for oid; do :; done\n"
        f'echo "$SNMPCONFPATH" > {rec}/dir\n'
        f"env > {rec}/env\n"
        f'cp "$SNMPCONFPATH/snmp.conf" {rec}/conf\n'
        f'stat -c %a "$SNMPCONFPATH/snmp.conf" > {rec}/mode\n'
        f'if [ -f "{tmp_path}/walks/$oid" ]; then cat "{tmp_path}/walks/$oid";'
        f" else cat {tmp_path}/out.txt; fi\n"
        f"cat {tmp_path}/err.txt >&2\n"
        f"exit {rc}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    return rec


def test_parse_walk_handles_wrapped_hex_and_types() -> None:
    values = snmp.parse_walk((FIXTURES / "snmp-system.txt").read_text())
    assert snmp.text(values[snmp.SYS_DESCR]).startswith("Juniper Networks, Inc. srx300")
    assert snmp.text(values[snmp.SYS_DESCR]).endswith("Juniper Networks, Inc.")
    assert values[snmp.SYS_OBJECT_ID] == "1.3.6.1.4.1.2636.1.1.1.2.133"
    assert values[snmp.SYS_UPTIME] == 1379882409
    assert values[snmp.SYS_CONTACT] == b""
    assert values["1.3.6.1.2.1.1.7.0"] == 4


def test_parse_walk_skips_missing_values_and_reads_other_types() -> None:
    values = snmp.parse_walk(
        ".1.3.6.1.4.1.9.9 = No Such Object available on this agent at this OID\n"
        ".1.3.6.1.2.1.4.20.1.1.192.0.2.1 = IpAddress: 192.0.2.1\n"
        '.1.3.6.1.2.1.2.2.1.2.1 = STRING: "eth0"\n'
        ".1.3.6.1.2.1.2.2.1.10.1 = Counter64: 12345678901\n"
        ".1.3.6.1.2.1.4.22.1.2.5.192.0.2.9 = Hex-STRING: 41 42 43 44 45 46 \n"
    )
    assert "1.3.6.1.4.1.9.9" not in values
    assert values["1.3.6.1.2.1.4.20.1.1.192.0.2.1"] == "192.0.2.1"
    assert values["1.3.6.1.2.1.2.2.1.2.1"] == b"eth0"
    assert values["1.3.6.1.2.1.2.2.1.10.1"] == 12345678901
    # Printable bytes still come back as bytes, so a MAC address is never taken for text.
    assert snmp.mac(values["1.3.6.1.2.1.4.22.1.2.5.192.0.2.9"]) == "41:42:43:44:45:46"


def test_parse_system_names_the_vendor() -> None:
    info = snmp.parse_system(snmp.parse_walk((FIXTURES / "snmp-system.txt").read_text()))
    assert info.name == "gw-test" and info.location == "rack" and info.contact == ""
    assert info.vendor == "Juniper"
    assert info.uptime_s == pytest.approx(13798824.09)
    with pytest.raises(snmp.SnmpError, match="system group"):
        snmp.parse_system({})


def test_config_is_v3_authpriv_only() -> None:
    assert snmp_config().auth_protocol == "SHA-256"
    with pytest.raises(ValidationError):
        snmp_config(auth_protocol="MD5")
    # SHA-1 as an HMAC is allowed (UniFi offers nothing else); MD5 is not.
    assert snmp_config(auth_protocol="SHA").auth_protocol == "SHA"
    with pytest.raises(ValidationError):
        snmp_config(priv_protocol="DES")
    with pytest.raises(ValidationError):
        snmp_config(community="public")  # no v1/v2c at all
    with pytest.raises(ValidationError, match="at least 8"):
        snmp_config(priv_password="short")
    with pytest.raises(ValidationError, match="spaces"):
        snmp_config(auth_password="has a space")
    # net-snmp would read a leading double quote as the start of a quoted value.
    with pytest.raises(ValidationError, match="double quote"):
        snmp_config(priv_password='"quoted-secret"')
    assert snmp_config(auth_password='quote"inside').auth_password == 'quote"inside'
    with pytest.raises(ValidationError, match="user"):
        snmp_config(user="bad user")
    # Off, nothing is required.
    assert not SnmpConfig().enabled


def test_config_show_redacts_snmp_passwords(tmp_path: Path) -> None:
    text = dump_effective(Config(data_dir=tmp_path, snmp=snmp_config()))
    assert AUTH not in text and PRIV not in text
    assert 'auth_password = "***"' in text and 'priv_password = "***"' in text


async def test_client_keeps_credentials_off_the_command_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    async with snmp.SnmpClient(snmp_config(), "192.0.2.1") as client:
        info = await client.system()
        conf_dir = Path((rec / "dir").read_text().strip())
        assert conf_dir.exists()
    assert info.name == "gw-test"
    args = (rec / "args").read_text()
    assert AUTH not in args and PRIV not in args
    assert "192.0.2.1" in args and "-On" in args and "-Ox" in args
    assert AUTH not in (rec / "env").read_text()
    conf = (rec / "conf").read_text()
    assert "defSecurityLevel authPriv" in conf
    assert f"defAuthPassphrase {AUTH}" in conf and f"defPrivPassphrase {PRIV}" in conf
    assert (rec / "mode").read_text().strip() == "600"
    assert not conf_dir.exists()  # removed with the client


async def test_client_explains_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_walker(
        tmp_path,
        monkeypatch,
        "",
        rc=1,
        stderr="Created directory: /tmp/x/cert_indexes\nTimeout: No Response from 192.0.2.1",
    )
    async with snmp.SnmpClient(snmp_config(), "192.0.2.1") as client:
        with pytest.raises(snmp.SnmpError, match="no answer") as err:
            await client.system()
    assert str(err.value).startswith("Timeout: No Response")


async def test_client_without_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    async with snmp.SnmpClient(snmp_config(), "192.0.2.1") as client:
        with pytest.raises(snmp.SnmpError, match="snmp package"):
            await client.system()


def test_walk_args_bracket_ipv6() -> None:
    assert "udp6:[2001:db8::1]" in snmp.walk_args("2001:db8::1", snmp.SYSTEM, 5)


async def test_collect_snmp_stores_state_and_keeps_it_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    store: Store,
    config: Config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO", logger="lanwatch.pipeline")
    config.snmp = snmp_config(host=None)

    async def gateways(ex: object = None) -> list[str]:
        return ["192.0.2.1"]

    monkeypatch.setattr(pipeline, "default_gateways", gateways)
    sid = store.begin_snapshot("infra", "t")
    rec = fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    out = await pipeline.collect_snmp(config, store, sid)
    assert out.error is None and out.host == "192.0.2.1"
    # 13798824 s is 159.7 days: the log says 159, like `lanwatch snmp`, not a rounded 160.
    assert "up 159 days" in caplog.text
    assert "192.0.2.1" in (rec / "args").read_text()  # the gateway, as no host was set
    system = json.loads(store.meta_get("snmp.system") or "{}")
    assert system["name"] == "gw-test" and system["vendor"] == "Juniper"
    assert store.meta_get("snmp.last_error") == ""

    (tmp_path / "out.txt").write_text("")
    (tmp_path / "err.txt").write_text("snmpbulkwalk: Authentication failure (incorrect password)")
    script = tmp_path / "bin" / "snmpbulkwalk"
    script.write_text(script.read_text().replace("exit 0", "exit 1"))
    out = await pipeline.collect_snmp(config, store, sid)
    assert out.error is not None and "auth_password" in out.error
    assert store.meta_get("snmp.last_error") == out.error
    assert json.loads(store.meta_get("snmp.system") or "{}")["name"] == "gw-test"


def test_cli_snmp_off(tmp_path: Path) -> None:
    r = CliRunner().invoke(app, ["--data-dir", str(tmp_path), "snmp"])
    assert r.exit_code == 1 and "docs/snmp.md" in r.output


def _walks() -> dict[str, dict[str, snmp.Value]]:
    return {
        name: snmp.parse_walk((FIXTURES / f"snmp-{name}.txt").read_text())
        for name in ("arp", "arp-types", "ifname", "ifphys", "jnx-dhcp")
    }


def test_parse_neighbours_skips_own_and_invalid_entries() -> None:
    w = _walks()
    got = {
        (n.ip, n.mac, n.interface, n.static)
        for n in snmp.parse_neighbours(w["arp"], w["arp-types"], w["ifname"], w["ifphys"])
    }
    assert got == {
        ("192.168.1.10", "aa:bb:cc:00:00:10", "irb.0", False),
        ("192.168.1.20", "aa:bb:cc:00:00:20", "irb.0", False),
        ("192.168.1.30", "aa:bb:cc:00:00:30", "irb.0", True),  # static entry
        ("fe80::10", "aa:bb:cc:00:00:10", "irb.0", False),  # IPv6 neighbour
        ("203.0.113.1", "ee:ee:ee:00:00:01", "ge-0/0/0.0", False),  # the WAN side
    }  # .1 is the router's own address (type 5), .40 is invalid (type 2), and 192.168.9.1
    # is listed as static but carries one of the router's interface MACs (as Junos does)


def test_parse_neighbours_from_the_older_table() -> None:
    macs = snmp.parse_walk(
        ".1.3.6.1.2.1.4.22.1.2.3.192.168.1.10 = Hex-STRING: AA BB CC 00 00 10 \n"
        ".1.3.6.1.2.1.4.22.1.2.3.192.168.1.40 = Hex-STRING: AA BB CC 00 00 40 \n"
    )
    types = snmp.parse_walk(
        ".1.3.6.1.2.1.4.22.1.4.3.192.168.1.10 = INTEGER: 3\n"
        ".1.3.6.1.2.1.4.22.1.4.3.192.168.1.40 = INTEGER: 2\n"
    )
    got = snmp.parse_neighbours(macs, types, {})
    assert [(n.ip, n.mac, n.interface) for n in got] == [
        ("192.168.1.10", "aa:bb:cc:00:00:10", None)
    ]


def test_parse_juniper_leases() -> None:
    leases = snmp.parse_juniper_leases(_walks()["jnx-dhcp"])
    assert [(x.ip, x.mac, x.since, x.expires) for x in leases] == [
        ("192.168.1.10", "aa:bb:cc:00:00:10", "2026-11-01 08:00:00 CET", "2026-11-10 10:44:01 CET"),
        ("192.168.1.20", "aa:bb:cc:00:00:20", "2026-11-09 18:29:45 CET", "2026-11-10 10:30:00 CET"),
    ]


def _router_fixtures(tmp_path: Path) -> None:
    for oid, name in (
        (snmp.NET_TO_PHYSICAL_MAC, "arp"),
        (snmp.NET_TO_PHYSICAL_TYPE, "arp-types"),
        (snmp.IF_NAME, "ifname"),
        (snmp.IF_PHYS_ADDRESS, "ifphys"),
        (snmp.JNX_DHCP_BINDINGS, "jnx-dhcp"),
    ):
        (tmp_path / "walks" / oid).write_text((FIXTURES / f"snmp-{name}.txt").read_text())


async def test_router_tables_facts_and_mismatch_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    """The router's tables land in infra and on known devices; an address the router ties
    to another MAC than the one that answered lanwatch becomes a finding after two reads."""
    from lanwatch.models import HostObservation
    from lanwatch.rules.base import RuleContext
    from lanwatch.rules.engine import Engine

    config.snmp = snmp_config()
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(
        sid,
        [
            HostObservation(ip="192.168.1.10", mac="aa:bb:cc:00:00:10", source="t"),
            # The router has .20 as aa..20; here something else answered for it.
            HostObservation(ip="192.168.1.20", mac="aa:bb:cc:00:00:99", source="t"),
            HostObservation(ip="192.168.1.30", mac="aa:bb:cc:00:00:30", source="t"),
        ],
    )
    store.finish_snapshot(sid, 3)
    fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    _router_fixtures(tmp_path)

    def mismatch_findings(snapshot_id: int) -> list[str]:
        ctx = RuleContext(store, config, snapshot_id, None, is_baseline=False)
        return [
            f.title
            for f in Engine(config).run(ctx).emitted
            if f.rule_id == "net.router-arp-mismatch"
        ]

    first = store.begin_snapshot("infra", "t")
    out = await pipeline.collect_snmp(config, store, first)
    assert out.error is None and out.leases is not None and len(out.leases) == 2
    assert {r.key for r in store.infra("router-arp")} >= {"192.168.1.10", "192.168.1.30"}
    assert {r.key for r in store.infra("router-dhcp")} == {"192.168.1.10", "192.168.1.20"}
    with_lease = store.device_by_key("aa:bb:cc:00:00:10")
    static = store.device_by_key("aa:bb:cc:00:00:30")
    assert with_lease is not None and static is not None
    assert with_lease.attrs["router"] == {
        "arp_interface": "irb.0",
        "dhcp_lease": True,
        "dhcp_lease_since": "2026-11-01 08:00:00 CET",
    }
    assert static.attrs["router"]["dhcp_lease"] is False
    assert out.mismatches == 1
    assert mismatch_findings(first) == []  # one read can be an address changing hands

    second = store.begin_snapshot("infra", "t")
    await pipeline.collect_snmp(config, store, second)
    (title,) = mismatch_findings(second)
    assert "192.168.1.20" in title and "aa:bb:cc:00:00:20" in title


async def test_router_without_lease_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    """Not a Juniper: no lease table is asked for, and devices get no lease facts."""
    config.snmp = snmp_config()
    system = (FIXTURES / "snmp-system.txt").read_text().replace(".2636.1.1", ".8072.3.2")
    rec = fake_walker(tmp_path, monkeypatch, system)
    _router_fixtures(tmp_path)
    out = await pipeline.collect_snmp(config, store, store.begin_snapshot("infra", "t"))
    assert out.system is not None and out.system.vendor == "net-snmp"
    assert out.leases is None and store.infra("router-dhcp") == []
    assert snmp.JNX_DHCP_BINDINGS not in (rec / "args").read_text()


async def test_merged_device_answering_with_its_other_mac_is_no_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    """A device merged from two MAC addresses (a phone with a private one) is known by the
    first. When it answers with the other, that is the MAC the router has for the address;
    both name the same device, so there is nothing to report."""
    from lanwatch.models import HostObservation
    from lanwatch.rules.base import RuleContext
    from lanwatch.rules.engine import Engine

    config.snmp = snmp_config()

    def discovery(mac: str) -> None:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(sid, [HostObservation(ip="192.168.1.20", mac=mac, source="t")])
        store.finish_snapshot(sid, 1)

    discovery("aa:bb:cc:00:00:99")
    discovery("aa:bb:cc:00:00:20")
    keep = store.device_by_key("aa:bb:cc:00:00:99")
    other = store.device_by_key("aa:bb:cc:00:00:20")
    assert keep is not None and other is not None
    assert store.merge_devices(keep.id, other.id)
    discovery("aa:bb:cc:00:00:20")  # the router has .20 as aa..20 too
    assert store.ip_holders()["192.168.1.20"] == [(keep.id, "aa:bb:cc:00:00:99")]
    fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    _router_fixtures(tmp_path)

    for _ in range(2):
        sid = store.begin_snapshot("infra", "t")
        out = await pipeline.collect_snmp(config, store, sid)
        assert out.error is None and out.mismatches == 0
        ctx = RuleContext(store, config, sid, None, is_baseline=False)
        emitted = Engine(config).run(ctx).emitted
        assert [f for f in emitted if f.rule_id == "net.router-arp-mismatch"] == []
