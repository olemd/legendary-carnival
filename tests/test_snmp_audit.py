"""SNMP audit probe: default communities over v1/v2c, the v3 presence check, the rules,
the schedule hook and the CLI."""

from __future__ import annotations

import stat
from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lanwatch import pipeline
from lanwatch.cli import app
from lanwatch.collectors import audit_snmp
from lanwatch.config import Config
from lanwatch.models import HostObservation, Severity, iso, now_utc
from lanwatch.rules.base import RuleContext
from lanwatch.rules.engine import Engine
from lanwatch.store import Store


def fake_snmpget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake snmpget first on PATH. Every call is recorded (one line of arguments). What a
    host answers comes from tmp_path/agents/<ip>, one word per line:
    `public:1`, `private:2c` (a community and version that answer) and `v3` (an SNMPv3
    agent). A request with a community that answers gets "Test agent <ip>" for sysDescr,
    or "name-<ip>" and an HP sysObjectID for the identity request. Any other request times
    out, like a real agent that drops it."""
    bin_dir = tmp_path / "bin"
    rec = tmp_path / "rec"
    agents = tmp_path / "agents"
    for d in (bin_dir, rec, agents):
        d.mkdir(exist_ok=True)
    script = bin_dir / "snmpget"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> {rec}/args\n'
        f'echo "$SNMPCONFPATH" > {rec}/confpath\n'
        'v=""; c=""; prev=""; host=""; id=""\n'
        "for a; do\n"
        '  case "$prev" in -v) v="$a";; -c) c="$a";; esac\n'
        f'  case "$a" in 192.0.2.*) host="$a";; {audit_snmp.SYS_NAME}) id=1;; esac\n'
        '  prev="$a"\n'
        "done\n"
        f'f="{agents}/$host"\n'
        'if [ "$v" = "3" ]; then\n'
        '  if [ -f "$f" ] && grep -qx v3 "$f"; then\n'
        '    echo "snmpget: Unknown user name" >&2; exit 1; fi\n'
        '  echo "Timeout: No Response from $host" >&2; exit 1\n'
        "fi\n"
        'if [ -f "$f" ] && grep -qx "$c:$v" "$f"; then\n'
        '  if [ -n "$id" ]; then\n'
        '    echo "\\"name-$host\\""; echo .1.3.6.1.4.1.11.2.3.9.1; exit 0; fi\n'
        '  echo "\\"Test agent $host\\""; exit 0; fi\n'
        'echo "Timeout: No Response from $host" >&2; exit 1\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    return rec


def agent(tmp_path: Path, ip: str, *answers: str) -> None:
    (tmp_path / "agents" / ip).write_text("".join(f"{a}\n" for a in answers))


async def test_probe_finds_default_communities_and_a_v3_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = fake_snmpget(tmp_path, monkeypatch)
    agent(tmp_path, "192.0.2.10", "public:1", "public:2c", "private:2c", "v3")
    agent(tmp_path, "192.0.2.11", "v3")
    results = {r.ip: r for r in await audit_snmp.audit(["192.0.2.10", "192.0.2.11", "192.0.2.12"])}

    loud = results["192.0.2.10"]
    assert loud.communities == {"public": ["1", "2c"], "private": ["2c"]}
    assert loud.v3_agent is True and loud.sys_descr == "Test agent 192.0.2.10"
    assert loud.sys_name == "name-192.0.2.10" and loud.sys_object_id == "1.3.6.1.4.1.11.2.3.9.1"
    quiet = results["192.0.2.11"]
    assert quiet.communities == {} and quiet.v3_agent is True
    silent = results["192.0.2.12"]
    assert silent.communities == {} and silent.v3_agent is False

    calls = (rec / "args").read_text().splitlines()
    # Per device: 2 communities x 2 versions + the v3 presence check, all GET sysDescr;
    # and for the one that answered, one GET of its name and sysObjectID, with v2c.
    ident = [c for c in calls if audit_snmp.SYS_NAME in c]
    assert len(calls) == 3 * 5 + 1 and len(ident) == 1
    assert "-v 2c -c public 192.0.2.10" in ident[0]
    assert ident[0].endswith(f"{audit_snmp.SYS_NAME} {audit_snmp.SYS_OBJECT_ID}")
    assert all(c.endswith(audit_snmp.SYS_DESCR) for c in calls if c not in ident)
    assert not any(" set " in c or "walk" in c for c in calls)
    assert all("-r 0" in c for c in calls)  # one try each
    # The presence check never logs in: no auth, a user no agent has.
    v3 = [c for c in calls if "-v 3" in c]
    assert v3 and all("noAuthNoPriv" in c and audit_snmp.PROBE_USER in c for c in v3)
    assert not any("-A " in c or "-X " in c for c in calls)
    # The user's and the system's snmp.conf stay out of it.
    assert "lanwatch-snmp-audit-" in (rec / "confpath").read_text()


def test_identity_is_short_and_skips_what_the_label_has() -> None:
    a = {"sys_name": "HP35FD51", "sys_descr": "HP ETHERNET MULTI-ENVIRONMENT,\nROM none"}
    assert audit_snmp.identity(a) == "HP35FD51, HP ETHERNET MULTI-ENVIRONMENT, ROM none"
    assert audit_snmp.identity(a, "HP35FD51 f0:47") == "HP ETHERNET MULTI-ENVIRONMENT, ROM none"
    assert len(audit_snmp.identity({"sys_descr": "x" * 300})) == 80
    assert audit_snmp.identity({}) == ""


def test_no_v3_defaults_without_a_source() -> None:
    assert all(d.source for d in audit_snmp.V3_DEFAULTS)


def _devices(store: Store, *ips: str) -> None:
    sid = store.begin_snapshot("discovery", "t")
    store.record_hosts(
        sid,
        [
            HostObservation(ip=ip, mac=f"aa:bb:cc:00:00:{i:02x}", source="t")
            for i, ip in enumerate(ips, start=1)
        ],
    )
    store.finish_snapshot(sid, len(ips))


def _findings(store: Store, config: Config) -> dict[str, tuple[str, Severity]]:
    ctx = RuleContext(store, config, store.begin_snapshot("t", "t"), None, is_baseline=False)
    result = Engine(config).run(ctx)
    return {
        f.title: (f.rule_id, f.severity)
        for f in result.emitted
        if f.rule_id.startswith("snmp.default")
    }


async def test_rules_flag_default_communities_and_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    fake_snmpget(tmp_path, monkeypatch)
    _devices(store, "192.0.2.10", "192.0.2.11")
    agent(tmp_path, "192.0.2.10", "public:2c", "private:1")
    agent(tmp_path, "192.0.2.11", "v3")
    await pipeline.snmp_audit(store, store.devices())
    found = _findings(store, config)
    assert len(found) == 2
    pub = next(v for k, v in found.items() if "'public'" in k and "(v2c)" in k)
    # The title says which device it is, from what it answered.
    assert any("(192.0.2.10, name-192.0.2.10, Test agent 192.0.2.10)" in k for k in found)
    priv = next(v for k, v in found.items() if "'private'" in k and "(v1)" in k)
    assert pub == ("snmp.default-community", Severity.HIGH)
    assert priv == ("snmp.default-community", Severity.CRITICAL)
    d = store.device_by_ip("192.0.2.11")
    assert d is not None and d.attrs["snmp_audit"]["v3_agent"] is True

    # Fixed on the device: the next probe gets no answer and the findings resolve.
    agent(tmp_path, "192.0.2.10", "v3")
    await pipeline.snmp_audit(store, store.devices())
    assert _findings(store, config) == {}


async def test_old_results_and_switched_off_do_not_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    fake_snmpget(tmp_path, monkeypatch)
    _devices(store, "192.0.2.10")
    agent(tmp_path, "192.0.2.10", "public:1")
    await pipeline.snmp_audit(store, store.devices())
    assert len(_findings(store, config)) == 1
    d = store.device_by_ip("192.0.2.10")
    assert d is not None
    old = dict(d.attrs["snmp_audit"], checked="2020-01-01T00:00:00+00:00")
    store.merge_device_attrs(d.id, {"snmp_audit": old})
    assert _findings(store, config) == {}
    store.merge_device_attrs(d.id, {"snmp_audit": dict(old, checked="2999-01-01T00:00:00+00:00")})
    config.snmp_audit.enabled = False
    assert _findings(store, config) == {}


async def test_one_missed_deep_scan_keeps_the_finding_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    """A device that is off on the day of one weekly deep scan goes two weeks between
    probes; its finding must stay open, not resolve and reopen. Three weeks resolves it."""
    fake_snmpget(tmp_path, monkeypatch)
    _devices(store, "192.0.2.10")
    agent(tmp_path, "192.0.2.10", "public:1")
    await pipeline.snmp_audit(store, store.devices())
    d = store.device_by_ip("192.0.2.10")
    assert d is not None
    week = config.schedule.deep_interval_s

    def probed_ago(seconds: float) -> None:
        at = iso(now_utc() - timedelta(seconds=seconds))
        store.merge_device_attrs(d.id, {"snmp_audit": dict(d.attrs["snmp_audit"], checked=at)})

    probed_ago(2 * week + 3600)
    assert len(_findings(store, config)) == 1
    probed_ago(3 * week + 3600)
    assert _findings(store, config) == {}


async def test_inventory_probes_new_and_deep_targets_not_the_hourly_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    """The probe rides on the service scan: for named (new) devices and the weekly deep
    scan, never the hourly light scan; scan.skip_hosts are left out."""
    rec = fake_snmpget(tmp_path, monkeypatch)
    _devices(store, "192.0.2.10", "192.0.2.11")

    async def no_nmap(ex: object, ips: list[str], cfg: object, deep: bool = False) -> object:
        from lanwatch.collectors.services import ServiceScanResult

        return ServiceScanResult()

    monkeypatch.setattr(pipeline, "scan_services", no_nmap)
    await pipeline.run_inventory(config, store)
    assert not (rec / "args").exists()

    config.scan.skip_hosts = ["192.0.2.11"]
    d10 = store.device_by_ip("192.0.2.10")
    d11 = store.device_by_ip("192.0.2.11")
    assert d10 is not None and d11 is not None
    await pipeline.run_inventory(config, store, device_ids=[d10.id, d11.id])
    hosts = {line.split()[-2] for line in (rec / "args").read_text().splitlines()}
    assert hosts == {"192.0.2.10"}

    config.snmp_audit.enabled = False
    (rec / "args").unlink()
    await pipeline.run_inventory(config, store, deep=True)
    assert not (rec / "args").exists()


def test_cli_snmp_audit_one_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_snmpget(tmp_path, monkeypatch)
    with Store(tmp_path / "lanwatch.db") as store:
        _devices(store, "192.0.2.10")
    agent(tmp_path, "192.0.2.10", "public:1", "v3")
    r = CliRunner().invoke(app, ["--data-dir", str(tmp_path), "snmp-audit", "192.0.2.10"])
    assert r.exit_code == 0, r.output
    assert "DEFAULT COMMUNITY answers: 'public' on v1" in r.output
    assert "name: name-192.0.2.10" in r.output and "description: Test agent" in r.output
    assert "sysObjectID: 1.3.6.1.4.1.11.2.3.9.1" in r.output
    assert "1 devices probed" in r.output
    r = CliRunner().invoke(app, ["--data-dir", str(tmp_path), "snmp-audit", "192.0.2.99"])
    assert r.exit_code == 1 and "no device" in r.output
