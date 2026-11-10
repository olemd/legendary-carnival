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
    """Put a fake snmpbulkwalk first on PATH. It records its arguments, environment and the
    config file it was given, then prints `output`."""
    bin_dir = tmp_path / "bin"
    rec = tmp_path / "rec"
    bin_dir.mkdir()
    rec.mkdir()
    (tmp_path / "out.txt").write_text(output)
    (tmp_path / "err.txt").write_text(stderr)
    script = bin_dir / "snmpbulkwalk"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" > {rec}/args\n'
        f'echo "$SNMPCONFPATH" > {rec}/dir\n'
        f"env > {rec}/env\n"
        f'cp "$SNMPCONFPATH/snmp.conf" {rec}/conf\n'
        f'stat -c %a "$SNMPCONFPATH/snmp.conf" > {rec}/mode\n'
        f"cat {tmp_path}/out.txt\n"
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: Store, config: Config
) -> None:
    config.snmp = snmp_config(host=None)

    async def gateways(ex: object = None) -> list[str]:
        return ["192.0.2.1"]

    monkeypatch.setattr(pipeline, "default_gateways", gateways)
    rec = fake_walker(tmp_path, monkeypatch, (FIXTURES / "snmp-system.txt").read_text())
    out = await pipeline.collect_snmp(config, store)
    assert out.error is None and out.host == "192.0.2.1"
    assert "192.0.2.1" in (rec / "args").read_text()  # the gateway, as no host was set
    system = json.loads(store.meta_get("snmp.system") or "{}")
    assert system["name"] == "gw-test" and system["vendor"] == "Juniper"
    assert store.meta_get("snmp.last_error") == ""

    (tmp_path / "out.txt").write_text("")
    (tmp_path / "err.txt").write_text("snmpbulkwalk: Authentication failure (incorrect password)")
    script = tmp_path / "bin" / "snmpbulkwalk"
    script.write_text(script.read_text().replace("exit 0", "exit 1"))
    out = await pipeline.collect_snmp(config, store)
    assert out.error is not None and "auth_password" in out.error
    assert store.meta_get("snmp.last_error") == out.error
    assert json.loads(store.meta_get("snmp.system") or "{}")["name"] == "gw-test"


def test_cli_snmp_off(tmp_path: Path) -> None:
    r = CliRunner().invoke(app, ["--data-dir", str(tmp_path), "snmp"])
    assert r.exit_code == 1 and "docs/snmp.md" in r.output
