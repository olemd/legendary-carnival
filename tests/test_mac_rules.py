from __future__ import annotations

from pathlib import Path
from unittest import mock

from lanwatch import oui
from lanwatch.config import Config, LlmConfig
from lanwatch.models import HostObservation, Severity
from lanwatch.rules.engine import Engine
from lanwatch.rules.inventory import PrivateMacRule, UnregisteredMacRule
from lanwatch.store import Store
from tests.test_rules_and_overview import _round

REGISTRY = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,E465B8,Espressif Inc.,Shanghai\n"
)


def _config(tmp_path: Path) -> Config:
    (tmp_path / "oui").mkdir()
    (tmp_path / "oui" / "oui.csv").write_text(REGISTRY)
    return Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))


def test_new_device_with_randomised_mac_is_a_note(store: Store, tmp_path: Path) -> None:
    config = _config(tmp_path)
    engine = Engine(config)
    engine.run(
        _round(store, config, [HostObservation(ip="10.0.0.1", mac="e4:65:b8:00:00:01", source="t")])
    )
    res = engine.run(
        _round(
            store,
            config,
            [
                HostObservation(ip="10.0.0.1", mac="e4:65:b8:00:00:01", source="t"),
                HostObservation(ip="10.0.0.2", mac="da:a1:19:00:00:02", source="t"),  # a phone
                HostObservation(ip="10.0.0.3", mac="e4:65:b8:00:00:03", source="t"),
            ],
        )
    )
    new = {f.evidence["mac"]: f for f in res.emitted if f.rule_id == "inventory.new-device"}
    assert new["da:a1:19:00:00:02"].severity is Severity.LOW
    assert new["da:a1:19:00:00:02"].evidence["private_mac"] is True
    assert new["e4:65:b8:00:00:03"].severity is Severity.MEDIUM
    assert new["e4:65:b8:00:00:03"].evidence["private_mac"] is False


def test_private_and_unregistered_mac_rules(store: Store, tmp_path: Path) -> None:
    config = _config(tmp_path)
    ctx = _round(
        store,
        config,
        [
            HostObservation(ip="10.0.0.1", mac="e4:65:b8:00:00:01", source="t"),  # registered
            HostObservation(ip="10.0.0.2", mac="da:a1:19:00:00:02", source="t"),  # randomised
            HostObservation(ip="10.0.0.3", mac="00:11:22:00:00:03", source="t"),  # made up
            HostObservation(ip="10.0.0.4", source="t"),  # no MAC at all
        ],
    )
    private = PrivateMacRule().evaluate(ctx)
    assert [f.evidence["mac"] for f in private] == ["da:a1:19:00:00:02"]
    unregistered = UnregisteredMacRule().evaluate(ctx)
    assert [f.evidence["mac"] for f in unregistered] == ["00:11:22:00:00:03"]
    assert unregistered[0].severity is Severity.LOW


def test_unregistered_mac_rule_needs_a_registry(store: Store, tmp_path: Path) -> None:
    """With no registry at hand nothing is reported, rather than everything."""
    config = Config(data_dir=tmp_path, llm=LlmConfig(enabled=False))
    ctx = _round(
        store, config, [HostObservation(ip="10.0.0.3", mac="00:11:22:00:00:03", source="t")]
    )
    with mock.patch.object(oui, "load", return_value=oui.Registry()):
        assert UnregisteredMacRule().evaluate(ctx) == []
