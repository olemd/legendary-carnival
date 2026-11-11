"""Virtual machines recognised by their MAC prefix."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from lanwatch.config import Config
from lanwatch.llm.tasks import device_facts
from lanwatch.llm.tools import ToolRunner
from lanwatch.models import HostObservation, vm_platform
from lanwatch.overview import render
from lanwatch.rules.inventory import PrivateMacRule, UnregisteredMacRule
from lanwatch.store import Store
from lanwatch.web.app import create_app
from tests.test_mac_rules import _config
from tests.test_rules_and_overview import _round

PROXMOX = HostObservation(
    ip="10.0.0.30",
    mac="bc:24:11:00:00:30",
    vendor="Proxmox Server Solutions GmbH",
    source="t",
)
KVM = HostObservation(ip="10.0.0.31", mac="52:54:00:00:00:31", source="t")
HOST = HostObservation(ip="10.0.0.9", mac="e4:65:b8:00:00:09", vendor="Espressif", source="t")


def test_vm_platform() -> None:
    assert vm_platform("bc:24:11:12:34:56") == "Proxmox"
    assert vm_platform("BC:24:11:12:34:56") == "Proxmox"
    assert vm_platform("52:54:00:ab:cd:ef") == "QEMU/KVM"
    assert vm_platform("00:50:56:00:00:01") == "VMware"
    assert vm_platform("00:15:5d:00:00:01") == "Hyper-V"
    assert vm_platform("e4:65:b8:00:00:01") is None
    assert vm_platform(None) is None and vm_platform("") is None


def test_vms_are_neither_randomised_nor_unregistered(store: Store, tmp_path: Path) -> None:
    """QEMU's 52:54:00 is locally administered and in no registry, but it is the
    hypervisor's fixed prefix: no "randomised MAC" note, no "made-up prefix" finding."""
    config = _config(tmp_path)
    ctx = _round(store, config, [PROXMOX, KVM, HOST])
    kvm = store.device_by_key(KVM.mac or "")
    assert kvm is not None and kvm.vm == "QEMU/KVM" and not kvm.private_mac
    assert PrivateMacRule().evaluate(ctx) == []
    assert UnregisteredMacRule().evaluate(ctx) == []


def test_vm_shown_in_lists_pages_overview_and_llm(config: Config) -> None:
    with Store(config.store_path) as store:
        sid = store.begin_snapshot("discovery", "t")
        store.record_hosts(sid, [PROXMOX, KVM, HOST])
        store.finish_snapshot(sid, 3)
        vm = store.device_by_key(PROXMOX.mac or "")
        host = store.device_by_key(HOST.mac or "")
        assert vm is not None and host is not None
        assert vm.vm == "Proxmox" and host.vm is None

        text = render(store, config)
        assert "Proxmox Server Solutions GmbH (VM)" in text
        assert "QEMU/KVM (VM)" in text  # no vendor known: the platform stands in
        assert "Espressif (VM)" not in text

        facts = device_facts(vm, [])
        assert facts["virtual_machine"] == "Proxmox"
        # Absent rather than None elsewhere, so other devices' cache keys stay as they were.
        assert "virtual_machine" not in device_facts(host, [])

        tools = ToolRunner(config, store)
        rows = {r["ip"]: r for r in tools.t_list_devices()}
        assert rows["10.0.0.30"]["vm"] == "Proxmox" and rows["10.0.0.9"]["vm"] is None
        assert tools.t_get_device(vm.id)["vm"] == "Proxmox"

    client = TestClient(create_app(config))
    listing = client.get("/devices").text
    assert listing.count(">VM</span>") == 2
    page = client.get(f"/devices/{vm.id}").text
    assert ">VM</span>" in page and "Virtual network card (Proxmox)" in page
    assert ">VM</span>" not in client.get(f"/devices/{host.id}").text
