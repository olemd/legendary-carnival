from __future__ import annotations

import json

from lanwatch.collectors.discovery import (
    parse_arp_scan_plain,
    parse_ip_neigh_json,
    parse_nmap_xml_hosts,
)
from lanwatch.config import NetworkConfig
from lanwatch.netinfo import parse_ip_addr_json, select_subnets, self_observations
from tests.conftest import fixture_text


def test_parse_arp_scan() -> None:
    hosts = parse_arp_scan_plain(fixture_text("arp-scan-plain.txt"))
    assert [h.ip for h in hosts] == ["192.168.1.1", "192.168.1.20", "192.168.1.33"]
    assert hosts[1].mac == "aa:bb:cc:00:00:14"  # normalised
    assert hosts[1].vendor is None  # "(Unknown)" dropped
    assert hosts[2].vendor == "Raspberry Pi Trading Ltd"
    assert hosts[0].key == "aa:bb:cc:00:00:01"


def test_parse_nmap_sn() -> None:
    hosts = parse_nmap_xml_hosts(fixture_text("nmap-sn.xml"))
    assert len(hosts) == 2
    gw, other = hosts
    assert (
        gw.mac == "aa:bb:cc:00:00:01" and gw.vendor == "Ubiquiti" and gw.hostname == "gateway.lan"
    )
    assert other.mac is None and other.key == "ip:192.168.1.50"


def test_parse_ip_neigh() -> None:
    data: list[dict[str, object]] = [
        {"dst": "192.168.1.1", "lladdr": "aa:bb:cc:00:00:01", "state": ["REACHABLE"]},
        {"dst": "192.168.1.7", "state": ["FAILED"]},
        {"dst": "192.168.1.8", "lladdr": "aa:bb:cc:00:00:08", "state": ["FAILED"]},
        {"dst": "fe80::1", "lladdr": "aa:bb:cc:00:00:09", "state": ["STALE"]},
    ]
    assert parse_ip_neigh_json(data) == {"192.168.1.1": "aa:bb:cc:00:00:01"}


def test_select_subnets_auto_defaults() -> None:
    ifaces = parse_ip_addr_json(json.loads(fixture_text("ip-addr.json")))
    subs = select_subnets(ifaces, NetworkConfig())
    # lo: loopback. docker0/wg0: excluded by pattern. eth1: down. eth2: /16 too wide.
    assert [str(s) for s in subs] == ["192.168.1.0/24 via eth0"]
    assert self_observations(ifaces, subs) == [("192.168.1.10", "aa:bb:cc:dd:ee:ff")]


def test_select_subnets_explicit_and_wide() -> None:
    ifaces = parse_ip_addr_json(json.loads(fixture_text("ip-addr.json")))
    cfg = NetworkConfig(subnets=["10.10.0.0/16", "172.16.5.0/24"], max_auto_prefix=16)
    subs = select_subnets(ifaces, cfg)
    assert [str(s) for s in subs] == ["10.10.0.0/16 via eth2", "172.16.5.0/24"]
    auto = select_subnets(ifaces, NetworkConfig(max_auto_prefix=16))
    assert {str(s.network) for s in auto} == {"192.168.1.0/24", "10.10.0.0/16"}


def test_parse_proc_net_arp() -> None:
    from lanwatch.collectors.discovery import parse_proc_net_arp

    text = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.1      0x1         0x2         aa:bb:cc:00:00:01     *        eth0\n"
        "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        "192.168.1.3      0x1         0x6         aa:bb:cc:00:00:03     *        eth0\n"
    )
    assert parse_proc_net_arp(text) == {
        "192.168.1.1": "aa:bb:cc:00:00:01",
        "192.168.1.3": "aa:bb:cc:00:00:03",
    }


def test_list_interfaces_ioctl_runs_on_linux() -> None:
    from lanwatch.netinfo import list_interfaces_ioctl

    ifaces = list_interfaces_ioctl()
    assert any(i.name == "lo" for i in ifaces)
    lo = next(i for i in ifaces if i.name == "lo")
    assert lo.mac is None and any(str(a.ip) == "127.0.0.1" for a in lo.addrs)
