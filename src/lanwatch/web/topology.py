"""Layout for the topology page: the network as the UniFi controller sees it, as a tree the
template draws with plain SVG and repeats as a nested list.

Gateway at the top left; each UniFi device (access point, switch) in the next column under
its uplink; clients in the column after that, grouped under the device they hang off. Rows
are handed out depth-first, so a device's clients sit directly beneath it and the picture
reads top to bottom like the list. Pure function of the stored infra rows: no store writes,
no network, easy to test."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lanwatch.collectors.unifi import OFFLINE_STATES
from lanwatch.store import Store

COLUMN_W = 250
ROW_H = 28
LEFT = 40
TOP = 30
NODE_W = 210
NODE_H = 22
MAX_CLIENTS_PER_DEVICE = 40
NETWORK_CLASSES = 8  # net-0 .. net-7 in the stylesheet


@dataclass(slots=True)
class Node:
    label: str
    kind: str  # gateway | ap | switch | client | more
    depth: int
    row: int
    sub: str = ""
    network: str | None = None
    net_class: int | None = None
    device_id: int | None = None
    state: str | None = None
    guest: bool = False
    wired: bool | None = None
    children: list[Node] = field(default_factory=list)

    @property
    def x(self) -> int:
        return LEFT + self.depth * COLUMN_W

    @property
    def y(self) -> int:
        return TOP + self.row * ROW_H

    @property
    def offline(self) -> bool:
        return bool(self.state and self.state in OFFLINE_STATES)

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "kind": self.kind,
            "x": self.x,
            "y": self.y,
            "sub": self.sub,
            "network": self.network,
            "net_class": self.net_class,
            "device_id": self.device_id,
            "state": self.state,
            "offline": self.offline,
            "guest": self.guest,
            "wired": self.wired,
            "children": [c.as_dict() for c in self.children],
        }


def _device_kind(d: dict[str, Any]) -> str:
    if d.get("is_gateway"):
        return "gateway"
    if d.get("is_access_point"):
        return "ap"
    return "switch"


def build_topology(store: Store) -> dict[str, Any] | None:
    """None when the controller has never been read. Otherwise the tree, the flat node and
    edge lists the SVG needs, its size, and a legend of networks."""
    devices = [r.data for r in store.infra("unifi-device")]
    if not devices:
        return None
    clients = [r.data for r in store.infra("unifi-client")]
    networks = sorted(
        (r.data for r in store.infra("unifi-network")),
        key=lambda n: (str(n.get("vlan") or 0), n["id"]),
    )
    net_class = {n["id"]: i % NETWORK_CLASSES for i, n in enumerate(networks)}
    by_mac = {d.mac: d for d in store.devices() if d.mac}

    by_id = {str(d.get("id")): d for d in devices}
    children_of: dict[str | None, list[dict[str, Any]]] = {}
    gateways = [d for d in devices if d.get("is_gateway")]
    root_id = str(gateways[0].get("id")) if gateways else None
    for d in devices:
        if d.get("is_gateway"):
            continue
        up = (d.get("uplink") or {}).get("id")
        parent = str(up) if up in by_id else root_id  # unknown uplink: hang off the gateway
        children_of.setdefault(parent, []).append(d)
    clients_of: dict[str | None, list[dict[str, Any]]] = {}
    for c in clients:
        up = c.get("uplink_id")
        clients_of.setdefault(str(up) if up in by_id else root_id, []).append(c)

    rows = 0
    nodes: list[Node] = []
    edges: list[tuple[int, int, int, int]] = []

    def device_node(d: dict[str, Any], depth: int) -> Node:
        nonlocal rows
        mac = d.get("mac")
        known = by_mac.get(mac) if isinstance(mac, str) else None
        n = Node(
            label=str(d.get("name") or d.get("model") or mac),
            kind=_device_kind(d),
            depth=depth,
            row=rows,
            sub=" · ".join(str(x) for x in (d.get("model"), d.get("ip")) if x),
            device_id=known.id if known else None,
            state=str(d.get("state") or ""),
        )
        rows += 1
        nodes.append(n)
        return n

    def attach_clients(parent: Node, parent_id: str | None) -> None:
        nonlocal rows
        group = sorted(
            clients_of.get(parent_id, []),
            key=lambda c: (str(c.get("network_name") or ""), str(c.get("name") or c.get("mac"))),
        )
        for c in group[:MAX_CLIENTS_PER_DEVICE]:
            mac = c.get("mac")
            known = by_mac.get(mac) if isinstance(mac, str) else None
            n = Node(
                label=str((known.label if known else None) or c.get("name") or mac),
                kind="client",
                depth=parent.depth + 1,
                row=rows,
                sub=str(c.get("ip") or ""),
                network=c.get("network_name"),
                net_class=net_class.get(str(c.get("network_id"))) if c.get("network_id") else None,
                device_id=known.id if known else None,
                guest=bool(c.get("guest")),
                wired=c.get("type") == "WIRED",
            )
            rows += 1
            nodes.append(n)
            parent.children.append(n)
            edges.append((parent.x + NODE_W, parent.y + NODE_H // 2, n.x, n.y + NODE_H // 2))
        if len(group) > MAX_CLIENTS_PER_DEVICE:
            n = Node(
                label=f"+{len(group) - MAX_CLIENTS_PER_DEVICE} more",
                kind="more",
                depth=parent.depth + 1,
                row=rows,
            )
            rows += 1
            nodes.append(n)
            parent.children.append(n)

    def walk(d: dict[str, Any], depth: int) -> Node:
        n = device_node(d, depth)
        attach_clients(n, str(d.get("id")))
        for child in sorted(
            children_of.get(str(d.get("id")), []), key=lambda x: str(x.get("name"))
        ):
            cn = walk(child, depth + 1)
            edges.append((n.x + NODE_W, n.y + NODE_H // 2, cn.x, cn.y + NODE_H // 2))
            n.children.append(cn)
        return n

    roots: list[Node] = []
    if gateways:
        roots.append(walk(gateways[0], 0))
        for extra in gateways[1:]:
            roots.append(walk(extra, 0))
    else:
        # No gateway among the adopted devices (another vendor's router): every UniFi
        # device is a root of its own, and the unassigned clients go under the first.
        for d in devices:
            roots.append(walk(d, 0))
    if root_id is None and roots and clients_of.get(None):
        attach_clients(roots[0], None)

    depth_max = max((n.depth for n in nodes), default=0)
    legend = [
        {
            "name": n.get("name"),
            "vlan": n.get("vlan"),
            "net_class": net_class[n["id"]],
            "default": n.get("default"),
            "clients": sum(1 for c in clients if c.get("network_id") == n["id"]),
        }
        for n in networks
    ]
    return {
        "nodes": [n.as_dict() for n in nodes],
        "edges": edges,
        "tree": [r.as_dict() for r in roots],
        "width": LEFT * 2 + (depth_max + 1) * COLUMN_W - (COLUMN_W - NODE_W),
        "height": TOP + rows * ROW_H + 10,
        "node_w": NODE_W,
        "node_h": NODE_H,
        "legend": legend,
        "devices": len(devices),
        "clients": len(clients),
        "offline": sum(1 for d in devices if str(d.get("state")) in OFFLINE_STATES),
        "unknown_clients": sum(1 for c in clients if not c.get("known")),
    }
