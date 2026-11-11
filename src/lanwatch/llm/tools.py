"""Tools the inventory chat may call. Read tools query the store; action tools are the
same operations the CLI and web UI expose (ack, name, scan) and are only meant to run
when the user asked for them in the conversation. Every call is traced back to the user."""

from __future__ import annotations

import inspect
import json
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any

from lanwatch.config import Config
from lanwatch.links import other_end, phrase
from lanwatch.models import FindingStatus, Severity, local_str
from lanwatch.store import Store

log = logging.getLogger(__name__)

MAX_RESULT_CHARS = 12000


def _first_sentence(text: str) -> str:
    m = re.match(r"(.+?[.!?])(?:\s|$)", text, re.S)
    return m.group(1) if m else text


def _tool(
    name: str, description: str, properties: dict[str, Any], required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required or []},
        },
    }


TOOLS: list[dict[str, Any]] = [
    _tool(
        "list_devices",
        "List known devices with ip, mac, vendor, hostname, kind, online state and open port "
        "count. "
        "Filter with online_only or a substring match on any field.",
        {
            "online_only": {"type": "boolean"},
            "query": {"type": "string", "description": "substring to match"},
        },
    ),
    _tool(
        "get_device",
        "Full details of one device: facts, attributes (upnp, mdns, ipv6), open services with "
        "versions and script output, open findings, recent history, and links to related "
        "devices (a BMC that manages it, the switch it hangs off, the UPS that powers it).",
        {"device_id": {"type": "integer"}},
        ["device_id"],
    ),
    _tool(
        "list_findings",
        "List findings. status: open (default), acked, resolved or all. Optional severity filter "
        "and rule_id substring.",
        {
            "status": {"type": "string", "enum": ["open", "acked", "resolved", "all"]},
            "severity": {"type": "string", "enum": [s.value for s in Severity]},
            "rule": {"type": "string"},
        },
    ),
    _tool(
        "get_finding",
        "One finding with its evidence and stored explanation.",
        {"finding_id": {"type": "string"}},
        ["finding_id"],
    ),
    _tool(
        "search",
        "Substring search across devices, services and findings.",
        {"query": {"type": "string"}},
        ["query"],
    ),
    _tool(
        "timeline",
        "Recent events (device new/changed, services opened/closed, findings, infra changes). "
        "Optional kind filter (e.g. finding.opened) and device_id. include_presence adds "
        "online/offline events.",
        {
            "kind": {"type": "string"},
            "device_id": {"type": "integer"},
            "include_presence": {"type": "boolean"},
            "limit": {"type": "integer"},
        },
    ),
    _tool(
        "infrastructure",
        "DHCP servers seen, UPnP devices and router port mappings, devices with global IPv6, "
        "last scan times.",
        {},
    ),
    _tool(
        "list_rules",
        "The rules lanwatch evaluates, with description and effective severity.",
        {},
    ),
    _tool(
        "ack_finding",
        "ACTION: acknowledge an open finding so it stops being reported as new. Only when the "
        "user explicitly asks to acknowledge or dismiss it.",
        {"finding_id": {"type": "string"}},
        ["finding_id"],
    ),
    _tool(
        "name_device",
        "ACTION: give a device a human-readable name. Only when the user explicitly asks.",
        {"device_id": {"type": "integer"}, "name": {"type": "string"}},
        ["device_id", "name"],
    ),
    _tool(
        "run_scan",
        "ACTION: run a scan now. kind: discovery (who is on the network), inventory (services "
        "on online devices, or on device_ids), infra (DHCP/UPnP/IPv6 probes). Takes from "
        "seconds to minutes. Only when the user explicitly asks for a scan.",
        {
            "kind": {"type": "string", "enum": ["discovery", "inventory", "infra"]},
            "device_ids": {"type": "array", "items": {"type": "integer"}},
        },
        ["kind"],
    ),
]
ACTION_TOOLS = {"ack_finding", "name_device", "run_scan"}


@dataclass(slots=True)
class ToolTrace:
    name: str
    arguments: dict[str, Any]
    result_preview: str
    ok: bool


class ToolRunner:
    def __init__(self, config: Config, store: Store, allow_actions: bool = True) -> None:
        self.config = config
        self.store = store
        self.allow_actions = allow_actions
        self.trace: list[ToolTrace] = []

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        try:
            if name in ACTION_TOOLS and not self.allow_actions:
                result: Any = {"error": "actions are disabled in this session"}
            else:
                handler = getattr(self, f"t_{name}", None)
                if handler is None:
                    result = {"error": f"unknown tool {name}"}
                else:
                    result = (
                        await handler(**arguments)
                        if inspect.iscoroutinefunction(handler)
                        else handler(**arguments)
                    )
            ok = not (isinstance(result, dict) and "error" in result)
        except TypeError as e:
            result, ok = {"error": f"bad arguments: {e}"}, False
        except Exception as e:
            log.exception("tool %s failed", name)
            result, ok = {"error": f"{type(e).__name__}: {e}"}, False
        text = json.dumps(result, ensure_ascii=False, default=str)
        if len(text) > MAX_RESULT_CHARS:
            text = text[:MAX_RESULT_CHARS] + '... [truncated]"}'
        self.trace.append(ToolTrace(name, arguments, text[:200], ok))
        return text

    # -- read tools ---------------------------------------------------------

    def t_list_devices(
        self, online_only: bool = False, query: str | None = None
    ) -> list[dict[str, Any]]:
        services = self.store.open_services()
        out = []
        q = (query or "").lower().strip()
        for d in self.store.devices(online_only=online_only):
            row = {
                "id": d.id,
                "label": d.label,
                "ip": d.ip,
                "mac": d.mac,
                "vendor": d.vendor,
                "hostname": d.hostname,
                "name": d.name,
                "kind": d.kind,
                "description": d.description,
                "online": d.online,
                "last_seen": local_str(d.last_seen),
                "open_ports": len(services.get(d.id, [])),
            }
            if q and q not in json.dumps(row, ensure_ascii=False).lower():
                continue
            out.append(row)
        return out

    def t_get_device(self, device_id: int) -> dict[str, Any]:
        d = self.store.device(int(device_id))
        if d is None:
            return {"error": f"no device {device_id}"}
        return {
            **asdict(d),
            "first_seen": local_str(d.first_seen),
            "last_seen": local_str(d.last_seen),
            "services": [
                {
                    "port": s.port,
                    "proto": s.proto,
                    "name": s.name,
                    "product": s.product,
                    "version": s.version,
                    "tunnel": s.tunnel,
                    "scripts": list(s.details),
                }
                for s in self.store.services(d.id)
            ],
            "open_findings": [
                {"id": f.id, "severity": f.severity.value, "title": f.title}
                for f in self.store.findings(FindingStatus.OPEN)
                if f.device_id == d.id
            ],
            "history": [
                {"ts": local_str(e.ts), "kind": e.kind, "summary": e.summary}
                for e in self.store.events(device_id=d.id, limit=20)
            ],
            "links": [
                {"relation": phrase(link, d.id), "device_id": other_end(link, d.id)}
                for link in self.store.links(d.id)
            ],
        }

    def t_list_findings(
        self, status: str = "open", severity: str | None = None, rule: str | None = None
    ) -> list[dict[str, Any]]:
        st = None if status == "all" else FindingStatus(status)
        out = []
        for f in self.store.findings(st):
            if severity and f.severity.value != severity:
                continue
            if rule and rule.lower() not in f.rule_id:
                continue
            dev = self.store.device(f.device_id) if f.device_id is not None else None
            out.append(
                {
                    "id": f.id,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "device_id": f.device_id,
                    "device": dev.label if dev else None,
                    "since": local_str(f.first_seen),
                }
            )
        return out

    def t_get_finding(self, finding_id: str) -> dict[str, Any]:
        f = self.store.finding(str(finding_id))
        if f is None:
            return {"error": f"no finding {finding_id}"}
        d = asdict(f)
        d["severity"], d["kind"], d["status"] = f.severity.value, f.kind.value, f.status.value
        d["first_seen"], d["last_seen"] = local_str(f.first_seen), local_str(f.last_seen)
        return d

    def t_search(self, query: str) -> dict[str, Any]:
        res = self.store.search(str(query))
        return {
            "devices": [
                {"id": d.id, "label": d.label, "ip": d.ip, "kind": d.kind} for d in res["devices"]
            ],
            "services": [{"device_id": s.device_id, "service": s.label} for s in res["services"]],
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "title": f.title,
                }
                for f in res["findings"]
            ],
        }

    def t_timeline(
        self,
        kind: str | None = None,
        device_id: int | None = None,
        include_presence: bool = False,
        limit: int = 30,
    ) -> list[dict[str, Any]]:
        rows = self.store.events(
            kinds=[kind] if kind else None,
            device_id=device_id,
            limit=min(int(limit), 200),
            exclude_prefix=None if (include_presence or kind) else "presence.",
        )
        return [
            {"ts": local_str(e.ts), "kind": e.kind, "summary": e.summary, "device_id": e.device_id}
            for e in rows
        ]

    def t_infrastructure(self) -> dict[str, Any]:
        snaps = {
            k: self.store.latest_snapshot(k) for k in ("discovery", "inventory", "deep", "infra")
        }
        return {
            "dhcp_servers": [r.data for r in self.store.infra("dhcp")],
            "upnp": [{"address": r.key, **r.data} for r in self.store.infra("upnp")],
            "ipv6_devices": [
                {
                    "id": d.id,
                    "label": d.label,
                    "ipv6": d.attrs.get("ipv6"),
                    "ipv6_open": d.attrs.get("ipv6_open"),
                }
                for d in self.store.devices()
                if d.attrs.get("ipv6")
            ],
            "last_scans": {k: (local_str(s.finished_at) if s else None) for k, s in snaps.items()},
        }

    def t_list_rules(self) -> list[dict[str, Any]]:
        """Every rule with the first sentence of its description: the full texts of all
        rules together are longer than a tool result may be (MAX_RESULT_CHARS), and the
        first sentence says what the rule is about."""
        from lanwatch.rules.engine import all_rules

        out = []
        for r in all_rules():
            o = self.config.rules.get(r.id)
            sev = o.severity if o is not None and o.severity is not None else r.default_severity
            enabled = not (o is not None and o.enabled is False)
            out.append(
                {
                    "id": r.id,
                    "kind": r.kind.value,
                    "severity": sev.value,
                    "enabled": enabled,
                    "description": _first_sentence(r.description),
                }
            )
        return out

    # -- action tools -------------------------------------------------------

    def t_ack_finding(self, finding_id: str) -> dict[str, Any]:
        f = self.store.finding(str(finding_id))
        if f is None:
            return {"error": f"no finding {finding_id}"}
        if not self.store.ack(f.id):
            return {
                "error": f"finding {finding_id} is {f.status.value};"
                " only open findings can be acknowledged"
            }
        self.store.add_event("chat.action", f"Chat acknowledged: {f.title}", f.device_id, f.id)
        return {"ok": True, "finding_id": f.id, "title": f.title}

    def t_name_device(self, device_id: int, name: str) -> dict[str, Any]:
        d = self.store.device(int(device_id))
        if d is None:
            return {"error": f"no device {device_id}"}
        self.store.set_device_name(d.id, str(name).strip()[:60] or None)
        self.store.add_event("chat.action", f"Chat named device {d.id}: {name}", d.id)
        return {"ok": True, "device_id": d.id, "name": name}

    async def t_run_scan(self, kind: str, device_ids: list[int] | None = None) -> dict[str, Any]:
        from lanwatch import pipeline

        self.store.add_event("chat.action", f"Chat started {kind} scan")
        if kind == "discovery":
            d = await pipeline.run_discovery(self.config, self.store)
            return {
                "ok": True,
                "hosts": d.hosts,
                "new_devices": d.new_devices,
                "new_findings": d.new_findings,
            }
        if kind == "inventory":
            i = await pipeline.run_inventory(self.config, self.store, device_ids=device_ids or None)
            return {
                "ok": True,
                "devices_scanned": i.devices,
                "ports_opened": i.opened,
                "ports_closed": i.closed,
                "new_findings": i.new_findings,
            }
        if kind == "infra":
            f = await pipeline.run_infra(self.config, self.store)
            return {
                "ok": True,
                "dhcp_servers": f.dhcp_servers,
                "upnp_devices": f.upnp_devices,
                "port_mappings": f.igd_mappings,
                "new_findings": f.new_findings,
            }
        return {"error": f"unknown scan kind {kind}"}
