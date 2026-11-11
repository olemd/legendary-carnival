"""The continuously maintained network overview: one markdown file, regenerated after
every round, written atomically, optionally committed to git for history."""

from __future__ import annotations

import logging
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from lanwatch.config import Config
from lanwatch.models import Device, FindingRow, FindingStatus, ServiceRow, iso, local_str, now_utc
from lanwatch.store import Store

log = logging.getLogger(__name__)


def _md_escape(s: str | None) -> str:
    return (s or "-").replace("|", "\\|")


def render(store: Store, config: Config, now: datetime | None = None) -> str:
    now = now or now_utc()
    devices = store.devices()
    online = [d for d in devices if d.online]
    open_findings = store.findings(FindingStatus.OPEN)
    acked = store.findings(FindingStatus.ACKED)
    latest = store.latest_snapshot("discovery")
    latest_inv = store.latest_snapshot("inventory")
    week_ago = iso(now - timedelta(days=7))
    recent = store.devices_first_seen_since(week_ago)

    lines: list[str] = []
    lines.append("# Network overview")
    lines.append("")
    lines.append(f"Generated {now.astimezone().strftime('%Y-%m-%d %H:%M')} by lanwatch.")
    if latest:
        lines.append(
            f"Last discovery: {local_str(latest.finished_at)} via {latest.source}, "
            f"{latest.host_count} hosts."
        )
    if latest_inv:
        lines.append(f"Last service inventory: {local_str(latest_inv.finished_at)}.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Devices known: {len(devices)}, online now: {len(online)}")
    lines.append(f"- Open findings: {len(open_findings)}, acknowledged: {len(acked)}")
    by_sev: dict[str, int] = {}
    for f in open_findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    if by_sev:
        lines.append("- Open by severity: " + ", ".join(f"{k} {v}" for k, v in by_sev.items()))
    lines.append("")

    lines.append("## Devices")
    lines.append("")
    services = store.open_services()
    lines.append("| | Name | IP | MAC | Vendor | Hostname | Open ports | First seen | Last seen |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for d in sorted(devices, key=_ip_sort_key):
        row = "| {on} | {name} | {ip} | {mac} | {vendor} | {host} | {ports} | {first} | {last} |"
        lines.append(
            row.format(
                on="●" if d.online else "○",
                name=_md_escape(d.name or d.kind),
                ip=_md_escape(d.ip),
                mac=_md_escape(d.mac),
                vendor=_md_escape(f"{d.vendor or d.vm} (VM)" if d.vm else d.vendor),
                host=_md_escape(d.hostname),
                ports=_md_escape(ports_summary(services.get(d.id, []))),
                first=local_str(d.first_seen),
                last=local_str(d.last_seen),
            )
        )
    lines.append("")

    lines.append("## Open findings")
    lines.append("")
    if not open_findings:
        lines.append("None.")
    else:
        lines.append("| Severity | Kind | Finding | Device | Since | ID |")
        lines.append("|---|---|---|---|---|---|")
        for f in open_findings:
            lines.append(_finding_row(store, f))
    lines.append("")

    if acked:
        lines.append("## Acknowledged findings")
        lines.append("")
        lines.append("| Severity | Kind | Finding | Device | Since | ID |")
        lines.append("|---|---|---|---|---|---|")
        for f in acked:
            lines.append(_finding_row(store, f))
        lines.append("")

    dhcp = store.infra("dhcp")
    upnp = store.infra("upnp")
    if dhcp or upnp:
        lines.append("## Infrastructure")
        lines.append("")
        if dhcp:
            servers = ", ".join(sorted({str(r.data.get("server")) for r in dhcp}))
            warn = "  **(more than one!)**" if len(dhcp) > 1 else ""
            lines.append(f"- DHCP servers: {servers}{warn}")
        for r in upnp:
            if r.data.get("is_igd"):
                n = len(r.data.get("mappings", []))
                lines.append(
                    f"- UPnP IGD: {r.data.get('friendly_name') or r.key} ({r.key}), "
                    f"external IP {r.data.get('external_ip') or '-'}, {n} port mapping(s)"
                )
                for m in r.data.get("mappings", []):
                    desc = f" {m['description']}" if m.get("description") else ""
                    lines.append(
                        f"  - {m.get('external_port')}/{m.get('protocol')} -> "
                        f"{m.get('internal_client')}:{m.get('internal_port')}{desc}"
                    )
        lines.append("")

    lines.append("## New devices, last 7 days")
    lines.append("")
    if not recent:
        lines.append("None.")
    else:
        for d in recent:
            lines.append(f"- {local_str(d.first_seen)}  {d.label}  {d.ip or '-'}  {d.mac or '-'}")
    lines.append("")
    return "\n".join(lines)


def ports_summary(services: list[ServiceRow], limit: int = 8) -> str:
    if not services:
        return ""
    parts = [f"{s.port}/{s.proto}" + (f" {s.name}" if s.name else "") for s in services]
    if len(parts) > limit:
        return ", ".join(parts[:limit]) + f", +{len(parts) - limit}"
    return ", ".join(parts)


def _finding_row(store: Store, f: FindingRow) -> str:
    dev = store.device(f.device_id) if f.device_id is not None else None
    label = _md_escape(dev.label if dev else None)
    return (
        f"| {f.severity.value} | {f.kind.value} | {_md_escape(f.title)} | {label} "
        f"| {local_str(f.first_seen)} | `{f.id}` |"
    )


def _ip_sort_key(d: Device) -> tuple[int, list[int]]:
    if not d.ip:
        return (1, [])
    try:
        return (0, [int(p) for p in d.ip.split(".")])
    except ValueError:
        return (1, [])


def write_atomic(path: Path, text: str) -> bool:
    """Write only if content changed. Returns True when the file was updated."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == text:
        return False
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)
    return True


def update(store: Store, config: Config) -> Path | None:
    if not config.overview.enabled:
        return None
    path = config.overview_path
    text = render(store, config)
    changed = write_atomic(path, text)
    if changed and config.overview.git:
        _git_commit(path)
    return path if changed else None


def _git_commit(path: Path) -> None:
    repo = path.parent
    try:
        if not (repo / ".git").exists():
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, timeout=30)
        subprocess.run(["git", "-C", str(repo), "add", path.name], check=True, timeout=30)
        msg = f"overview {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M')}"
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=lanwatch",
                "-c",
                "user.email=lanwatch@localhost",
                "commit",
                "-q",
                "-m",
                msg,
            ],
            check=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as e:
        log.warning("overview git commit failed: %s", e)
