"""Read-mostly web UI: dashboard, devices, findings, overview. Plus a small JSON API.

Bound to loopback by default. Binding wider requires web.password (HTTP basic auth).
"""

import secrets
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from lanwatch import __version__
from lanwatch.config import Config
from lanwatch.models import FindingStatus, Severity, local_str
from lanwatch.overview import ports_summary, render
from lanwatch.overview import update as update_overview
from lanwatch.store import Store

TEMPLATES = Path(__file__).parent / "templates"
SEVERITY_ORDER = [s.value for s in Severity]


def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="lanwatch", version=__version__, docs_url=None, redoc_url=None)
    templates = Jinja2Templates(directory=str(TEMPLATES))
    templates.env.filters["local"] = local_str
    basic = HTTPBasic(auto_error=False)

    def auth(creds: Annotated[HTTPBasicCredentials | None, Depends(basic)]) -> None:
        if not config.web.password:
            return
        ok = creds is not None and secrets.compare_digest(
            creds.password.encode(), config.web.password.encode()
        )
        if not ok:
            raise HTTPException(401, headers={"WWW-Authenticate": "Basic realm=lanwatch"})

    def store() -> Iterator[Store]:
        with Store(config.store_path, check_same_thread=False) as s:
            yield s

    StoreDep = Annotated[Store, Depends(store)]
    deps = [Depends(auth)]

    def page(request: Request, name: str, **ctx: Any) -> HTMLResponse:
        return templates.TemplateResponse(
            request, name, {"version": __version__, "config": config, **ctx}
        )

    # -- pages --------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse, dependencies=deps)
    def dashboard(request: Request, s: StoreDep) -> HTMLResponse:
        devices = s.devices()
        open_f = s.findings(FindingStatus.OPEN)
        counts = {sev: sum(1 for f in open_f if f.severity.value == sev) for sev in SEVERITY_ORDER}
        return page(
            request,
            "dashboard.html",
            devices_total=len(devices),
            devices_online=sum(1 for d in devices if d.online),
            findings=open_f[:25],
            findings_total=len(open_f),
            counts=counts,
            devices_by_id={d.id: d for d in devices},
            snapshots={
                k: s.latest_snapshot(k) for k in ("discovery", "inventory", "deep", "infra")
            },
            infra_summary={
                "dhcp": sorted({str(r.data.get("server")) for r in s.infra("dhcp")}),
                "igd": [r for r in s.infra("upnp") if r.data.get("is_igd")],
                "mappings": sum(len(r.data.get("mappings", [])) for r in s.infra("upnp")),
            },
            recent=s.devices_first_seen_since(_days_ago(7)),
            digest=_latest_digest(config, s),
        )

    @app.get("/devices", response_class=HTMLResponse, dependencies=deps)
    def devices_page(request: Request, s: StoreDep) -> HTMLResponse:
        services = s.open_services()
        rows = [(d, ports_summary(services.get(d.id, []))) for d in s.devices()]
        rows.sort(key=lambda r: _ip_key(r[0].ip))
        open_by_dev: dict[int, int] = {}
        for f in s.findings(FindingStatus.OPEN):
            if f.device_id is not None:
                open_by_dev[f.device_id] = open_by_dev.get(f.device_id, 0) + 1
        return page(request, "devices.html", rows=rows, open_by_dev=open_by_dev)

    @app.get("/devices/{device_id}", response_class=HTMLResponse, dependencies=deps)
    def device_page(request: Request, s: StoreDep, device_id: int) -> HTMLResponse:
        d = s.device(device_id)
        if d is None:
            raise HTTPException(404)
        findings = [f for f in s.findings(None) if f.device_id == device_id]
        return page(
            request,
            "device.html",
            device=d,
            services=s.services(device_id, open_only=False),
            findings=findings,
            last_inventory=s.last_inventory_at(device_id),
        )

    @app.post("/devices/{device_id}/name", dependencies=deps)
    def set_name(
        s: StoreDep, device_id: int, name: Annotated[str, Form()] = ""
    ) -> RedirectResponse:
        if not s.set_device_name(device_id, name.strip() or None):
            raise HTTPException(404)
        update_overview(s, config)
        return RedirectResponse(f"/devices/{device_id}", status_code=303)

    @app.get("/findings", response_class=HTMLResponse, dependencies=deps)
    def findings_page(request: Request, s: StoreDep, status: str = "open") -> HTMLResponse:
        st = None if status == "all" else FindingStatus(status)
        findings = s.findings(st)
        devices = {d.id: d for d in s.devices()}
        return page(
            request, "findings.html", findings=findings, status=status, devices_by_id=devices
        )

    @app.post("/findings/{finding_id}/ack", dependencies=deps)
    def ack(
        s: StoreDep, finding_id: str, back: Annotated[str, Form()] = "/findings"
    ) -> RedirectResponse:
        if not s.ack(finding_id):
            raise HTTPException(404)
        update_overview(s, config)
        return RedirectResponse(back if back.startswith("/") else "/findings", status_code=303)

    @app.get("/overview", response_class=HTMLResponse, dependencies=deps)
    def overview_page(request: Request, s: StoreDep) -> HTMLResponse:
        return page(request, "overview.html", markdown=render(s, config))

    @app.get("/infra", response_class=HTMLResponse, dependencies=deps)
    def infra_page(request: Request, s: StoreDep) -> HTMLResponse:
        upnp = s.infra("upnp")
        return page(
            request,
            "infra.html",
            dhcp=s.infra("dhcp"),
            upnp=upnp,
            igds=[r for r in upnp if r.data.get("is_igd")],
            ipv6=[d for d in s.devices() if d.attrs.get("ipv6")],
            devices_by_ip={d.ip: d for d in s.devices() if d.ip},
            snapshot=s.latest_snapshot("infra"),
        )

    @app.get("/notifications", response_class=HTMLResponse, dependencies=deps)
    def notifications_page(request: Request, s: StoreDep) -> HTMLResponse:
        from lanwatch.notify.dispatch import channels

        return page(
            request,
            "notifications.html",
            rows=s.notifications(200),
            channels=[c.name for c in channels(config)],
        )

    @app.get("/digest", response_class=HTMLResponse, dependencies=deps)
    def digest_page(request: Request, s: StoreDep, day: str | None = None) -> HTMLResponse:
        files = sorted(config.report_dir.glob("digest-*.md"), reverse=True)
        chosen = next(
            (f for f in files if day and f.stem == f"digest-{day}"), files[0] if files else None
        )
        return page(
            request,
            "digest.html",
            days=[f.stem.removeprefix("digest-") for f in files],
            chosen=chosen.stem.removeprefix("digest-") if chosen else None,
            text=chosen.read_text() if chosen else None,
            suggestions=_read_report(config, "suggestions.md"),
        )

    # -- api ----------------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/devices", dependencies=deps)
    def api_devices(s: StoreDep) -> list[dict[str, Any]]:
        services = s.open_services()
        return [
            {**asdict(d), "services": [asdict(sv) for sv in services.get(d.id, [])]}
            for d in s.devices()
        ]

    @app.get("/api/findings", dependencies=deps)
    def api_findings(s: StoreDep, status: str = "open") -> list[dict[str, Any]]:
        st = None if status == "all" else FindingStatus(status)
        return [asdict(f) for f in s.findings(st)]

    @app.get("/api/overview.md", response_class=PlainTextResponse, dependencies=deps)
    def api_overview(s: StoreDep) -> str:
        return render(s, config)

    return app


def _read_report(config: Config, name: str) -> str | None:
    p = config.report_dir / name
    return p.read_text() if p.is_file() else None


def _latest_digest(config: Config, s: Store) -> tuple[str, str] | None:
    """(day, summary paragraph) of the newest digest, for the dashboard."""
    latest = s.meta_get("digest.latest")
    p = Path(latest) if latest else None
    if p is None or not p.is_file():
        files = sorted(config.report_dir.glob("digest-*.md"))
        p = files[-1] if files else None
    if p is None:
        return None
    body = p.read_text().split("\n\n")
    summary = body[1].strip() if len(body) > 1 else ""
    return p.stem.removeprefix("digest-"), summary


def _days_ago(days: int) -> str:
    from datetime import timedelta

    from lanwatch.models import iso, now_utc

    return iso(now_utc() - timedelta(days=days))


def _ip_key(ip: str | None) -> tuple[int, list[int]]:
    try:
        return (0, [int(p) for p in (ip or "").split(".")])
    except ValueError:
        return (1, [])
