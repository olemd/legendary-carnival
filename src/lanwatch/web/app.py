"""Read-mostly web UI: dashboard, devices, findings, overview. Plus a small JSON API.

Bound to loopback by default. Binding wider requires web.password (HTTP basic auth).
"""

import secrets
import time
from collections.abc import Iterator
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

from fastapi import Body, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from lanwatch import __version__
from lanwatch.collectors.base import CommandError, make_executor
from lanwatch.config import Config
from lanwatch.models import FindingStatus, Severity, local_str
from lanwatch.overview import ports_summary, render
from lanwatch.overview import update as update_overview
from lanwatch.scheduler import Job, Scheduler
from lanwatch.store import Store

TEMPLATES = Path(__file__).parent / "templates"
SEVERITY_ORDER = [s.value for s in Severity]


def create_app(config: Config, scheduler: Scheduler | None = None) -> FastAPI:
    """`scheduler` is the one running in this process (`lanwatch run`). Without it
    (`lanwatch web`) the UI is read-only as far as scanning goes."""
    app = FastAPI(title="lanwatch", version=__version__, docs_url=None, redoc_url=None)
    templates = Jinja2Templates(directory=str(TEMPLATES))
    templates.env.filters["local"] = local_str
    templates.env.filters["duration"] = _duration
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

    def same_origin(request: Request) -> None:
        """Refuse cross-site form posts. A browser attaches the basic-auth credentials to
        every request for this origin, including one that a page on another site submits,
        but it also says where the request came from. Clients that are not browsers send
        neither header and are let through: they hold the password themselves."""
        site = request.headers.get("sec-fetch-site")
        if site is not None and site not in ("same-origin", "none"):
            raise HTTPException(403, "cross-site request refused")
        origin = request.headers.get("origin")
        if origin is not None and urlparse(origin).netloc != request.headers.get("host"):
            raise HTTPException(403, "cross-site request refused")

    StoreDep = Annotated[Store, Depends(store)]
    deps = [Depends(auth)]
    write_deps = [Depends(auth), Depends(same_origin)]

    def scan_state() -> dict[str, Any] | None:
        """The job the scheduler is running right now, if any."""
        job = scheduler.running if scheduler is not None else None
        if job is None or job.running_since is None:
            return None
        return {"job": job.name, "seconds": int(time.time() - job.running_since)}

    def page(request: Request, name: str, **ctx: Any) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            name,
            {
                "version": __version__,
                "config": config,
                "scan": scan_state(),
                "has_scheduler": scheduler is not None,
                **ctx,
            },
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
            events=s.events(limit=15, exclude_prefix="presence."),
            spark=_sparkline(s.snapshot_series("discovery", _days_ago(7))),
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
        # Other devices this one could be merged with; likely duplicates (same hostname) first.
        host = (d.hostname or "").lower()
        others = sorted(
            (o for o in s.devices() if o.id != d.id),
            key=lambda o: (not (host and (o.hostname or "").lower() == host), o.label.lower()),
        )
        from lanwatch.llm.tasks import DeviceKind

        return page(
            request,
            "device.html",
            device=d,
            services=s.services(device_id, open_only=False),
            findings=findings,
            last_inventory=s.last_inventory_at(device_id),
            events=s.events(device_id=device_id, limit=50),
            aliases=s.device_aliases(device_id),
            others=others,
            same_host={o.id for o in others if host and (o.hostname or "").lower() == host},
            kinds=[k.value for k in DeviceKind],
        )

    @app.post("/devices/{device_id}/edit", dependencies=write_deps)
    def edit_device(
        s: StoreDep,
        device_id: int,
        name: Annotated[str, Form()] = "",
        kind: Annotated[str, Form()] = "",
        description: Annotated[str, Form()] = "",
        watch: Annotated[bool, Form()] = False,  # an unticked checkbox is simply not sent
    ) -> RedirectResponse:
        ok = s.edit_device(
            device_id,
            name=name.strip()[:60] or None,
            kind=kind.strip().lower()[:40] or None,
            description=description.strip()[:200] or None,
            watch=watch,
        )
        if not ok:
            raise HTTPException(404)
        update_overview(s, config)
        return RedirectResponse(f"/devices/{device_id}", status_code=303)

    @app.post("/devices/{device_id}/merge", dependencies=write_deps)
    def merge_device(
        s: StoreDep, device_id: int, other: Annotated[int, Form()]
    ) -> RedirectResponse:
        if not s.merge_devices(device_id, other):
            raise HTTPException(404)
        update_overview(s, config)
        return RedirectResponse(f"/devices/{device_id}", status_code=303)

    @app.post("/devices/{device_id}/forget", dependencies=write_deps)
    def forget_device(s: StoreDep, device_id: int) -> RedirectResponse:
        if not s.delete_device(device_id):
            raise HTTPException(404)
        update_overview(s, config)
        return RedirectResponse("/devices", status_code=303)

    @app.post("/devices/{device_id}/name", dependencies=write_deps)
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

    @app.post("/findings/{finding_id}/ack", dependencies=write_deps)
    def ack(
        s: StoreDep,
        finding_id: str,
        back: Annotated[str, Form()] = "/findings",
        accept: Annotated[bool, Form()] = False,
        note: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        if not s.ack(finding_id, accept=accept, note=note.strip()[:300] or None):
            raise HTTPException(404)
        update_overview(s, config)
        return RedirectResponse(back if back.startswith("/") else "/findings", status_code=303)

    @app.post("/findings/{finding_id}/reopen", dependencies=write_deps)
    def reopen(
        s: StoreDep, finding_id: str, back: Annotated[str, Form()] = "/findings"
    ) -> RedirectResponse:
        if not s.reopen(finding_id):
            raise HTTPException(404)
        update_overview(s, config)
        return RedirectResponse(back if back.startswith("/") else "/findings", status_code=303)

    @app.get("/overview", response_class=HTMLResponse, dependencies=deps)
    def overview_page(request: Request, s: StoreDep) -> HTMLResponse:
        return page(request, "overview.html", markdown=render(s, config))

    @app.get("/timeline", response_class=HTMLResponse, dependencies=deps)
    def timeline_page(
        request: Request,
        s: StoreDep,
        kind: str | None = None,
        device: int | None = None,
        presence: bool = False,
        limit: int = 200,
    ) -> HTMLResponse:
        kinds = [kind] if kind else None
        rows = s.events(
            kinds=kinds,
            device_id=device,
            limit=min(limit, 1000),
            exclude_prefix=None if (presence or kind) else "presence.",
        )
        return page(
            request,
            "timeline.html",
            rows=rows,
            kinds=s.event_kinds(),
            kind=kind,
            device=device,
            presence=presence,
            devices_by_id={d.id: d for d in s.devices()},
        )

    @app.get("/search", response_class=HTMLResponse, dependencies=deps)
    def search_page(request: Request, s: StoreDep, q: str = "") -> HTMLResponse:
        res = s.search(q) if q.strip() else {"devices": [], "services": [], "findings": []}
        return page(
            request, "search.html", q=q, res=res, devices_by_id={d.id: d for d in s.devices()}
        )

    @app.get("/chat", response_class=HTMLResponse, dependencies=deps)
    def chat_page(request: Request) -> HTMLResponse:
        return page(request, "chat.html")

    @app.post("/api/chat", dependencies=write_deps)
    async def api_chat(s: StoreDep, body: Annotated[dict[str, Any], Body()]) -> dict[str, Any]:
        from lanwatch.llm.hooks import ask

        question = str(body.get("question", "")).strip()
        if not question:
            raise HTTPException(400, "question required")
        history = body.get("history") or []
        if not isinstance(history, list):
            history = []
        if not config.llm.enabled:
            return {"answer": None, "error": "LLM disabled in config"}
        allow_actions = bool(body.get("allow_actions", True))
        answer = await ask(config, s, question[:4000], history, allow_actions)
        if answer is None:
            return {"answer": None, "error": "LLM unavailable (is Ollama running?)"}
        return {"answer": answer.text, "tools": answer.tools}

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

    @app.get("/status", response_class=HTMLResponse, dependencies=deps)
    async def status_page(request: Request, s: StoreDep) -> HTMLResponse:
        llm = None
        if config.llm.enabled:
            from lanwatch.llm.client import OllamaClient

            client = OllamaClient(config.llm)
            try:
                llm = await client.status()
            finally:
                await client.aclose()
        db = config.store_path
        return page(
            request,
            "status.html",
            active="status",
            jobs=_job_rows(scheduler, s) if scheduler is not None else [],
            capability=await _scan_capability(config),
            llm=llm,
            db_bytes=db.stat().st_size if db.is_file() else 0,
            devices_total=len(s.devices()),
        )

    @app.post("/scan/{name}", dependencies=write_deps)
    def scan_now(name: str) -> RedirectResponse:
        if scheduler is None:
            raise HTTPException(409, "no scheduler in this process (started with `lanwatch web`)")
        if not scheduler.trigger(name):
            raise HTTPException(404)
        return RedirectResponse("/status", status_code=303)

    # -- api ----------------------------------------------------------------

    @app.get("/api/status", dependencies=deps)
    def api_status() -> dict[str, Any]:
        """Small and cheap: the header's scan indicator polls this."""
        return {"scheduler": scheduler is not None, "running": scan_state()}

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


def _duration(seconds: float | None) -> str:
    """Rough human duration: 42 s, 7 min, 3 h 5 min, 6 d."""
    if seconds is None:
        return "-"
    s = int(seconds)
    if s < 90:
        return f"{s} s"
    if s < 5400:
        return f"{round(s / 60)} min"
    if s < 172800:
        return f"{s // 3600} h {s % 3600 // 60} min"
    return f"{round(s / 86400)} d"


def _job_rows(scheduler: Scheduler, s: Store) -> list[dict[str, Any]]:
    """What the status page shows per job. "Last completed" comes from the database, so it
    survives restarts; the rest is the running process's own memory."""

    def row(j: Job) -> dict[str, Any]:
        last = s.meta_get(f"job.{j.name}.last_run")
        return {
            "name": j.name,
            "schedule": f"daily at {j.daily_at}"
            if j.daily_at
            else f"every {_duration(j.interval_s)}",
            "running_for": time.time() - j.running_since if j.running_since else None,
            "last_completed": (
                datetime.fromtimestamp(float(last), UTC).isoformat(timespec="seconds")
                if last
                else None
            ),
            "last_duration_s": j.last_duration_s,
            "last_error": j.last_error,
            "failures": j.failures,
            "next_in_s": max(0.0, j.next_due - time.monotonic()),
        }

    return [row(j) for j in scheduler.jobs]


async def _scan_capability(config: Config) -> dict[str, Any]:
    """Can scans use raw sockets, and through what? Asked of whatever executor the scans use,
    so with a helper socket configured this is the helper's own answer."""
    ex = make_executor(config.scan.helper_socket)
    info: dict[str, Any] = {"via": ex.name, "socket": config.scan.helper_socket, "error": None}
    try:
        info["nmap"], info["raw"] = await ex.which("nmap")
        info["arp_scan"], _ = await ex.which("arp-scan")
    except CommandError as e:
        info.update(nmap=False, arp_scan=False, raw=False, error=str(e))
    return info


def _sparkline(
    series: list[tuple[str, int]], width: int = 320, height: int = 40
) -> dict[str, Any] | None:
    """Points for an inline SVG polyline of hosts online over time."""
    if len(series) < 2:
        return None
    values = [v for _, v in series]
    lo, hi = min(values), max(values)
    span = max(1, hi - lo)
    n = len(values)
    pts = [
        f"{i * (width - 2) / (n - 1) + 1:.1f},{height - 2 - (v - lo) * (height - 4) / span:.1f}"
        for i, v in enumerate(values)
    ]
    return {
        "points": " ".join(pts),
        "width": width,
        "height": height,
        "min": lo,
        "max": hi,
        "last": values[-1],
        "first_ts": series[0][0],
        "last_ts": series[-1][0],
        "n": n,
    }


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
