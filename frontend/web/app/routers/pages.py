from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.config import MAX_UPLOAD_BYTES, UPLOAD_DIR
from app.db import get_db
from app.deps import require_user
from app.models import DiagnosticItem, HostReport
from app.services.guidelines import guidelines_as_dicts, list_guidelines, update_guideline
from app.services.json_parser import parse_json_report
from app.services.stats import compute_stats, filter_diagnostics, filter_reports, load_reports

router = APIRouter(tags=["pages"])
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _authed(request: Request):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return user
    return user


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    host_type: str = "전체",
    db: Session = Depends(get_db),
):
    user = _authed(request)
    if isinstance(user, RedirectResponse):
        return user
    reports = filter_reports(load_reports(db), host_type)
    stats = compute_stats(reports)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "active": "dashboard",
            "reports": reports,
            "stats": stats,
            "host_type": host_type,
            "host_types": ["전체", "UNIX/Linux", "Windows Server", "개인 PC"],
            "flash": request.query_params.get("flash"),
        },
    )


@router.get("/details", response_class=HTMLResponse)
async def details(
    request: Request,
    report_id: int | None = None,
    status: str = "전체",
    q: str = "",
    db: Session = Depends(get_db),
):
    user = _authed(request)
    if isinstance(user, RedirectResponse):
        return user
    reports = load_reports(db)
    selected = None
    if report_id:
        selected = db.query(HostReport).filter(HostReport.id == report_id).first()
    if selected is None and reports:
        selected = reports[0]
    items = filter_diagnostics(selected.diagnostics if selected else [], status, q)
    item_id = request.query_params.get("item_id")
    selected_item = None
    if item_id and selected:
        selected_item = next((i for i in selected.diagnostics if str(i.id) == item_id), None)
    if selected_item is None and items:
        selected_item = items[0]
    return templates.TemplateResponse(
        request,
        "details.html",
        {
            "user": user,
            "active": "details",
            "reports": reports,
            "selected": selected,
            "items": items,
            "selected_item": selected_item,
            "status": status,
            "q": q,
            "statuses": ["전체", "Pass", "Fail", "N/A"],
        },
    )


@router.get("/guidelines", response_class=HTMLResponse)
async def guidelines_page(
    request: Request,
    os_type: str = "Linux",
    guideline_id: int | None = None,
    db: Session = Depends(get_db),
):
    user = _authed(request)
    if isinstance(user, RedirectResponse):
        return user
    rows = list_guidelines(db, os_type)
    selected = None
    if guideline_id:
        selected = next((g for g in rows if g.id == guideline_id), None)
    if selected is None and rows:
        selected = rows[0]
    return templates.TemplateResponse(
        request,
        "guidelines.html",
        {
            "user": user,
            "active": "guidelines",
            "os_type": os_type,
            "os_types": ["Linux", "Windows"],
            "rows": rows,
            "selected": selected,
            "reports": load_reports(db),
            "flash": request.query_params.get("flash"),
        },
    )


@router.post("/guidelines/save")
async def guidelines_save(
    request: Request,
    db: Session = Depends(get_db),
    guideline_id: int = Form(...),
    os_type: str = Form("Linux"),
    title: str = Form(""),
    remediation: str = Form(""),
    pass_comment: str = Form(""),
    fail_comment: str = Form(""),
):
    user = _authed(request)
    if isinstance(user, RedirectResponse):
        return user
    update_guideline(
        db,
        guideline_id,
        title=title,
        remediation=remediation,
        pass_comment=pass_comment,
        fail_comment=fail_comment,
    )
    return RedirectResponse(
        f"/guidelines?os_type={os_type}&guideline_id={guideline_id}&flash=saved",
        status_code=HTTP_303_SEE_OTHER,
    )


@router.get("/export", response_class=HTMLResponse)
async def export_page(request: Request, db: Session = Depends(get_db)):
    user = _authed(request)
    if isinstance(user, RedirectResponse):
        return user
    reports = load_reports(db)
    return templates.TemplateResponse(
        request,
        "export.html",
        {
            "user": user,
            "active": "export",
            "reports": reports,
            "logs": [],
            "files": [],
            "error": None,
        },
    )


@router.post("/upload")
async def upload_reports(
    request: Request,
    db: Session = Depends(get_db),
    files: list[UploadFile] = File(...),
):
    user = _authed(request)
    if isinstance(user, RedirectResponse):
        return user

    guides = guidelines_as_dicts(db)
    uploaded = 0
    skipped = 0
    for upload in files:
        name = upload.filename or "upload.json"
        if not name.lower().endswith(".json"):
            skipped += 1
            continue
        raw = await upload.read()
        if len(raw) > MAX_UPLOAD_BYTES:
            skipped += 1
            continue
        text = raw.decode("utf-8-sig", errors="replace")
        parsed = parse_json_report(text, name, guides)
        if parsed is None:
            skipped += 1
            continue

        # Replace same hostname+ip if present
        existing = (
            db.query(HostReport)
            .filter(
                HostReport.hostname == parsed.hostname,
                HostReport.ip_address == parsed.ip_address,
            )
            .first()
        )
        if existing:
            db.delete(existing)
            db.flush()

        dest = UPLOAD_DIR / Path(name).name
        dest.write_bytes(raw)

        report = HostReport(
            hostname=parsed.hostname,
            ip_address=parsed.ip_address,
            target_os=parsed.target_os,
            inspection_date=parsed.inspection_date,
            source_filename=parsed.source_filename,
        )
        for d in parsed.diagnostics:
            report.diagnostics.append(
                DiagnosticItem(
                    code=d.code,
                    category=d.category,
                    title=d.title,
                    status=d.status,
                    severity=d.severity,
                    description=d.description,
                    evidence=d.evidence,
                    remediation=d.remediation,
                    processed_config=d.processed_config,
                    err_msg=d.err_msg,
                )
            )
        db.add(report)
        uploaded += 1
    db.commit()
    flash = f"uploaded-{uploaded}-skipped-{skipped}"
    return RedirectResponse(f"/?flash={flash}", status_code=HTTP_303_SEE_OTHER)


@router.post("/hosts/{report_id}/delete")
async def delete_host(report_id: int, request: Request, db: Session = Depends(get_db)):
    user = _authed(request)
    if isinstance(user, RedirectResponse):
        return user
    report = db.query(HostReport).filter(HostReport.id == report_id).first()
    if report:
        db.delete(report)
        db.commit()
    return RedirectResponse("/?flash=deleted", status_code=HTTP_303_SEE_OTHER)
