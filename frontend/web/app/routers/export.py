from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import EXPORT_DIR, UPLOAD_DIR
from app.db import get_db
from app.deps import require_user
from app.services.excel_export import ExportOptions, export_reports
from app.services.guidelines import guidelines_as_dicts
from app.services.json_parser import enrich_reports_from_uploads
from app.services.stats import load_reports

router = APIRouter(tags=["export"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


@router.post("/export/run", response_class=HTMLResponse)
async def export_run(
    request: Request,
    db: Session = Depends(get_db),
    detail: str | None = Form(None),
    summary: str | None = Form(None),
    action_plan: str | None = Form(None),
    unix: str | None = Form(None),
    dbms: str | None = Form(None),
    win_server: str | None = Form(None),
    pc: str | None = Form(None),
):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return user

    reports = load_reports(db)
    guides = guidelines_as_dicts(db)
    # Restore Manual/Interview/Error + VulnerableConfig lost on older uploads.
    if enrich_reports_from_uploads(reports, UPLOAD_DIR, guides):
        db.commit()

    options = ExportOptions(
        detail=detail is not None,
        summary=summary is not None,
        action_plan=action_plan is not None,
        unix=unix is not None,
        dbms=dbms is not None,
        win_server=win_server is not None,
        pc=pc is not None,
    )
    error = None
    logs: list[str] = []
    files: list[str] = []
    try:
        result = export_reports(reports, options, guidelines=guides)
        logs = result.logs
        files = result.files
    except Exception as exc:  # noqa: BLE001 — surface to UI
        error = str(exc)
        logs = [f"오류: {exc}"]

    return templates.TemplateResponse(
        request,
        "export.html",
        {
            "user": user,
            "active": "export",
            "reports": reports,
            "logs": logs,
            "files": files,
            "error": error,
            "options": options,
        },
    )


@router.get("/export/download/{filename}")
async def export_download(filename: str, request: Request):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return user
    # Prevent path traversal
    safe = PathSafe(filename)
    path = EXPORT_DIR / safe
    if not path.exists() or not path.is_file():
        return RedirectResponse("/export")
    return FileResponse(path, filename=safe, media_type="application/octet-stream")


def PathSafe(name: str) -> str:
    return name.replace("\\", "/").split("/")[-1]
