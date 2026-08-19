from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import EXPORT_DIR, MAX_UPLOAD_BYTES, UPLOAD_DIR
from app.db import get_db
from app.deps import require_user
from app.services.detail_to_risk import export_from_detailed_report, list_detailed_exports
from app.services.excel_export import ExportOptions, export_reports
from app.services.guidelines import guidelines_as_dicts
from app.services.json_parser import enrich_reports_from_uploads
from app.services.stats import load_reports

router = APIRouter(tags=["export"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def PathSafe(name: str) -> str:
    return name.replace("\\", "/").split("/")[-1]


def _page_ctx(
    request: Request,
    user,
    reports,
    *,
    logs: list[str] | None = None,
    files: list[str] | None = None,
    error: str | None = None,
    options: ExportOptions | None = None,
    selected_detail: str = "",
):
    return {
        "user": user,
        "active": "export",
        "reports": reports,
        "logs": logs or [],
        "files": files or [],
        "error": error,
        "options": options,
        "detail_files": list_detailed_exports(),
        "selected_detail": selected_detail,
    }


@router.post("/export/run", response_class=HTMLResponse)
async def export_run(
    request: Request,
    db: Session = Depends(get_db),
    detail: str | None = Form(None),
    summary: str | None = Form(None),
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
        _page_ctx(request, user, reports, logs=logs, files=files, error=error, options=options),
    )


@router.post("/export/from-detail", response_class=HTMLResponse)
async def export_from_detail(
    request: Request,
    db: Session = Depends(get_db),
    detail_file: UploadFile | None = File(None),
    existing_file: str | None = Form(None),
):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return user

    reports = load_reports(db)
    error = None
    logs: list[str] = []
    files: list[str] = []
    selected_detail = PathSafe(existing_file or "")
    src: Path | None = None
    uploaded_tmp: Path | None = None

    try:
        upload_name = (detail_file.filename or "").strip() if detail_file is not None else ""
        if upload_name:
            raw = await detail_file.read()
            if len(raw) > MAX_UPLOAD_BYTES:
                raise ValueError("업로드 파일이 너무 큽니다.")
            if not upload_name.lower().endswith(".xlsx"):
                raise ValueError("상세결과보고서는 .xlsx 파일이어야 합니다.")
            EXPORT_DIR.mkdir(parents=True, exist_ok=True)
            uploaded_tmp = EXPORT_DIR / f"_upload_{PathSafe(upload_name)}"
            uploaded_tmp.write_bytes(raw)
            src = uploaded_tmp
            selected_detail = PathSafe(upload_name)
        elif selected_detail:
            src = EXPORT_DIR / selected_detail
            if not src.exists() or not src.is_file() or "상세결과" not in selected_detail:
                raise ValueError("선택한 상세결과보고서 파일을 찾을 수 없습니다.")
        else:
            raise ValueError("상세결과보고서 엑셀을 업로드하거나 최근 생성 파일을 선택하세요.")

        result = export_from_detailed_report(src)
        logs = result.logs
        files = result.files
    except Exception as exc:  # noqa: BLE001 — surface to UI
        error = str(exc)
        logs = [f"오류: {exc}"]
    finally:
        if uploaded_tmp is not None and uploaded_tmp.exists() and uploaded_tmp.name.startswith("_upload_"):
            try:
                uploaded_tmp.unlink()
            except OSError:
                pass

    return templates.TemplateResponse(
        request,
        "export.html",
        _page_ctx(
            request,
            user,
            reports,
            logs=logs,
            files=files,
            error=error,
            selected_detail=selected_detail if not str(selected_detail).startswith("_upload_") else "",
        ),
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
