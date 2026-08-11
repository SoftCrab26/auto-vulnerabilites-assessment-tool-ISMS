from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from openpyxl import load_workbook

from app.config import EXCEL_TEMPLATE_DIR, EXPORT_DIR
from app.models import HostReport
from app.services.stats import classify_host_type


@dataclass
class ExportOptions:
    detail: bool = True
    summary: bool = False
    action_plan: bool = False
    unix: bool = True
    win_server: bool = True
    pc: bool = True


@dataclass
class ExportResult:
    files: list[str]
    logs: list[str]


def _unique_path(directory: Path, base: str, ext: str) -> Path:
    candidate = directory / f"{base}{ext}"
    idx = 1
    while candidate.exists():
        candidate = directory / f"{base}_{idx}{ext}"
        idx += 1
    return candidate


def _status_ko_detail(status: str) -> str:
    s = (status or "").upper()
    if s == "PASS":
        return "양호"
    if s == "FAIL":
        return "취약"
    return "N/A"


def _status_yn(status: str) -> str:
    s = (status or "").upper()
    if s == "PASS":
        return "Y"
    if s == "FAIL":
        return "N"
    return "N/A"


def _filter_reports(reports: list[HostReport], options: ExportOptions) -> list[HostReport]:
    selected: list[HostReport] = []
    for report in reports:
        host_type = classify_host_type(report.target_os)
        if host_type == "UNIX/Linux" and options.unix:
            selected.append(report)
        elif host_type == "Windows Server" and options.win_server:
            selected.append(report)
        elif host_type == "개인 PC" and options.pc:
            selected.append(report)
        elif host_type == "기타":
            selected.append(report)
    return selected


def _group_by_os(reports: list[HostReport]) -> dict[str, list[HostReport]]:
    groups: dict[str, list[HostReport]] = {}
    for report in reports:
        key = (report.target_os or "UNIX").strip().upper() or "UNIX"
        groups.setdefault(key, []).append(report)
    return groups


def _diag_map(report: HostReport) -> dict[str, object]:
    return {d.code.upper(): d for d in report.diagnostics if d.code}


def _safe_sheet_name(name: str) -> str:
    cleaned = "".join("_" if c in r"[]:*?/\\" else c for c in (name or "host"))
    return cleaned[:31] or "host"


def _fill_targets_sheet(ws, reports: list[HostReport]) -> None:
    if ws is None:
        return
    for i, report in enumerate(reports):
        row = 7 + i
        if i > 0:
            # Copy style/formulas from row 7 when possible by duplicating values only.
            for col in range(1, 12):
                src = ws.cell(7, col)
                dst = ws.cell(row, col)
                if src.has_style:
                    dst._style = src._style
        ws.cell(row, 1).value = i + 1
        ws.cell(row, 2).value = report.hostname
        ws.cell(row, 3).value = report.target_os
        ws.cell(row, 4).value = report.ip_address


def _fill_host_detail_sheet(ws, report: HostReport, *, code_col: int, result_col: int, result_mapper, evidence_col: int | None, op_col: int | None, start_row: int, end_row: int) -> None:
    mapping = _diag_map(report)
    for row in range(start_row, end_row + 1):
        code = str(ws.cell(row, code_col).value or "").strip()
        if not code:
            continue
        diag = mapping.get(code.upper())
        if diag is None:
            ws.cell(row, result_col).value = "N/A"
            if evidence_col:
                ws.cell(row, evidence_col).value = ""
            if op_col:
                ws.cell(row, op_col).value = ""
            continue
        ws.cell(row, result_col).value = result_mapper(diag.status)
        if evidence_col:
            ws.cell(row, evidence_col).value = diag.evidence or ""
        if op_col:
            ws.cell(row, op_col).value = diag.processed_config or diag.err_msg or ""


def generate_detailed_report(reports: list[HostReport], os_type: str) -> Path:
    template = EXCEL_TEMPLATE_DIR / "UNIX_서버_취약점진단_상세결과보고서.xlsx"
    if not template.exists():
        raise FileNotFoundError(f"상세결과 템플릿 없음: {template.name}")

    clean_os = os_type.replace(" ", "_")
    out = _unique_path(
        EXPORT_DIR,
        f"{clean_os}_서버_취약점진단_상세결과보고서_{datetime.now():%Y%m%d}",
        ".xlsx",
    )
    shutil.copy2(template, out)
    wb = load_workbook(out)

    if "표지" in wb.sheetnames:
        wb["표지"]["H19"] = datetime.now().strftime("%Y.%m.")

    if "점검대상" in wb.sheetnames:
        _fill_targets_sheet(wb["점검대상"], reports)

    sample_name = "sample" if "sample" in wb.sheetnames else None
    if sample_name:
        for report in reports:
            sheet_name = _safe_sheet_name(report.hostname)
            if sheet_name in wb.sheetnames:
                del wb[sheet_name]
            ws = wb.copy_worksheet(wb[sample_name])
            ws.title = sheet_name
            # C6 hostname / C7 IP (WPF detailed path) with fallbacks
            for coord, value in (("C6", report.hostname), ("C7", report.ip_address), ("D4", report.hostname), ("D5", report.ip_address)):
                try:
                    ws[coord] = value
                except Exception:
                    pass
            # Prefer detailed layout (rows 28-94, code col C=3, result O=15, op Q=17, evidence U=21)
            _fill_host_detail_sheet(
                ws,
                report,
                code_col=3,
                result_col=15,
                result_mapper=_status_ko_detail,
                evidence_col=21,
                op_col=17,
                start_row=28,
                end_row=94,
            )
        try:
            del wb[sample_name]
        except Exception:
            pass

    wb.save(out)
    wb.close()
    return out


def generate_risk_workbook(reports: list[HostReport], os_type: str, template_name: str, out_prefix: str) -> Path:
    template = EXCEL_TEMPLATE_DIR / template_name
    if not template.exists():
        raise FileNotFoundError(f"템플릿 없음: {template_name}")

    clean_os = os_type.replace(" ", "_")
    out = _unique_path(EXPORT_DIR, f"{clean_os}_{out_prefix}_{datetime.now():%Y%m%d}", ".xlsm")
    shutil.copy2(template, out)
    wb = load_workbook(out, keep_vba=True)

    if "표지" in wb.sheetnames:
        try:
            wb["표지"]["I21"] = datetime.now().strftime("%Y.%m.")
        except Exception:
            pass

    if "점검대상" in wb.sheetnames:
        ws = wb["점검대상"]
        for i, report in enumerate(reports):
            row = 7 + i
            ws.cell(row, 2).value = i + 1
            ws.cell(row, 3).value = report.hostname
            ws.cell(row, 4).value = report.target_os
            ws.cell(row, 5).value = report.ip_address
            ws.cell(row, 7).value = 3
            ws.cell(row, 8).value = 3
            ws.cell(row, 9).value = 3
            ws.cell(row, 10).value = (
                f'=IF(AND(SUM(G{row}:I{row})>=8, SUM(G{row}:I{row})<=9), "1등급", '
                f'IF(AND(SUM(G{row}:I{row})>=6, SUM(G{row}:I{row})<=7), "2등급", '
                f'IF(AND(SUM(G{row}:I{row})>=3, SUM(G{row}:I{row})<=5), "3등급", "")))'
            )

    sample_name = "sample" if "sample" in wb.sheetnames else None
    if sample_name:
        for report in reports:
            sheet_name = _safe_sheet_name(report.hostname)
            if sheet_name in wb.sheetnames:
                del wb[sheet_name]
            ws = wb.copy_worksheet(wb[sample_name])
            ws.title = sheet_name
            for coord, value in (("D4", report.hostname), ("D5", report.ip_address), ("H4", report.target_os)):
                try:
                    ws[coord] = value
                except Exception:
                    pass
            _fill_host_detail_sheet(
                ws,
                report,
                code_col=4,
                result_col=13,
                result_mapper=_status_yn,
                evidence_col=15,
                op_col=None,
                start_row=21,
                end_row=87,
            )
        try:
            del wb[sample_name]
        except Exception:
            pass

    wb.save(out)
    wb.close()
    return out


def export_reports(reports: list[HostReport], options: ExportOptions) -> ExportResult:
    logs: list[str] = []
    files: list[str] = []
    now = datetime.now().strftime("%H:%M:%S")
    logs.append(f"[{now}] 보고서 생성 작업을 시작합니다...")

    if not (options.detail or options.summary or options.action_plan):
        raise ValueError("출력할 보고서 양식을 최소 하나 이상 선택해야 합니다.")
    if not (options.unix or options.win_server or options.pc):
        raise ValueError("내보낼 자산 유형을 최소 하나 이상 선택해야 합니다.")

    target = _filter_reports(reports, options)
    if not target:
        raise ValueError("선택한 자산 유형에 해당하는 진단 결과 호스트가 존재하지 않습니다.")

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    groups = _group_by_os(target)

    if options.detail:
        for os_type, group in groups.items():
            logs.append(f"[{datetime.now():%H:%M:%S}] {os_type} 상세결과보고서 생성 중... ({len(group)} hosts)")
            path = generate_detailed_report(group, os_type)
            files.append(path.name)
            logs.append(f"[{datetime.now():%H:%M:%S}]   - 완료: {path.name}")

    if options.summary:
        for os_type, group in groups.items():
            logs.append(f"[{datetime.now():%H:%M:%S}] {os_type} 위험관리 계획서 생성 중... ({len(group)} hosts)")
            path = generate_risk_workbook(
                group,
                os_type,
                "UNIX_서버_위험관리 계획서_양식.xlsm",
                "서버_위험관리_계획서",
            )
            files.append(path.name)
            logs.append(f"[{datetime.now():%H:%M:%S}]   - 완료: {path.name}")

    if options.action_plan:
        for os_type, group in groups.items():
            logs.append(f"[{datetime.now():%H:%M:%S}] {os_type} 위험 분석 평가표 생성 중... ({len(group)} hosts)")
            path = generate_risk_workbook(
                group,
                os_type,
                "UNIX_서버_위험_분석_평가표_양식.xlsm",
                "서버_위험_분석_평가표",
            )
            files.append(path.name)
            logs.append(f"[{datetime.now():%H:%M:%S}]   - 완료: {path.name}")

    logs.append(f"[{datetime.now():%H:%M:%S}] 모든 보고서 생성이 완료되었습니다.")
    return ExportResult(files=files, logs=logs)
