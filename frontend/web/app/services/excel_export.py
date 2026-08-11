from __future__ import annotations

import re
import shutil
import zipfile
from copy import copy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from openpyxl import load_workbook
from openpyxl.chart import BarChart, RadarChart, Reference
from openpyxl.chart.data_source import AxDataSource, StrRef
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.chart.text import RichText
from openpyxl.drawing.graphic import GraphicFrameLocking
from openpyxl.drawing.line import LineProperties
from openpyxl.drawing.spreadsheet_drawing import (
    AnchorClientData,
    AnchorMarker,
    SpreadsheetDrawing,
    TwoCellAnchor,
)
from openpyxl.drawing.text import (
    CharacterProperties,
    Paragraph,
    ParagraphProperties,
    RichTextProperties,
)
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

# Chart palette (corporate blue — live cell-linked series)
CHART_FILL = "2E75B6"
CHART_LINE = "1F4E79"
CHART_FILL_ALT = "5B9BD5"
CHART_LINE_ALT = "2F5496"

AREA_VERTEX_LABELS = (
    (18, "① 계정 관리"),
    (19, "② 파일·디렉터리"),
    (20, "③ 서비스 관리"),
    (21, "④ 패치 관리"),
    (22, "⑤ 로그 관리"),
)
SECURITY_VERTEX_LABELS = (
    (6, "① 계정 관리"),
    (7, "② 파일·디렉터리"),
    (8, "③ 서비스 관리"),
    (9, "④ 패치 관리"),
    (10, "⑤ 로그 관리"),
)

from app.config import EXCEL_TEMPLATE_DIR, EXPORT_DIR
from app.models import HostReport
from app.services.stats import classify_host_type

FAIL_FILL = PatternFill(fill_type="solid", fgColor="FFFF0000")
FAIL_FONT = Font(bold=True, color="FFFFFFFF")
PASS_FILL = PatternFill(fill_type="solid", fgColor="FFFFFFFF")
PASS_FONT = Font(bold=True, color="FF000000")
WARN_FILL = PatternFill(fill_type="solid", fgColor="FFFFFF00")
WARN_FONT = Font(bold=True, color="FF000000")
NA_FILL = PatternFill(fill_type="solid", fgColor="FFD9D9D9")
NA_FONT = Font(bold=True, color="FF000000")

_CENTER = Alignment(horizontal="center", vertical="center")
_WARN_LABELS = {"인터뷰", "수동점검", "ERROR", "부분만족"}


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
    raw = (status or "").strip()
    if raw in {"양호", "취약", "인터뷰", "수동점검", "ERROR", "N/A"}:
        return raw
    s = raw.lower()
    if s in {"pass", "good"}:
        return "양호"
    if s in {"fail", "vulnerable"}:
        return "취약"
    if s in {"interview"}:
        return "인터뷰"
    if s in {"manual"}:
        return "수동점검"
    if s in {"error"}:
        return "ERROR"
    if s in {"n/a", "na", "notapplicable", "not applicable", "not_applicable"}:
        return "N/A"
    return "N/A"


def _status_yn(status: str) -> str:
    s = (status or "").strip().lower()
    if s in {"pass", "good"}:
        return "Y"
    if s in {"fail", "vulnerable"}:
        return "N"
    if s in {"interview", "manual", "error"}:
        return "N/A"
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


def _apply_result_style(cell, result_text: str) -> None:
    text = (result_text or "").strip()
    if text == "취약" or text == "N":
        cell.fill = FAIL_FILL
        cell.font = FAIL_FONT
        cell.alignment = _CENTER
    elif text == "양호" or text == "Y":
        cell.fill = PASS_FILL
        cell.font = PASS_FONT
        cell.alignment = _CENTER
    elif text in _WARN_LABELS:
        cell.fill = WARN_FILL
        cell.font = WARN_FONT
        cell.alignment = _CENTER
    elif text.upper() == "N/A":
        cell.fill = NA_FILL
        cell.font = NA_FONT
        cell.alignment = _CENTER


def _clear_chart_cache(chart) -> None:
    """Drop cached series values so Excel refreshes from live cell references."""
    for series in getattr(chart, "series", []) or []:
        val = getattr(series, "val", None)
        if val is not None and getattr(val, "numRef", None) is not None:
            val.numRef.numCache = None
        cat = getattr(series, "cat", None)
        if cat is not None:
            if getattr(cat, "numRef", None) is not None:
                cat.numRef.numCache = None
            if getattr(cat, "strRef", None) is not None:
                cat.strRef.strCache = None


def _pin_chart(
    chart,
    *,
    from_col: int,
    from_row: int,
    to_col: int,
    to_row: int,
) -> None:
    """Bind chart to a fixed TwoCellAnchor (editAs=absolute) that cannot move with cells."""
    anchor = TwoCellAnchor(
        editAs="absolute",
        _from=AnchorMarker(col=from_col, colOff=0, row=from_row, rowOff=0),
        to=AnchorMarker(col=to_col, colOff=0, row=to_row, rowOff=0),
        clientData=AnchorClientData(fLocksWithSheet=True, fPrintsWithSheet=True),
    )
    chart.anchor = anchor
    _clear_chart_cache(chart)


def _install_chart_frame_locks():
    """Patch openpyxl so written chart frames get noMove/noResize locks."""
    original = SpreadsheetDrawing._chart_frame

    def _locked_chart_frame(self, idx):
        frame = original(self, idx)
        frame.nvGraphicFramePr.cNvGraphicFramePr.graphicFrameLocks = GraphicFrameLocking(
            noGrp=True,
            noMove=True,
            noResize=True,
            noChangeAspect=True,
        )
        return frame

    SpreadsheetDrawing._chart_frame = _locked_chart_frame  # type: ignore[method-assign]
    return original


def _restore_chart_frame_locks(original) -> None:
    SpreadsheetDrawing._chart_frame = original  # type: ignore[method-assign]


def _fill_targets_sheet(ws, reports: list[HostReport], sheet_names: list[str]) -> None:
    if ws is None:
        return
    for i, (report, sheet_name) in enumerate(zip(reports, sheet_names)):
        row = 7 + i
        if i > 0:
            for col in range(1, 12):
                src = ws.cell(7, col)
                dst = ws.cell(row, col)
                if src.has_style:
                    dst._style = src._style
        ws.cell(row, 1).value = i + 1
        # B열은 호스트 시트명과 반드시 동일해야 INDIRECT/장비별 공식이 동작한다.
        ws.cell(row, 2).value = sheet_name
        ws.cell(row, 3).value = report.target_os
        ws.cell(row, 4).value = report.ip_address


def _fill_host_detail_sheet(
    ws,
    report: HostReport,
    *,
    code_col: int,
    result_col: int,
    result_mapper,
    evidence_col: int | None,
    op_col: int | None,
    start_row: int,
    end_row: int,
) -> None:
    mapping = _diag_map(report)
    for row in range(start_row, end_row + 1):
        code = str(ws.cell(row, code_col).value or "").strip()
        if not code:
            continue
        result_cell = ws.cell(row, result_col)
        diag = mapping.get(code.upper())
        if diag is None:
            result_cell.value = "N/A"
            _apply_result_style(result_cell, "N/A")
            if evidence_col:
                ws.cell(row, evidence_col).value = ""
            if op_col:
                ws.cell(row, op_col).value = ""
            continue
        result_text = result_mapper(diag.status)
        result_cell.value = result_text
        _apply_result_style(result_cell, result_text)
        if evidence_col:
            ws.cell(row, evidence_col).value = diag.evidence or ""
        if op_col:
            ws.cell(row, op_col).value = diag.processed_config or diag.err_msg or ""


def _reapply_detail_conditional_formatting(ws) -> None:
    # copy_worksheet drops CF; restore rules for 점검결과(O).
    try:
        ws.conditional_formatting._cf_rules.clear()
    except Exception:
        pass
    ws.conditional_formatting.add(
        "O28:O94",
        CellIsRule(operator="equal", formula=['"취약"'], fill=FAIL_FILL, font=FAIL_FONT),
    )
    for label in ("인터뷰", "수동점검", "ERROR", "부분만족"):
        ws.conditional_formatting.add(
            "O28:O94",
            CellIsRule(operator="equal", formula=[f'"{label}"'], fill=WARN_FILL, font=WARN_FONT),
        )
    ws.conditional_formatting.add(
        "O28:O94",
        CellIsRule(operator="equal", formula=['"양호"'], fill=PASS_FILL, font=PASS_FONT),
    )
    ws.conditional_formatting.add(
        "O28:O94",
        CellIsRule(operator="equal", formula=['"N/A"'], fill=NA_FILL, font=NA_FONT),
    )


def _fix_host_stat_formulas(ws) -> None:
    """Count 취약 only via COUNTIF; interview/manual/error go to 해당없음 bucket."""
    specs = [
        (18, "O28:O40"),
        (19, "O41:O60"),
        (20, "O61:O90"),
        (21, "O91"),
        (22, "O92:O94"),
    ]
    for row, rng in specs:
        ws.cell(row, 6).value = f'=COUNTIF({rng},"양호")'
        ws.cell(row, 7).value = f'=COUNTIF({rng},"취약")'
        ws.cell(row, 8).value = f'=COUNTIF({rng},"부분만족")'
        ws.cell(row, 9).value = (
            f'=COUNTIF({rng},"N/A")+COUNTIF({rng},"인터뷰")'
            f'+COUNTIF({rng},"수동점검")+COUNTIF({rng},"ERROR")'
        )


def _percent_data_labels(*, position: str | None = "outEnd") -> DataLabelList:
    labels = DataLabelList()
    labels.showVal = True
    labels.showCatName = False
    labels.showSerName = False
    labels.showPercent = False
    labels.showLegendKey = False
    labels.numFmt = "0%"
    if position:
        labels.dLblPos = position
    return labels


def _style_series(series, *, fill: str = CHART_FILL, line: str = CHART_LINE) -> None:
    series.graphicalProperties = GraphicalProperties(
        solidFill=fill,
        ln=LineProperties(solidFill=line, w=25000),
    )


def _write_vertex_labels(ws, labels: tuple[tuple[int, str], ...], col: int) -> None:
    """Helper column used as radar/bar categories (numbered vertex names)."""
    for row, text in labels:
        cell = ws.cell(row, col)
        cell.value = text
        cell.font = Font(name="맑은 고딕", size=9, bold=True, color="FF1F4E79")


def _category_formula(sheet_title: str, col_letter: str, start_row: int, end_row: int) -> str:
    safe = sheet_title.replace("'", "''")
    return f"'{safe}'!${col_letter}${start_row}:${col_letter}${end_row}"


def _bind_str_categories(chart, formula: str) -> None:
    """Force text category axis (openpyxl defaults to numRef, which hides X labels)."""
    for series in chart.series:
        series.cat = AxDataSource(strRef=StrRef(f=formula))


def _rotate_axis_labels(axis, degrees: float = -45.0) -> None:
    # OOXML rotation unit: 1/60000 of a degree.
    rot = int(degrees * 60000)
    axis.txPr = RichText(
        bodyPr=RichTextProperties(rot=rot, anchor="ctr"),
        p=[
            Paragraph(
                pPr=ParagraphProperties(defRPr=CharacterProperties(sz=900)),
                endParaRPr=CharacterProperties(sz=900),
            )
        ],
    )


def _build_radar_chart(
    *,
    title: str | None,
    cats: Reference,
    data: Reference,
    cat_formula: str,
    from_col: int,
    from_row: int,
    to_col: int,
    to_row: int,
) -> RadarChart:
    chart = RadarChart()
    chart.type = "filled"
    chart.style = 10
    chart.title = title
    chart.add_data(data, titles_from_data=True)
    chart.set_categories(cats)
    _bind_str_categories(chart, cat_formula)
    # Hide series legend — category names already sit on each vertex axis.
    chart.legend = None
    chart.dataLabels = _percent_data_labels(position=None)
    for series in chart.series:
        _style_series(series, fill=CHART_FILL_ALT, line=CHART_LINE)
        series.dLbls = _percent_data_labels(position=None)
    try:
        chart.y_axis.scaling.min = 0
        chart.y_axis.scaling.max = 1
        # Keep concentric grid; tick text is stripped in _hide_radar_value_axis_labels().
        chart.y_axis.numFmt = "0%"
        chart.y_axis.majorTickMark = "none"
        chart.y_axis.minorTickMark = "none"
        chart.y_axis.delete = False
        chart.x_axis.delete = False
    except Exception:
        pass
    chart.width = 12
    chart.height = 10
    _pin_chart(chart, from_col=from_col, from_row=from_row, to_col=to_col, to_row=to_row)
    return chart


def _hide_radar_value_axis_labels(xlsx_path: Path) -> None:
    """openpyxl cannot emit tickLblPos=none; patch radar valAx after save."""

    def _patch_val_ax(match: re.Match[str]) -> str:
        block = match.group(0)
        # Preserve whatever prefix the chart XML uses (c: or none).
        prefix = "c:" if "<c:axPos" in block or block.startswith("<c:") else ""
        tick_tag = f"<{prefix}tickLblPos val=\"none\"/>"
        if re.search(rf"<{prefix}tickLblPos\s+val=\"none\"", block):
            return block
        if f"<{prefix}tickLblPos" in block or "<tickLblPos" in block:
            return re.sub(r"<[^>]*tickLblPos[^/]*/>", tick_tag, block)
        return re.sub(
            rf"(<{prefix}axPos[^/]*/>)",
            rf"\1{tick_tag}",
            block,
            count=1,
        )

    with zipfile.ZipFile(xlsx_path, "r") as zin:
        files = {info.filename: (info, zin.read(info.filename)) for info in zin.infolist()}

    changed = False
    for name, (info, data) in list(files.items()):
        if not (name.startswith("xl/charts/") and name.endswith(".xml")):
            continue
        text = data.decode("utf-8")
        if "<radarChart>" not in text and "<c:radarChart>" not in text:
            continue
        patched = re.sub(
            r"<(?:c:)?valAx>.*?</(?:c:)?valAx>",
            _patch_val_ax,
            text,
            flags=re.S,
        )
        if patched != text:
            files[name] = (info, patched.encode("utf-8"))
            changed = True

    if not changed:
        return

    tmp = xlsx_path.with_suffix(xlsx_path.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name, (info, data) in files.items():
            zout.writestr(info, data)
    tmp.replace(xlsx_path)


def _build_bar_chart(
    *,
    title: str | None,
    cats: Reference,
    data: Reference,
    cat_formula: str,
    from_col: int,
    from_row: int,
    to_col: int,
    to_row: int,
    rotate_labels: bool = True,
) -> BarChart:
    chart = BarChart()
    chart.type = "col"
    chart.style = 10
    chart.title = title
    chart.add_data(data, titles_from_data=True)
    chart.set_categories(cats)
    _bind_str_categories(chart, cat_formula)
    # Single series — legend only adds clutter under the x-axis labels.
    chart.legend = None
    chart.dataLabels = _percent_data_labels(position="outEnd")
    for series in chart.series:
        _style_series(series, fill=CHART_FILL, line=CHART_LINE)
        series.dLbls = _percent_data_labels(position="outEnd")
    chart.y_axis.scaling.min = 0
    chart.y_axis.scaling.max = 1
    chart.y_axis.numFmt = "0%"
    chart.y_axis.title = None
    chart.x_axis.title = None
    chart.x_axis.delete = False
    chart.x_axis.tickLblPos = "nextTo"
    if rotate_labels:
        _rotate_axis_labels(chart.x_axis, -45.0)
    chart.shape = 4
    chart.width = 12
    chart.height = 10
    _pin_chart(chart, from_col=from_col, from_row=from_row, to_col=to_col, to_row=to_row)
    return chart


def _add_host_area_charts(ws) -> None:
    """Recreate live, pinned area charts — radar at column P, bar at column Q."""
    ws._charts = []
    # AA열: 꼭짓점/축 라벨 / L열: 보안수준(비율)
    _write_vertex_labels(ws, AREA_VERTEX_LABELS, col=27)
    if not ws.cell(17, 12).value:
        ws.cell(17, 12).value = "보안수준"
    ws.cell(17, 27).value = "점검 영역"

    # Give P/Q enough width so each chart has its own column lane.
    ws.column_dimensions["P"].width = 42
    ws.column_dimensions["Q"].width = 42

    cats = Reference(ws, min_col=27, min_row=18, max_row=22)
    data = Reference(ws, min_col=12, min_row=17, max_row=22)
    cat_formula = _category_formula(ws.title, "AA", 18, 22)

    # P=15, Q=16 (0-based anchor indices); from_row=6 → Excel 7행
    radar = _build_radar_chart(
        title=None,
        cats=cats,
        data=data,
        cat_formula=cat_formula,
        from_col=15,
        from_row=6,
        to_col=16,
        to_row=22,
    )
    ws.add_chart(radar)

    bar = _build_bar_chart(
        title=None,
        cats=cats,
        data=data,
        cat_formula=cat_formula,
        from_col=16,
        from_row=6,
        to_col=17,
        to_row=22,
    )
    ws.add_chart(bar)


def _fill_summary_sheet(ws, host_count: int) -> None:
    if ws is None or host_count < 1:
        return
    # Template has host results starting at column L (12).
    for i in range(host_count):
        col = 12 + i
        letter = get_column_letter(col)
        if i > 0:
            ws.column_dimensions[letter].width = ws.column_dimensions["L"].width or 12
            for row in range(1, 92):
                src = ws.cell(row, 12)
                dst = ws.cell(row, col)
                if src.has_style:
                    dst._style = copy(src._style)

        ws.cell(4, col).value = (
            '=HYPERLINK("[" & MID(CELL("filename"),SEARCH("[",CELL("filename"))+1, '
            'SEARCH("]",CELL("filename"))-SEARCH("[",CELL("filename"))-1) & "]\'" & '
            'INDIRECT(ADDRESS(COLUMN()-5,2,1,TRUE,"점검대상")) & "\'!A1",'
            'INDIRECT(ADDRESS(COLUMN()-5,2,1,TRUE,"점검대상")))'
        )
        for row in range(6, 73):
            ws.cell(row, col).value = (
                f'=IFERROR(INDIRECT(ADDRESS(ROW()+22,15,1,TRUE,{letter}$4)),"")'
            )
        ws.cell(73, col).value = (
            f'=COUNTIF({letter}6:{letter}72,"양호")+COUNTIF({letter}6:{letter}72,"취약")'
            f'+COUNTIF({letter}6:{letter}72,"부분만족")+COUNTIF({letter}6:{letter}72,"N/A")'
        )
        for row in range(75, 79):
            ws.cell(row, col).value = f"=COUNTIF({letter}$6:{letter}$72,$J{row})"
        for row in range(80, 92):
            # Severity blocks: 상@80, 중@84, 하@88 (template I-column anchors).
            if row <= 83:
                anchor_row = 80
            elif row <= 87:
                anchor_row = 84
            else:
                anchor_row = 88
            ws.cell(row, col).value = (
                f"=COUNTIFS($D$6:$D$72,$I${anchor_row},{letter}$6:{letter}$72,$J{row})"
            )

    last_letter = get_column_letter(11 + host_count)
    for row in range(75, 79):
        ws.cell(row, 11).value = f"=SUM(L{row}:{last_letter}{row})"
    for row in range(80, 92):
        ws.cell(row, 11).value = f"=SUM(L{row}:{last_letter}{row})"


def _fill_security_level_sheet(ws, reports: list[HostReport], os_type: str) -> None:
    if ws is None or not reports:
        return

    host_count = len(reports)
    ws["A32"] = "▣ 장비별 보안수준 그래프"

    if host_count > 1:
        # Push "계" row down; openpyxl keeps old merge on A37 so fix merges after.
        try:
            ws.unmerge_cells("A37:B37")
        except Exception:
            pass
        ws.insert_rows(37, host_count - 1)
        for r in range(37, 36 + host_count):
            for c in range(1, 12):
                src = ws.cell(36, c)
                dst = ws.cell(r, c)
                if src.has_style:
                    dst._style = copy(src._style)

    for i in range(host_count):
        r = 36 + i
        ws.cell(r, 1).value = (os_type or "UNIX").upper()
        ws.cell(r, 2).value = '=INDIRECT(ADDRESS(ROW()-29,2,1,TRUE,"점검대상"))'
        for c in range(3, 11):
            ws.cell(r, c).value = f'=IFERROR(INDIRECT(ADDRESS(23,COLUMN()+1,1,TRUE,$B{r})),0)'
        ws.cell(r, 11).value = f'=IF(I{r}=0,"N/A",((I{r}-J{r})/I{r})*1)'

    total_row = 36 + host_count
    # Ensure 계 merge sits on the total row.
    for merged in list(ws.merged_cells.ranges):
        if str(merged).startswith("A37:"):
            try:
                ws.unmerge_cells(str(merged))
            except Exception:
                pass
    try:
        ws.merge_cells(start_row=total_row, start_column=1, end_row=total_row, end_column=2)
    except Exception:
        pass

    ws.cell(total_row, 1).value = "계"
    for c in range(3, 11):
        letter = get_column_letter(c)
        ws.cell(total_row, c).value = f"=SUM({letter}36:{letter}{total_row - 1})"
    ws.cell(total_row, 11).value = (
        f'=SUM(K36:K{total_row - 1})/'
        f'(COUNTA(K36:K{total_row - 1})-COUNTIF(K36:K{total_row - 1},"N/A"))'
    )
    ws["K11"] = f"=K{total_row}"

    # Rebuild all charts: live cell refs, percent labels, pinned anchors.
    ws._charts = []
    _write_vertex_labels(ws, SECURITY_VERTEX_LABELS, col=13)  # M열
    if not ws.cell(5, 11).value:
        ws.cell(5, 11).value = "보안수준"
    ws.cell(5, 13).value = "점검 영역"

    area_cats = Reference(ws, min_col=13, min_row=6, max_row=10)
    area_data = Reference(ws, min_col=11, min_row=5, max_row=10)
    area_cat_formula = _category_formula(ws.title, "M", 6, 10)

    # Left radar / right bar — matches 영역별 보안수준 그래프 section layout.
    radar = _build_radar_chart(
        title=None,
        cats=area_cats,
        data=area_data,
        cat_formula=area_cat_formula,
        from_col=0,
        from_row=12,
        to_col=5,
        to_row=30,
    )
    ws.add_chart(radar)

    area_bar = _build_bar_chart(
        title=None,
        cats=area_cats,
        data=area_data,
        cat_formula=area_cat_formula,
        from_col=5,
        from_row=12,
        to_col=11,
        to_row=30,
    )
    ws.add_chart(area_bar)

    last_host_row = total_row - 1
    # Ensure series header for 장비별 chart.
    if not ws.cell(35, 11).value:
        ws.cell(35, 11).value = "보안수준"
    host_cats = Reference(ws, min_col=2, min_row=36, max_row=last_host_row)
    host_data = Reference(ws, min_col=11, min_row=35, max_row=last_host_row)
    host_cat_formula = _category_formula(ws.title, "B", 36, last_host_row)
    host_bar = _build_bar_chart(
        title="장비별 보안수준 (%)",
        cats=host_cats,
        data=host_data,
        cat_formula=host_cat_formula,
        from_col=0,
        from_row=total_row + 1,
        to_col=11,
        to_row=total_row + 16,
        rotate_labels=True,
    )
    host_bar.width = 18
    host_bar.height = 10
    ws.add_chart(host_bar)


def _retarget_security_3d_refs(ws, first_sheet: str) -> None:
    """Point area rollups at host sheets sandwiched before 기준 DB."""
    old = "'sample:기준 DB'"
    new = f"'{first_sheet}:기준 DB'"
    for row in ws.iter_rows(min_row=6, max_row=10, min_col=3, max_col=11):
        for cell in row:
            if isinstance(cell.value, str) and old in cell.value:
                cell.value = cell.value.replace(old, new)


def _move_sheets_before(wb, sheet_names: list[str], before_title: str) -> None:
    if before_title not in wb.sheetnames:
        return
    for name in sheet_names:
        if name not in wb.sheetnames:
            continue
        # Move sheet to sit immediately before 기준 DB (or current before_title).
        before_idx = wb.sheetnames.index(before_title)
        cur_idx = wb.sheetnames.index(name)
        offset = before_idx - cur_idx
        if offset != 0:
            wb.move_sheet(name, offset=offset)


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

    # Unique sheet names (Excel 31-char limit), stable for 점검대상/INDIRECT.
    sheet_names: list[str] = []
    used: set[str] = set()
    for report in reports:
        base = _safe_sheet_name(report.hostname)
        name = base
        n = 2
        while name.lower() in used or name in wb.sheetnames and name != "sample":
            suffix = f"_{n}"
            name = _safe_sheet_name(base[: 31 - len(suffix)] + suffix)
            n += 1
        used.add(name.lower())
        sheet_names.append(name)

    if "점검대상" in wb.sheetnames:
        _fill_targets_sheet(wb["점검대상"], reports, sheet_names)

    if "요약 통계" in wb.sheetnames:
        _fill_summary_sheet(wb["요약 통계"], len(reports))

    sample_name = "sample" if "sample" in wb.sheetnames else None
    created: list[str] = []
    if sample_name:
        for report, sheet_name in zip(reports, sheet_names):
            if sheet_name in wb.sheetnames:
                del wb[sheet_name]
            ws = wb.copy_worksheet(wb[sample_name])
            ws.title = sheet_name
            created.append(sheet_name)
            for coord, value in (
                ("C6", report.hostname),
                ("C7", report.ip_address),
                ("D4", report.hostname),
                ("D5", report.ip_address),
            ):
                try:
                    ws[coord] = value
                except Exception:
                    pass
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
            _fix_host_stat_formulas(ws)
            _reapply_detail_conditional_formatting(ws)
            _add_host_area_charts(ws)

        try:
            del wb[sample_name]
        except Exception:
            pass

    if created:
        _move_sheets_before(wb, created, "기준 DB")
        if "보안수준 통계" in wb.sheetnames:
            _retarget_security_3d_refs(wb["보안수준 통계"], created[0])
            _fill_security_level_sheet(wb["보안수준 통계"], reports, os_type)

    original_frame = _install_chart_frame_locks()
    try:
        wb.save(out)
    finally:
        _restore_chart_frame_locks(original_frame)
        wb.close()
    _hide_radar_value_axis_labels(out)
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

    sheet_names: list[str] = []
    used: set[str] = set()
    for report in reports:
        base = _safe_sheet_name(report.hostname)
        name = base
        n = 2
        while name.lower() in used or name in wb.sheetnames and name != "sample":
            suffix = f"_{n}"
            name = _safe_sheet_name(base[: 31 - len(suffix)] + suffix)
            n += 1
        used.add(name.lower())
        sheet_names.append(name)

    if "점검대상" in wb.sheetnames:
        ws = wb["점검대상"]
        for i, (report, sheet_name) in enumerate(zip(reports, sheet_names)):
            row = 7 + i
            ws.cell(row, 2).value = i + 1
            ws.cell(row, 3).value = sheet_name
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
        for report, sheet_name in zip(reports, sheet_names):
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
