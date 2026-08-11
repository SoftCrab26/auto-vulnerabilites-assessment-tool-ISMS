from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import DiagnosticItem, HostReport


@dataclass
class DashboardStats:
    total_hosts: int = 0
    total_items: int = 0
    total_pass: int = 0
    total_fail: int = 0
    total_na: int = 0
    pass_rate: float = 0.0


def classify_host_type(target_os: str) -> str:
    os_u = (target_os or "").strip().upper()
    is_unix = any(x in os_u for x in ("UNIX", "LINUX", "AIX", "SOLARIS", "HP", "DBMS"))
    is_windows = "WINDOWS" in os_u
    is_win_server = is_windows and ("SERVER" in os_u or "서버" in (target_os or ""))
    is_pc = is_windows and not is_win_server
    if is_unix:
        return "UNIX/Linux"
    if is_win_server:
        return "Windows Server"
    if is_pc:
        return "개인 PC"
    return "기타"


def filter_reports(reports: list[HostReport], host_type: str) -> list[HostReport]:
    if not host_type or host_type == "전체":
        return reports
    return [r for r in reports if classify_host_type(r.target_os) == host_type]


def compute_stats(reports: list[HostReport]) -> DashboardStats:
    stats = DashboardStats(total_hosts=len(reports))
    for report in reports:
        for item in report.diagnostics:
            stats.total_items += 1
            status = (item.status or "").strip().lower()
            if status == "pass":
                stats.total_pass += 1
            elif status == "fail":
                stats.total_fail += 1
            else:
                stats.total_na += 1
    judged = stats.total_pass + stats.total_fail
    stats.pass_rate = round((stats.total_pass / judged) * 100, 1) if judged else 0.0
    return stats


def load_reports(db: Session) -> list[HostReport]:
    return (
        db.query(HostReport)
        .order_by(HostReport.uploaded_at.desc())
        .all()
    )


def filter_diagnostics(
    items: list[DiagnosticItem],
    status_filter: str = "전체",
    search: str = "",
) -> list[DiagnosticItem]:
    result = items
    if status_filter and status_filter != "전체":
        result = [i for i in result if i.status.lower() == status_filter.lower()]
    if search:
        q = search.lower()
        result = [
            i
            for i in result
            if q in (i.code or "").lower()
            or q in (i.title or "").lower()
            or q in (i.description or "").lower()
        ]
    return result
