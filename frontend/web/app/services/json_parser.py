from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

HIGH_ITEMS = {
    1, 2, 3, 4, 7, 8, 13, 17, 20, 22, 24, 25, 28, 30, 31, 32, 35, 36,
    44, 45, 46, 47, 48, 50, 54, 56, 57, 60, 61, 64, 65, 66, 67,
}
LOW_ITEMS = {16, 42, 43, 59}

DBMS_HIGH_ITEMS = {1, 2, 4, 7, 8, 10, 12, 14, 19, 23, 25, 26}
DBMS_LOW_ITEMS = {13, 16, 24}

RAW_PREVIEW_LIMIT = 1500

FALLBACK_REMEDIATION = (
    "[ISMS-P 조치 가이드]\n"
    "주요정보통신기반시설 기술적 취약점 가이드라인을 참조하여 "
    "권한 설정 수정, 불필요 서비스 비활성화 또는 패치 적용 등의 조치를 취하십시오."
)


@dataclass
class ParsedDiagnostic:
    code: str = ""
    category: str = ""
    title: str = ""
    status: str = "N/A"
    severity: str = "Medium"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    processed_config: str = ""
    raw_config: str = ""
    vulnerable_config: str = ""
    err_msg: str = ""


@dataclass
class ParsedReport:
    hostname: str = "UNKNOWN"
    ip_address: str = "0.0.0.0"
    target_os: str = "Linux"
    inspection_date: str = ""
    source_filename: str = ""
    diagnostics: list[ParsedDiagnostic] = field(default_factory=list)


def dbms_category(code: str) -> str:
    if not code.upper().startswith("D-"):
        return "기타"
    try:
        num = int(code[2:])
    except ValueError:
        return "기타"
    if 1 <= num <= 9:
        return "계정 관리"
    if 10 <= num <= 18:
        return "접근통제"
    if 19 <= num <= 24:
        return "권한/옵션"
    if 25 <= num <= 26:
        return "패치/감사"
    return "기타"


def dbms_severity(code: str) -> str:
    if not code.upper().startswith("D-"):
        return "Medium"
    try:
        num = int(code[2:])
    except ValueError:
        return "Medium"
    if num in DBMS_HIGH_ITEMS:
        return "High"
    if num in DBMS_LOW_ITEMS:
        return "Low"
    return "Medium"


def linux_category(code: str) -> str:
    if code.upper().startswith("D-"):
        return dbms_category(code)
    if not code.startswith("U-"):
        return "기타 서비스"
    try:
        num = int(code[2:])
    except ValueError:
        return "기타 서비스"
    if (1 <= num <= 5) or (44 <= num <= 54):
        return "계정 관리"
    if (6 <= num <= 18) or (55 <= num <= 59):
        return "파일 및 디렉터리 관리"
    if (19 <= num <= 41) or (60 <= num <= 72):
        return "서비스 관리"
    if num in (42, 43):
        return "패치 및 로그 관리"
    return "기타 서비스"


def linux_severity(code: str) -> str:
    if code.upper().startswith("D-"):
        return dbms_severity(code)
    if not code.startswith("U-"):
        return "Medium"
    try:
        num = int(code[2:])
    except ValueError:
        return "Medium"
    if num in HIGH_ITEMS:
        return "High"
    if num in LOW_ITEMS:
        return "Low"
    return "Medium"


def guide_os_type(target_os: str, code: str = "") -> str:
    """Map host OS / item code to guidelines.os_type key."""
    code_u = (code or "").strip().upper()
    os_l = (target_os or "").lower()
    if code_u.startswith("D-") or any(x in os_l for x in ("dbms", "oracle", "mssql", "mysql", "postgres")):
        return "DBMS"
    if "windows" in os_l:
        return "Windows"
    return "Linux"


def map_go_status(status: int) -> str:
    # Go Status iota: Good, Vulnerable, Interview, Manual, NotApplicable, Error
    return {
        0: "Pass",
        1: "Fail",
        2: "Interview",
        3: "Manual",
        4: "N/A",
        5: "Error",
    }.get(status, "N/A")


def normalize_status(value: Any) -> str:
    if isinstance(value, bool):
        return "Fail" if value else "Pass"
    if isinstance(value, int):
        return map_go_status(value)
    text = str(value or "").strip().lower()
    if text in {"0", "pass", "good"}:
        return "Pass"
    if text in {"1", "fail", "vulnerable"}:
        return "Fail"
    if text in {"2", "interview", "인터뷰"}:
        return "Interview"
    if text in {"3", "manual", "수동점검", "수동"}:
        return "Manual"
    if text in {"4", "n/a", "na", "notapplicable", "not applicable", "not_applicable"}:
        return "N/A"
    if text in {"5", "error", "err"}:
        return "Error"
    if text in {"pass", "fail", "interview", "manual", "error"}:
        return text[:1].upper() + text[1:]
    if text == "n/a":
        return "N/A"
    return "N/A"


def looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value or ""))


def truncate_text(value: str, limit: int = RAW_PREVIEW_LIMIT) -> str:
    text = value or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (truncated, total {len(text)} chars)"


def parse_filename_meta(filename: str) -> tuple[str, str, str]:
    base = Path(filename).stem
    parts = base.split("_")
    hostname = "UNKNOWN"
    ip_address = "0.0.0.0"
    target_os = "Linux"

    known = {
        "windowsserver": "Windows Server",
        "unix": "Linux",
        "linux": "Linux",
        "dbms": "DBMS",
        "oracle": "Oracle",
        "windows": "Windows",
        "pc": "Windows",
        "aix": "AIX",
        "centos": "Linux",
        "rhel": "Linux",
        "ubuntu": "Linux",
        "synology": "Linux",
        "synologydsm": "Linux",
        "dsm": "Linux",
    }
    lower_base = base.lower()
    if lower_base.startswith("aix_") or "_aix_" in f"_{lower_base}_":
        target_os = "AIX"
    if lower_base.startswith("oracle_") or lower_base.startswith("dbms_"):
        target_os = "Oracle" if lower_base.startswith("oracle_") else "DBMS"

    if len(parts) >= 3:
        first = parts[0].strip()
        key = first.lower()
        if key in known:
            target_os = known[key]
            # oracle_<uniqueName>_<timestamp> — last token is not an IP.
            if key in {"oracle", "dbms"}:
                hostname = "_".join(parts[1:-1]) or "UNKNOWN"
                ip_address = "0.0.0.0"
            else:
                ip_address = parts[-1]
                hostname = "_".join(parts[1:-1]) or "UNKNOWN"
        else:
            ip_address = parts[-1]
            hostname = "_".join(parts[:-1]) or "UNKNOWN"
    elif len(parts) == 2:
        hostname, ip_address = parts[0], parts[1]
    else:
        hostname = base

    if looks_like_ip(ip_address) is False and looks_like_ip(hostname):
        hostname, ip_address = ip_address, hostname
    return hostname, ip_address, target_os


def infer_os_from_items(items: list[dict[str, Any]], fallback: str) -> str:
    # Scan enough of RawConfig — AIX markers often sit past the first few KB
    # (e.g. sendmail.cf headers with src/bos/...).
    chunks: list[str] = []
    for item in items[:40]:
        raw = str(
            item.get("RawConfig")
            or item.get("rawConfig")
            or item.get("raw_config")
            or ""
        )
        chunks.append(raw[:8000])
        processed = str(
            item.get("ProcessedConfig")
            or item.get("processedConfig")
            or item.get("processed_config")
            or ""
        )
        chunks.append(processed[:500])
    blob = " ".join(chunks).lower()
    if "synology" in blob or "synoinfo" in blob or "/etc.defaults/" in blob:
        return "Linux"
    if (
        "/etc/security/user" in blob
        or "/etc/objrepos" in blob
        or "src/bos/" in blob
        or "/bos/usr/" in blob
        or "/bos/etc/" in blob
        or "bos71" in blob
        or "aix5.m4" in blob
        or "component_name: cmdsend" in blob
        or "ibm aix" in blob
    ):
        return "AIX"
    return fallback


def _guideline_lookup(guidelines: list[dict[str, Any]], os_type: str, code: str) -> dict[str, Any] | None:
    guide_os = guide_os_type(os_type, code)
    for g in guidelines:
        if g.get("os_type", "").lower() == guide_os.lower() and g.get("code", "").lower() == code.lower():
            return g
    return None


def _apply_dbms_metadata(report: ParsedReport, data: dict[str, Any], filename: str) -> None:
    """Prefer Oracle scanner engine/metadata when present."""
    engine = str(data.get("engine") or data.get("Engine") or "").strip().upper()
    meta = data.get("metadata") or data.get("Metadata") or {}
    if not isinstance(meta, dict):
        meta = {}
    codes = [str(d.code or "").upper() for d in report.diagnostics]
    is_dbms = (
        engine in {"ORACLE", "MSSQL", "MYSQL", "DBMS", "POSTGRES"}
        or Path(filename).stem.lower().startswith(("oracle_", "dbms_"))
        or any(c.startswith("D-") for c in codes)
    )
    if not is_dbms:
        return
    if engine == "ORACLE" or Path(filename).stem.lower().startswith("oracle_"):
        report.target_os = "Oracle"
    else:
        report.target_os = engine.title() if engine else "DBMS"
    host = str(meta.get("dbUniqueName") or meta.get("UniqueName") or meta.get("dbName") or meta.get("Name") or "").strip()
    if host:
        report.hostname = host
    generated = data.get("generatedAt") or data.get("GeneratedAt")
    if generated:
        report.inspection_date = str(generated).replace("T", " ")[:19]


def _build_remediation(
    *,
    mitre: Any,
    vulnerable: str,
    guidelines: list[dict[str, Any]],
    target_os: str,
    code: str,
) -> str:
    guide = _guideline_lookup(guidelines, target_os, code)
    base_remediation = (guide or {}).get("remediation") or FALLBACK_REMEDIATION
    remediation = ""
    if isinstance(mitre, dict) and mitre.get("tactic"):
        techniques = ", ".join(mitre.get("techniques") or [])
        mitigations = ", ".join(mitre.get("mitigations") or [])
        remediation += (
            f"[MITRE ATTACK 정보]\n- Tactic (전술): {mitre.get('tactic')}\n"
            f"- Techniques (기술): {techniques}\n"
            f"- Mitigations (완화조치): {mitigations}\n\n"
        )
    if vulnerable:
        remediation += f"[취약한 설정 분석 내용]\n{vulnerable}\n\n"
    remediation += base_remediation
    return remediation


def _build_evidence(
    *,
    status_str: str,
    processed: str,
    raw: str,
    vulnerable: str,
    err_msg: str,
    existing_evidence: str,
    synthesize_comments: bool,
    guidelines: list[dict[str, Any]],
    target_os: str,
    code: str,
) -> str:
    if existing_evidence.strip():
        return truncate_text(existing_evidence, limit=8000)

    parts: list[str] = []
    if synthesize_comments:
        guide = _guideline_lookup(guidelines, target_os, code)
        pass_comm = (guide or {}).get("pass_comment") or "설정이 기준에 부합하여 안전합니다."
        fail_comm = (guide or {}).get("fail_comment") or "설정이 기준에 미달하여 취약합니다."
        if status_str == "Pass":
            parts.append(pass_comm)
        elif status_str == "Fail":
            parts.append(fail_comm)
        else:
            parts.append("N/A")

    if vulnerable.strip():
        parts.append(f"[취약 근거]\n{vulnerable.strip()}")
    if processed.strip():
        parts.append(f"[검출된 설정값 (ProcessedConfig)]\n{processed.strip()}")
    if raw.strip():
        parts.append(f"[진단 로그 / 설정 원본 (RawConfig)]\n{truncate_text(raw)}")
    if err_msg.strip():
        parts.append(f"[오류 메시지]\n{err_msg.strip()}")
    return "\n\n".join(parts) if parts else ""


def _item_get(item: dict[str, Any], *names: str, default: str = "") -> str:
    for name in names:
        if name in item and item[name] is not None:
            return str(item[name])
    return default


def looks_like_complete_check_result(item: dict[str, Any]) -> bool:
    """Scanner output already has PascalCase CheckResult fields (not only Code/Status)."""
    keys = set(item.keys())
    return (
        ("Code" in keys or "code" in keys)
        and ("Status" in keys or "status" in keys)
        and ("RawConfig" in keys or "rawConfig" in keys or "ProcessedConfig" in keys or "processedConfig" in keys)
        and ("VulnerableConfig" in keys or "vulnerableConfig" in keys or "ErrMsg" in keys or "errMsg" in keys)
    )


def convert_check_results(
    items: list[dict[str, Any]],
    filename: str,
    guidelines: list[dict[str, Any]],
    *,
    synthesize_comments: bool,
) -> ParsedReport:
    hostname, ip_address, target_os = parse_filename_meta(filename)
    target_os = infer_os_from_items(items, target_os)
    report = ParsedReport(
        hostname=hostname,
        ip_address=ip_address,
        target_os=target_os,
        inspection_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_filename=Path(filename).name,
    )

    for item in items:
        code = _item_get(item, "Code", "code")
        description = _item_get(item, "Description", "description")
        raw = _item_get(item, "RawConfig", "rawConfig", "raw_config")
        vulnerable = _item_get(item, "VulnerableConfig", "vulnerableConfig", "vulnerable_config")
        processed = _item_get(item, "ProcessedConfig", "processedConfig", "processed_config")
        err_msg = _item_get(item, "ErrMsg", "errMsg", "err_msg")
        existing_evidence = _item_get(item, "Evidence", "evidence")
        mitre = item.get("MitreAttack") or item.get("mitreAttack") or item.get("mitre_attack") or {}
        status_str = normalize_status(item.get("Status", item.get("status", 4)))

        report.diagnostics.append(
            ParsedDiagnostic(
                code=code,
                category=dbms_category(code) if code.upper().startswith("D-") else linux_category(code),
                title=description,
                status=status_str,
                severity=dbms_severity(code) if code.upper().startswith("D-") else linux_severity(code),
                description=description,
                evidence=_build_evidence(
                    status_str=status_str,
                    processed=processed,
                    raw=raw,
                    vulnerable=vulnerable,
                    err_msg=err_msg,
                    existing_evidence=existing_evidence,
                    synthesize_comments=synthesize_comments,
                    guidelines=guidelines,
                    target_os=target_os,
                    code=code,
                ),
                remediation=_build_remediation(
                    mitre=mitre,
                    vulnerable=vulnerable,
                    guidelines=guidelines,
                    target_os=target_os,
                    code=code,
                ),
                processed_config=processed,
                raw_config=raw,
                vulnerable_config=vulnerable,
                err_msg=err_msg,
            )
        )
    return report


def convert_go_results(
    go_results: list[dict[str, Any]],
    filename: str,
    guidelines: list[dict[str, Any]],
) -> ParsedReport:
    # Legacy path: synthesize pass/fail comments into evidence.
    return convert_check_results(
        go_results,
        filename,
        guidelines,
        synthesize_comments=True,
    )


def parse_json_report(
    json_text: str,
    filename: str,
    guidelines: list[dict[str, Any]],
) -> ParsedReport | None:
    if "unknown_host" in Path(filename).stem.lower():
        return None

    try:
        # PowerShell-exported samples may include a UTF-8 BOM.
        data = json.loads(json_text.lstrip("\ufeff"))
    except json.JSONDecodeError:
        return None

    if isinstance(data, dict):
        diagnostics = data.get("diagnostics") or data.get("Diagnostics")
        system_info = data.get("system_info") or data.get("SystemInfo") or {}
        if isinstance(diagnostics, list) and diagnostics:
            report = ParsedReport(
                hostname=str(system_info.get("hostname") or system_info.get("Hostname") or "UNKNOWN"),
                ip_address=str(system_info.get("ip_address") or system_info.get("IpAddress") or "0.0.0.0"),
                target_os=str(system_info.get("target_os") or system_info.get("TargetOs") or "Linux"),
                inspection_date=str(
                    system_info.get("inspection_date")
                    or system_info.get("InspectionDate")
                    or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ),
                source_filename=Path(filename).name,
            )
            for item in diagnostics:
                if not isinstance(item, dict):
                    continue
                status_raw = item.get("status", item.get("Status", "N/A"))
                status = normalize_status(status_raw) if not isinstance(status_raw, str) or status_raw.strip().lower() in {
                    "0", "1", "2", "3", "4", "5", "good", "vulnerable", "pass", "fail"
                } else str(status_raw)
                # Keep explicit status strings from enriched format.
                if isinstance(status_raw, str) and status_raw.strip() in {
                    "Pass", "Fail", "N/A", "Interview", "Manual", "Error",
                    "양호", "취약", "인터뷰", "수동점검", "ERROR",
                }:
                    status = status_raw.strip()
                    if status in {"양호", "취약", "인터뷰", "수동점검", "ERROR", "N/A"}:
                        status = {
                            "양호": "Pass",
                            "취약": "Fail",
                            "인터뷰": "Interview",
                            "수동점검": "Manual",
                            "ERROR": "Error",
                            "N/A": "N/A",
                        }[status]
                report.diagnostics.append(
                    ParsedDiagnostic(
                        code=str(item.get("code") or item.get("Code") or ""),
                        category=str(item.get("category") or item.get("Category") or ""),
                        title=str(item.get("title") or item.get("Title") or item.get("description") or ""),
                        status=status,
                        severity=str(item.get("severity") or item.get("Severity") or "Medium"),
                        description=str(item.get("description") or item.get("Description") or ""),
                        evidence=truncate_text(str(item.get("evidence") or item.get("Evidence") or ""), limit=8000),
                        remediation=str(item.get("remediation") or item.get("Remediation") or ""),
                        processed_config=str(item.get("processed_config") or item.get("ProcessedConfig") or ""),
                        raw_config=str(item.get("raw_config") or item.get("RawConfig") or ""),
                        vulnerable_config=str(
                            item.get("vulnerable_config") or item.get("VulnerableConfig") or ""
                        ),
                        err_msg=str(item.get("err_msg") or item.get("ErrMsg") or ""),
                    )
                )
            return report if report.diagnostics else None

        results = data.get("Results") or data.get("results")
        if isinstance(results, list) and results and isinstance(results[0], dict):
            complete = looks_like_complete_check_result(results[0])
            report = convert_check_results(
                results,
                filename,
                guidelines,
                synthesize_comments=not complete,
            )
            _apply_dbms_metadata(report, data, filename)
            return report

    if isinstance(data, list) and data and isinstance(data[0], dict):
        if any(k in data[0] for k in ("Code", "code", "Status", "status")):
            complete = looks_like_complete_check_result(data[0])
            report = convert_check_results(
                data,
                filename,
                guidelines,
                synthesize_comments=not complete,
            )
            # list-only payloads may still be oracle_* filenames / D-codes
            _apply_dbms_metadata(report, {}, filename)
            return report

    return None


def enrich_reports_from_uploads(
    reports: list[Any],
    upload_dir: Path,
    guidelines: list[dict[str, Any]] | None = None,
) -> int:
    """Backfill status/raw/vulnerable from original JSON uploads (in-place).

    Older uploads stored Manual/Interview/Error as N/A and left raw/vulnerable
    columns empty. Re-parsing the saved upload file restores Excel detail fields
    without requiring the user to re-upload.
    """
    guides = guidelines or []
    updated = 0
    for report in reports:
        filename = (getattr(report, "source_filename", None) or "").strip()
        if not filename:
            continue
        path = upload_dir / Path(filename).name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError:
            continue
        parsed = parse_json_report(text, filename, guides)
        if parsed is None:
            continue
        by_code = {
            (d.code or "").strip().upper(): d
            for d in parsed.diagnostics
            if (d.code or "").strip()
        }
        for diag in getattr(report, "diagnostics", []) or []:
            code = (getattr(diag, "code", None) or "").strip().upper()
            src = by_code.get(code)
            if src is None:
                continue
            changed = False
            if src.status and src.status != (diag.status or ""):
                diag.status = src.status
                changed = True
            if src.vulnerable_config and not (getattr(diag, "vulnerable_config", None) or "").strip():
                diag.vulnerable_config = src.vulnerable_config
                changed = True
            if src.raw_config and not (getattr(diag, "raw_config", None) or "").strip():
                diag.raw_config = src.raw_config
                changed = True
            if src.processed_config and not (getattr(diag, "processed_config", None) or "").strip():
                diag.processed_config = src.processed_config
                changed = True
            # Refresh evidence so [취약 근거] is present for export fallbacks.
            if src.evidence and (
                not (diag.evidence or "").strip()
                or (
                    src.vulnerable_config
                    and "[취약 근거]" not in (diag.evidence or "")
                    and src.vulnerable_config not in (diag.evidence or "")
                )
            ):
                diag.evidence = src.evidence
                changed = True
            if changed:
                updated += 1
    return updated
