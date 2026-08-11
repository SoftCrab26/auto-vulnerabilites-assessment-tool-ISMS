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
    err_msg: str = ""


@dataclass
class ParsedReport:
    hostname: str = "UNKNOWN"
    ip_address: str = "0.0.0.0"
    target_os: str = "Linux"
    inspection_date: str = ""
    source_filename: str = ""
    diagnostics: list[ParsedDiagnostic] = field(default_factory=list)


def linux_category(code: str) -> str:
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


def map_go_status(status: int) -> str:
    return {0: "Pass", 1: "Fail", 2: "N/A", 3: "N/A", 4: "N/A", 5: "Fail"}.get(status, "N/A")


def parse_filename_meta(filename: str) -> tuple[str, str, str]:
    base = Path(filename).stem
    parts = base.split("_")
    hostname = "UNKNOWN"
    ip_address = "0.0.0.0"
    target_os = "Linux"

    known = {"windowsserver", "unix", "dbms", "linux", "windows", "pc"}
    if len(parts) >= 3:
        first = parts[0].strip()
        if first.lower() in known:
            key = first.lower()
            if key == "windowsserver":
                target_os = "Windows Server"
            elif key in {"unix", "linux"}:
                target_os = "Linux"
            elif key == "dbms":
                target_os = "DBMS"
            elif key in {"pc", "windows"}:
                target_os = "Windows"
            else:
                target_os = first
            ip_address = parts[-1]
            hostname = "_".join(parts[1:-1]) or "UNKNOWN"
        else:
            ip_address = parts[-1]
            hostname = "_".join(parts[:-1]) or "UNKNOWN"
            target_os = "Linux"
    elif len(parts) == 2:
        hostname, ip_address = parts[0], parts[1]
        target_os = "Linux"
    else:
        hostname = base
    return hostname, ip_address, target_os


def _guideline_lookup(guidelines: list[dict[str, Any]], os_type: str, code: str) -> dict[str, Any] | None:
    guide_os = "Windows" if "windows" in os_type.lower() else "Linux"
    for g in guidelines:
        if g.get("os_type", "").lower() == guide_os.lower() and g.get("code", "").lower() == code.lower():
            return g
    return None


def convert_go_results(
    go_results: list[dict[str, Any]],
    filename: str,
    guidelines: list[dict[str, Any]],
) -> ParsedReport:
    hostname, ip_address, target_os = parse_filename_meta(filename)
    report = ParsedReport(
        hostname=hostname,
        ip_address=ip_address,
        target_os=target_os,
        inspection_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_filename=Path(filename).name,
    )

    for go in go_results:
        status_int = int(go.get("Status", go.get("status", 4)))
        status_str = map_go_status(status_int)
        code = str(go.get("Code") or go.get("code") or "")
        description = str(go.get("Description") or go.get("description") or "")
        raw = str(go.get("RawConfig") or go.get("raw_config") or "")
        vulnerable = str(go.get("VulnerableConfig") or go.get("vulnerable_config") or "")
        processed = str(go.get("ProcessedConfig") or go.get("processed_config") or "")
        err_msg = str(go.get("ErrMsg") or go.get("err_msg") or "")
        mitre = go.get("MitreAttack") or go.get("mitre_attack") or {}

        guide = _guideline_lookup(guidelines, target_os, code)
        pass_comm = (guide or {}).get("pass_comment") or "설정이 기준에 부합하여 안전합니다."
        fail_comm = (guide or {}).get("fail_comment") or "설정이 기준에 미달하여 취약합니다."
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

        if status_str == "Pass":
            status_section = pass_comm
        elif status_str == "Fail":
            status_section = fail_comm
        elif status_int == 2:
            status_section = "인터뷰"
        else:
            status_section = "N/A"

        evidence = (
            f"{status_section}\n\n[검출된 설정값 (ProcessedConfig)]\n{processed}\n\n"
            f"[진단 로그 / 설정 원본 (RawConfig)]\n{raw}"
        )
        if err_msg:
            evidence += f"\n\n[오류 메시지]\n{err_msg}"

        report.diagnostics.append(
            ParsedDiagnostic(
                code=code,
                category=linux_category(code),
                title=description,
                status=status_str,
                severity=linux_severity(code),
                description=description,
                evidence=evidence,
                remediation=remediation,
                processed_config=processed,
                err_msg=err_msg,
            )
        )
    return report


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
                report.diagnostics.append(
                    ParsedDiagnostic(
                        code=str(item.get("code") or item.get("Code") or ""),
                        category=str(item.get("category") or item.get("Category") or ""),
                        title=str(item.get("title") or item.get("Title") or item.get("description") or ""),
                        status=str(item.get("status") or item.get("Status") or "N/A"),
                        severity=str(item.get("severity") or item.get("Severity") or "Medium"),
                        description=str(item.get("description") or item.get("Description") or ""),
                        evidence=str(item.get("evidence") or item.get("Evidence") or ""),
                        remediation=str(item.get("remediation") or item.get("Remediation") or ""),
                        processed_config=str(item.get("processed_config") or item.get("ProcessedConfig") or ""),
                        err_msg=str(item.get("err_msg") or item.get("ErrMsg") or ""),
                    )
                )
            return report if report.diagnostics else None

    if isinstance(data, list) and data and isinstance(data[0], dict):
        if any(k in data[0] for k in ("Code", "code", "Status", "status")):
            return convert_go_results(data, filename, guidelines)

    # Oracle-style wrapped report: { Results: [...], ... }
    if isinstance(data, dict):
        results = data.get("Results") or data.get("results")
        if isinstance(results, list) and results:
            return convert_go_results(results, filename, guidelines)

    return None


def looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value or ""))
