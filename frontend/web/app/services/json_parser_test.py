from __future__ import annotations

import json
from pathlib import Path

from app.services.json_parser import parse_json_report


def test_complete_check_result_skips_korean_fail_banner():
    sample = [
        {
            "Code": "U-46",
            "Description": "Restrict ordinary users from running the mail queue.",
            "Status": 1,
            "RawConfig": (
                "# @(#)sendmail.cf 1.35 src/bos/usr/sbin/sendmail/sendmail.cf, "
                "cmdsend, bos71\nO PrivacyOptions=authwarnings\n" + ("# pad\n" * 400)
            ),
            "VulnerableConfig": "PrivacyOptions does not include restrictqrun.",
            "ProcessedConfig": "privacy_options=authwarnings",
            "ErrMsg": "",
            "MitreAttack": {
                "tactic": "Privilege Escalation",
                "techniques": ["T1548"],
                "mitigations": ["M1026"],
            },
        }
    ]
    parsed = parse_json_report(json.dumps(sample), "ilis1_121.172.114.130.json", [])
    assert parsed is not None
    assert parsed.hostname == "ilis1"
    assert parsed.target_os == "AIX"
    item = parsed.diagnostics[0]
    assert item.status == "Fail"
    assert "기준에 미달하여 취약합니다" not in item.evidence
    assert "PrivacyOptions does not include restrictqrun" in item.evidence
    assert "privacy_options=authwarnings" in item.evidence
    assert "truncated" in item.evidence


def test_aix_filename_prefix():
    sample = [
        {
            "Code": "U-01",
            "Description": "root login",
            "Status": 0,
            "RawConfig": "PermitRootLogin no",
            "VulnerableConfig": "",
            "ProcessedConfig": "PermitRootLogin=no",
            "ErrMsg": "",
            "MitreAttack": {"tactic": "", "techniques": [], "mitigations": []},
        }
    ]
    parsed = parse_json_report(json.dumps(sample), "aix_srv_192.168.1.100.json", [])
    assert parsed is not None
    assert parsed.target_os == "AIX"
    assert parsed.diagnostics[0].status == "Pass"


def test_pc_filename_and_codes():
    sample = [
        {
            "Code": "PC-01",
            "Description": "비밀번호의 주기적 변경",
            "Status": 0,
            "RawConfig": "Maximum password age (days): 42",
            "VulnerableConfig": "최대 암호 사용 기간이 90일 이하로 설정된 경우이므로 양호함.",
            "ProcessedConfig": "Maximum password age (days): 42",
            "ErrMsg": "",
            "MitreAttack": {"tactic": "", "techniques": [], "mitigations": []},
        },
        {
            "Code": "PC-02",
            "Description": "비밀번호 관리정책 설정",
            "Status": 1,
            "RawConfig": "MinimumPasswordLength = 0",
            "VulnerableConfig": "최소 암호 길이가 8문자 미만이거나 확인할 수 없어 취약함.",
            "ProcessedConfig": "MinimumPasswordLength = 0",
            "ErrMsg": "",
            "MitreAttack": {"tactic": "", "techniques": [], "mitigations": []},
        },
    ]
    parsed = parse_json_report(json.dumps(sample), "HHJ-PC-2025_203.200.10.45.json", [])
    assert parsed is not None
    assert parsed.hostname == "HHJ-PC-2025"
    assert parsed.ip_address == "203.200.10.45"
    assert parsed.target_os == "Windows"
    assert parsed.diagnostics[0].category == "계정 관리"
    assert parsed.diagnostics[0].severity == "High"
    assert parsed.diagnostics[0].status == "Pass"
    assert parsed.diagnostics[1].status == "Fail"
    assert parsed.diagnostics[1].severity == "High"


if __name__ == "__main__":
    test_complete_check_result_skips_korean_fail_banner()
    test_aix_filename_prefix()
    test_pc_filename_and_codes()
    real = Path("/Users/loke/work/천일/회신 결과/서버/aix/ilis1_121.172.114.130.json")
    if real.exists():
        parsed = parse_json_report(real.read_text(encoding="utf-8-sig"), real.name, [])
        assert parsed is not None
        assert parsed.target_os == "AIX"
        u46 = next(d for d in parsed.diagnostics if d.code == "U-46")
        assert "기준에 미달하여 취약합니다" not in u46.evidence
        assert "[취약 근거]" in u46.evidence
        assert "truncated" in u46.evidence
        print("real file OK", parsed.hostname, parsed.target_os, "evidence_len", len(u46.evidence))
    print("OK")
