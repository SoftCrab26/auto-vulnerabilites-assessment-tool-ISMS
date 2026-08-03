#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
export GOTOOLCHAIN=auto
export CGO_ENABLED=0

rm -rf "$BUILD"

# outdir: build/<category>/<kind>/<arch_label>/
# arch_label: x86-64 | ibm-power | arm64 | armv7
build_one() {
  local src="$1"
  local category="$2"
  local kind="$3"
  local name="$4"
  local goos="$5"
  local goarch="$6"
  local arch_label="$7"
  local goarm="${8:-}"
  local howto="$9"

  local outdir="$BUILD/$category/$kind/$arch_label"
  mkdir -p "$outdir"

  local outfile="$outdir/$name"
  if [[ "$goos" == "windows" ]]; then
    outfile="${outfile}.exe"
  fi

  echo ">>> $src -> ${outfile#"$ROOT"/} (GOOS=$goos GOARCH=$goarch${goarm:+ GOARM=$goarm} label=$arch_label)"
  (
    cd "$ROOT/$src"
    if [[ -n "$goarm" ]]; then
      GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" go build -trimpath -ldflags="-s -w" -o "$outfile" .
    else
      GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "$outfile" .
    fi
  )

  printf '%s\n' "$howto" >"$outdir/HOWTO.txt"
}

ubuntu_howto() {
  local bin="$1"
  local cpu="$2"
  cat <<EOF
Ubuntu Linux 취약점 점검 실행 방법
================================

대상
  - Ubuntu Linux 호스트 (U-01 ~ U-67)
  - CPU: ${cpu}
  - 이 디렉터리 바이너리와 대상 서버 CPU/아키텍처가 일치해야 합니다.

사전 준비
  1. 바이너리를 대상 서버로 복사합니다.
  2. 실행 권한을 부여합니다.
       chmod +x ./${bin}
  3. 가능한 한 root 권한으로 실행합니다 (계정/권한/서비스 수집 정확도).

실행
  sudo ./${bin}

결과 파일 (실행 디렉터리에 생성)
  <hostname>_<ip>.json
    - 점검 결과 보고서 (U-01 ~ U-67)
    - 각 항목: CODE, STATUS, DESCRIPTION, ProcessedConfig, VulnerableConfig, RawConfig 등
  <hostname>_<ip>.stdout.log
    - 콘솔에 출력된 실행 요약 로그 사본

예시
  web01_192.168.0.10.json
  web01_192.168.0.10.stdout.log
EOF
}

synology_howto() {
  local bin="$1"
  local cpu="$2"
  cat <<EOF
Synology DSM 취약점 점검 실행 방법
=================================

대상
  - Synology DSM 6.2.x (U-01 ~ U-67)
  - CPU: ${cpu}
  - DSM CPU 아키텍처에 맞는 바이너리를 사용합니다.

사전 준비
  1. 바이너리를 DSM으로 복사합니다. (예: /volume1/security/)
  2. SSH로 접속한 뒤 실행 권한을 부여합니다.
       chmod +x ./${bin}

실행 (권장)
  sudo ./${bin}

선택 환경 변수
  DSM_OUTPUT_DIR=/volume1/security DSM_COMMAND_TIMEOUT=10s sudo -E ./${bin}

결과 파일 (DSM_OUTPUT_DIR 또는 실행 디렉터리)
  synology_dsm_<host>_<ip>_<UTC타임스탬프>.json
    - OS/DSM 메타데이터, U-01 ~ U-67 결과, Warnings
  synology_dsm_<host>_<ip>_<UTC타임스탬프>.stdout.log
    - 콘솔에 표시한 비민감 실행 요약

예시
  synology_dsm_NAS_192.168.0.20_20260730T021500.000000000Z.json
  synology_dsm_NAS_192.168.0.20_20260730T021500.000000000Z.stdout.log
EOF
}

aix_howto() {
  local bin="$1"
  local cpu="$2"
  cat <<EOF
AIX 취약점 점검 실행 방법
=======================

대상
  - AIX (ppc64 바이너리)
  - CPU: ${cpu}
  - AIX 7.2+ 권장

사전 준비
  1. 바이너리를 AIX 서버로 복사합니다.
  2. 실행 권한을 부여합니다.
       chmod +x ./${bin}

실행
  sudo ./${bin}

결과 파일 (실행 디렉터리에 생성)
  <hostname>_<ip>.json
    - 점검 결과 보고서 (U-01 ~ U-67)
  <hostname>_<ip>.stdout.log
    - 콘솔 출력 로그 사본

예시
  aixdb01_10.0.0.5.json
  aixdb01_10.0.0.5.stdout.log

참고
  - root 권한이 없으면 일부 계정/보안 파일 수집이 누락될 수 있습니다.
EOF
}

oracle_howto() {
  local bin="$1"
  local cpu="$2"
  cat <<EOF
Oracle DB 취약점 점검 실행 방법
=============================

대상
  - Oracle DB 엔진 점검 (D-01 ~ D-26)
  - CPU/OS: ${cpu}
  - sqlplus 와 ORACLE_HOME 이 보이는 환경에서 실행합니다.
  - Linux ibm-power 는 ppc64le(ELF) 이고, AIX 는 aix-ppc64(XCOFF) 를 사용하십시오.

사전 준비
  1. 이 아키텍처 바이너리를 DB 호스트로 복사합니다.
  2. 실행 권한 (AIX 0403-006 방지)
       chmod +x ./${bin}
       ls -l ./${bin}
  3. PATH 에 sqlplus 가 있어야 합니다. (없으면 ORACLE_SQLPLUS=/path/to/sqlplus)

필수 환경 변수
  ORACLE_CONNECT   SQL*Plus connect 뒤에 붙는 단일 행 연결 명세
                   예) '/ as sysdba'
                   예) '/@wallet_alias'

실행 예 (AIX / ksh)
  ORACLE_HOME=/oracle/app/oracle/product/11g \\
  ORACLE_SQLPLUS=/oracle/app/oracle/product/11g/bin/sqlplus \\
  ORACLE_OUTPUT_DIR=/tmp \\
  ORACLE_CONNECT='/ as sysdba' \\
  ./${bin}

선택 환경 변수
  ORACLE_SQLPLUS=/oracle/app/oracle/product/.../bin/sqlplus
  ORACLE_OUTPUT_DIR=/tmp
  ORACLE_HOME / ORACLE_BASE   (D-13~D-15 호스트 파일 점검용)

참고
  - 쿼리 타임아웃은 180초 고정 (ORACLE_QUERY_TIMEOUT 불필요)

결과 파일 (ORACLE_OUTPUT_DIR 또는 실행 디렉터리, 권한 0600)
  oracle_<DB_UNIQUE_NAME또는호스트>_<UTC타임스탬프>.json
    - engine: ORACLE
    - DB 메타데이터 (이름, 버전, role, open mode 등)
    - GeneratedAt, D-01 ~ D-26 Results
  oracle_<DB_UNIQUE_NAME또는호스트>_<UTC타임스탬프>.stdout.log
    - 콘솔에 출력된 점검 요약 로그

예시
  oracle_ORCLCDB_20260730T021500.000000000Z.json
  oracle_ORCLCDB_20260730T021500.000000000Z.stdout.log

주의
  - ORACLE_CONNECT 는 이 스캐너 전용 변수이며 Oracle 표준 env 가 아닙니다.
  - 비밀번호를 명령 이력에 남기지 마십시오. Wallet / OS 인증을 권장합니다.
  - AIX 에서는 build/db/oracleDB/aix-ppc64 바이너리만 사용하십시오.
EOF
}

aws_howto() {
  local bin="$1"
  local cpu="$2"
  cat <<EOF
AWS 취약점 점검 실행 방법
=======================

대상
  - AWS 계정/리소스 점검 (aws CLI 사용)
  - CPU: ${cpu}
  - 실행 호스트에 aws CLI 와 유효한 자격 증명이 필요합니다.

사전 준비
  1. aws configure 또는 환경 변수로 자격 증명 설정
  2. chmod +x ./${bin}

실행
  ./${bin}

결과 파일 (실행 디렉터리에 생성)
  <accountId>_<region>.json
    - AWS 점검 결과 보고서
  <accountId>_<region>.stdout.log
    - 콘솔 출력 로그 사본

예시
  123456789012_ap-northeast-2.json
  123456789012_ap-northeast-2.stdout.log

참고
  - IAM 권한이 부족한 항목은 수집 실패/수동 확인으로 남을 수 있습니다.
EOF
}

windows_howto() {
  local bin="$1"
  local cpu="$2"
  cat <<EOF
Windows 취약점 점검 실행 방법
===========================

대상
  - Windows Server / Desktop (W-01 ~ W-43)
  - CPU: ${cpu}
  - 이 디렉터리 바이너리와 대상 OS 아키텍처가 일치해야 합니다.

사전 준비
  1. 바이너리를 대상 Windows 로 복사합니다.
  2. 관리자 권한 PowerShell 을 엽니다.

실행
  .\\${bin}.exe

결과 파일 (실행 디렉터리에 생성)
  <hostname>_<ip>.json
    - 점검 결과 보고서 (W-01 ~ W-43)
  <hostname>_<ip>.stdout.log
    - 콘솔 출력 로그 사본

예시
  WIN-SERVER01_192.168.0.50.json
  WIN-SERVER01_192.168.0.50.stdout.log

참고
  - 계정/레지스트리/ACL/감사 정책 수집을 위해 관리자 권한 실행을 권장합니다.
EOF
}

CPU_X86_64="x86-64 / Intel Xeon / AMD EPYC (GOARCH=amd64)"
CPU_POWER_LINUX="IBM Power (linux ppc64le)"
CPU_POWER_AIX="IBM Power (AIX ppc64)"
CPU_ARM64="ARM64 (aarch64)"
CPU_ARMV7="ARMv7 (32-bit)"

# ---------- x86-64 (GOARCH=amd64) ----------
build_one scripts/linux/ubuntu      linux ubuntu      ubuntu-check      linux   amd64   x86-64 "" "$(ubuntu_howto ubuntu-check "$CPU_X86_64")"
build_one scripts/linux/synologyDSM linux synologyDSM synologyDSM-check linux   amd64   x86-64 "" "$(synology_howto synologyDSM-check "$CPU_X86_64")"
build_one scripts/db/oracleDB       db    oracleDB    oracleDB-check    linux   amd64   x86-64 "" "$(oracle_howto oracleDB-check "$CPU_X86_64")"
build_one scripts/aws               aws   aws         aws-check         linux   amd64   x86-64 "" "$(aws_howto aws-check "$CPU_X86_64")"
build_one scripts/windows           windows windows   windows-check     windows amd64   x86-64 "" "$(windows_howto windows-check "$CPU_X86_64")"

# ---------- IBM Power ----------
# Linux on Power (ppc64le)
build_one scripts/linux/ubuntu      linux ubuntu      ubuntu-check      linux   ppc64le ibm-power "" "$(ubuntu_howto ubuntu-check "$CPU_POWER_LINUX")"
build_one scripts/linux/synologyDSM linux synologyDSM synologyDSM-check linux   ppc64le ibm-power "" "$(synology_howto synologyDSM-check "$CPU_POWER_LINUX")"
build_one scripts/db/oracleDB       db    oracleDB    oracleDB-check    linux   ppc64le ibm-power "" "$(oracle_howto oracleDB-check "$CPU_POWER_LINUX")"
build_one scripts/aws               aws   aws         aws-check         linux   ppc64le ibm-power "" "$(aws_howto aws-check "$CPU_POWER_LINUX")"
# AIX on Power (ppc64 / XCOFF)
build_one scripts/linux/aix         linux aix         aix-check         aix     ppc64   ibm-power "" "$(aix_howto aix-check "$CPU_POWER_AIX")"
build_one scripts/linux/aix         linux aix         aix-check         aix     ppc64   ppc64     "" "$(aix_howto aix-check "$CPU_POWER_AIX")"
# Oracle on AIX — Linux ibm-power(ppc64le) 와 다름
build_one scripts/db/oracleDB       db    oracleDB    oracleDB-check    aix     ppc64   aix-ppc64 "" "$(oracle_howto oracleDB-check "$CPU_POWER_AIX")"

# ---------- ARM (기존 NAS/엣지용, CPU 명칭 유지) ----------
build_one scripts/linux/ubuntu      linux ubuntu      ubuntu-check      linux arm64 arm64 "" "$(ubuntu_howto ubuntu-check "$CPU_ARM64")"
build_one scripts/linux/ubuntu      linux ubuntu      ubuntu-check      linux arm   armv7 7 "$(ubuntu_howto ubuntu-check "$CPU_ARMV7")"
build_one scripts/linux/synologyDSM linux synologyDSM synologyDSM-check linux arm64 arm64 "" "$(synology_howto synologyDSM-check "$CPU_ARM64")"
build_one scripts/linux/synologyDSM linux synologyDSM synologyDSM-check linux arm   armv7 7 "$(synology_howto synologyDSM-check "$CPU_ARMV7")"
build_one scripts/db/oracleDB       db    oracleDB    oracleDB-check    linux arm64 arm64 "" "$(oracle_howto oracleDB-check "$CPU_ARM64")"
build_one scripts/aws               aws   aws         aws-check         linux arm64 arm64 "" "$(aws_howto aws-check "$CPU_ARM64")"
build_one scripts/aws               aws   aws         aws-check         linux arm   armv7 7 "$(aws_howto aws-check "$CPU_ARMV7")"
build_one scripts/windows           windows windows   windows-check     windows arm64 arm64 "" "$(windows_howto windows-check "$CPU_ARM64")"

echo
echo "==== build tree ===="
find "$BUILD" -type f | sort | while read -r f; do
  if [[ "$f" == *.txt ]]; then
    printf "%s\n" "${f#"$ROOT"/}"
  else
    printf "%-56s " "${f#"$ROOT"/}"
    file "$f" | sed "s|^$f: ||"
  fi
done

echo
echo "done: $BUILD"
echo
echo "CPU map:"
echo "  x86-64      -> GOARCH=amd64   (Intel Xeon / AMD / x86_64)"
echo "  ibm-power   -> GOARCH=ppc64le (Linux on Power) / AIX OS scanner ppc64"
echo "  aix-ppc64   -> GOOS=aix GOARCH=ppc64 (Oracle DB on AIX, XCOFF)"
echo "  ppc64       -> GOOS=aix GOARCH=ppc64 (AIX OS scanner alias)"
echo "  arm64/armv7 -> ARM devices"
