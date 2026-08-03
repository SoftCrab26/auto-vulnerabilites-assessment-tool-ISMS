#!/usr/bin/env bash
#
# linux-inspection.sh
# Linux 쉘 스크립트(.sh) 대상 위험 명령어 블랙리스트 점검 스크립트
#
# 기존 워크플로우의 블랙리스트(rm, chmod, chown, curl, wget, nc, dd, mkfs)를
# 위험도별로 세분화하고, 파이프 다운로드/리버스셸/권한상승 패턴을 추가로 점검합니다.
#
# 종료 코드: 위반 발견 시 1, 없으면 0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "==== 🛡️  Linux 위험 명령어 블랙리스트 스캔 시작 ===="
echo "📂 대상 루트: ${REPO_ROOT}"

VIOLATION_FOUND=false

# CI 스크립트·의도적 취약 랩/픽스처는 제외한다.
SH_FILES=$(find . -name "*.sh" \
  -not -path "*/.*" \
  -not -path "./ci/*" \
  -not -path "*/ci/*" \
  -not -path "./test-lab/*" \
  -not -path "*/test-lab/*" \
  -not -path "*/vulnerableEnviorment/*" \
  -not -path "*/vulnerableEnvironment/*")

if [ -z "$SH_FILES" ]; then
  echo "ℹ️  검사 대상 .sh 파일이 없습니다."
  exit 0
fi

check_pattern() {
  local description="$1"
  local pattern="$2"
  local file="$3"

  local matches
  matches=$(grep -nE "$pattern" "$file" | grep -vE '^[0-9]+:[[:space:]]*#')

  if [ -n "$matches" ]; then
    echo "❌ [Violation] $file"
    echo "   └ 항목: $description"
    echo "$matches" | sed 's/^/     /'
    VIOLATION_FOUND=true
  fi
}

for FILE in $SH_FILES; do
  echo "🔍 스캔 중: $FILE"

  # [1] 시스템 파괴 가능성이 있는 삭제/포맷 명령 (rm -rf /, mkfs, dd of=/dev/*)
  check_pattern \
    "루트 경로 강제 삭제(rm -rf /) 의심 패턴" \
    'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+(/[[:space:]]|/\*|/$|/[a-zA-Z]* )' \
    "$FILE"

  check_pattern \
    "디스크 포맷/직접 쓰기 명령(mkfs, dd of=/dev/*) - 데이터 파괴 위험" \
    '\b(mkfs(\.[a-z0-9]+)?|dd\s+.*of=/dev/)' \
    "$FILE"

  # [2] 권한 관련 (chmod 777, chown root 등 과도한 권한 부여)
  check_pattern \
    "과도한 권한 부여(chmod 777/666 등) - 최소 권한 원칙 위반" \
    'chmod\s+(-R\s+)?(777|666|a\+rwx|a\+w)' \
    "$FILE"

  check_pattern \
    "소유권을 root로 변경(chown root) - 권한 상승 위험" \
    'chown\s+(-R\s+)?root' \
    "$FILE"

  # [3] 원격 다운로드 후 즉시 실행 (파이프 투 셸) - 가장 위험한 패턴
  check_pattern \
    "원격 스크립트 다운로드 후 즉시 실행(curl|bash, wget|sh 등) - 매우 위험" \
    '(curl|wget)\s.*\|\s*(sudo\s+)?(bash|sh|zsh)' \
    "$FILE"

  # [4] 단순 다운로드/전송 명령어 (정보 유출 혹은 외부 리소스 다운로드)
  check_pattern \
    "외부 다운로드/전송 명령어 사용(curl, wget, nc, tftp, scp)" \
    '\b(curl|wget|nc|ncat|netcat|tftp)\b' \
    "$FILE"

  # [5] 리버스 셸 의심 패턴 (nc -e, /dev/tcp)
  check_pattern \
    "리버스 셸 의심 패턴(nc -e, /dev/tcp 리다이렉션)" \
    '(nc\s+.*-e\s|/dev/tcp/)' \
    "$FILE"

  # [6] 계정/사용자 조작 (root 권한 계정 생성)
  check_pattern \
    "UID 0(root 권한) 계정 생성/수정 의심" \
    '(useradd|usermod).*(-u\s*0|uid=0)' \
    "$FILE"

  # [7] 방화벽/보안 설정 초기화
  check_pattern \
    "방화벽 규칙 초기화(iptables -F 등) - 보안 정책 우회 위험" \
    'iptables\s+(-F|--flush)' \
    "$FILE"

  # [8] history/log 삭제 (흔적 인멸 의심)
  check_pattern \
    "명령 기록/로그 삭제 - 흔적 인멸 의심" \
    '(history\s+-c|>\s*/var/log/|rm\s+.*\.bash_history)' \
    "$FILE"

done

echo "--------------------------------------------------"
if [ "$VIOLATION_FOUND" = true ]; then
  echo "🚨 빌드 실패: 블랙리스트에 등록된 위험 명령어가 발견되었습니다."
  exit 1
else
  echo "✅ 빌드 성공: 스크립트 내에 알려진 위험 명령어가 없습니다."
  exit 0
fi
