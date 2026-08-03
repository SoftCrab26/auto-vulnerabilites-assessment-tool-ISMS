#!/usr/bin/env bash
#
# go-db-vuln-scan.sh
# Go 코드 내 DB 관련 취약점(블랙리스트 패턴) 점검 스크립트
#
# 점검 항목:
#   [1] SQL 문자열 조합(Sprintf/문자열 + 연산자)으로 쿼리를 만드는 패턴 -> SQL Injection 위험
#   [2] fmt.Sprintf 로 만든 문자열을 Query/Exec 에 바로 전달하는 패턴
#   [3] DB 연결 정보(비밀번호, DSN)가 코드에 하드코딩된 패턴
#   [4] os/exec.Command 에 외부 입력을 그대로 연결(커맨드 인젝션)
#   [5] 에러를 무시하는 DB 호출 (_ = db.Exec(...)) - 보안상 silent failure 위험
#
# 종료 코드: 위반 발견 시 1, 없으면 0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "==== 🛡️  Go DB 취약점 블랙리스트 스캔 시작 ===="
echo "📂 대상 루트: ${REPO_ROOT}"

VIOLATION_FOUND=false

# 테스트 픽스처의 가짜 비밀번호/DSN 문자열은 제외한다.
GO_FILES=$(find . -name "*.go" \
  -not -name "*_test.go" \
  -not -path "*/vendor/*" \
  -not -path "*/.git/*" \
  -not -path "./ci/*" \
  -not -path "*/ci/*" \
  -not -path "./test-lab/*" \
  -not -path "*/test-lab/*" \
  -not -path "*/vulnerableEnviorment/*" \
  -not -path "*/vulnerableEnvironment/*")

if [ -z "$GO_FILES" ]; then
  echo "ℹ️  검사 대상 .go 파일이 없습니다."
  exit 0
fi

check_pattern() {
  local description="$1"
  local pattern="$2"
  local file="$3"

  # 주석(// 로 시작하는 라인) 제외하고 검사
  local matches
  matches=$(grep -nE "$pattern" "$file" | grep -vE '^[0-9]+:[[:space:]]*//')

  if [ -n "$matches" ]; then
    echo "❌ [Violation] $file"
    echo "   └ 항목: $description"
    echo "$matches" | sed 's/^/     /'
    VIOLATION_FOUND=true
  fi
}

for FILE in $GO_FILES; do
  echo "🔍 스캔 중: $FILE"

  # [1] fmt.Sprintf 로 만든 값을 Query/QueryRow/Exec 에 바로 전달 (SQL Injection 의심)
  check_pattern \
    "동적 문자열 조합(Sprintf 등)으로 SQL 쿼리 생성 - Prepared Statement/Placeholder(\$1, ?) 사용 권장" \
    '(Query|QueryRow|Exec)\(\s*(fmt\.Sprintf|["'\''"]?\s*\+)' \
    "$FILE"

  # [2] SQL 키워드와 + 문자열 연결이 같은 라인에 있는 경우 (직접적인 쿼리 문자열 concat)
  check_pattern \
    "SQL 키워드와 문자열 '+' 연산자 조합 - SQL Injection 가능성" \
    '"[^"]*(SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+' \
    "$FILE"

  # [3] DB 접속정보 하드코딩 (password=, DSN 문자열 내 credential)
  check_pattern \
    "DB 접속 정보(비밀번호/DSN)가 코드에 하드코딩됨 - 환경변수/Secret Manager 사용 권장" \
    '(password|passwd|pwd)\s*[:=]\s*["'\''][^"'\'']+["'\'']' \
    "$FILE"

  check_pattern \
    "DSN 형태의 문자열에 계정정보가 그대로 포함됨 (예: user:pass@tcp(...))" \
    '[a-zA-Z0-9_]+:[a-zA-Z0-9_@#\$%\^&\*]+@(tcp|unix)\(' \
    "$FILE"

  # [4] exec.Command 에 외부 입력이 그대로 연결되는 패턴 (커맨드 인젝션 의심)
  check_pattern \
    "exec.Command 사용 - 사용자 입력이 그대로 전달되지 않는지 확인 필요 (커맨드 인젝션 위험)" \
    'exec\.Command\(' \
    "$FILE"

  # [5] DB 에러를 무시하는 패턴
  check_pattern \
    "DB 호출 결과의 에러를 무시함(_ =) - 실패 시 silent failure 위험" \
    '_\s*=\s*[a-zA-Z0-9_.]*\.(Exec|Query|QueryRow)\(' \
    "$FILE"

done

echo "--------------------------------------------------"
if [ "$VIOLATION_FOUND" = true ]; then
  echo "🚨 빌드 실패: Go 코드 내 DB 관련 취약 패턴이 발견되었습니다."
  exit 1
else
  echo "✅ 빌드 성공: DB 관련 위험 패턴이 발견되지 않았습니다."
  exit 0
fi
