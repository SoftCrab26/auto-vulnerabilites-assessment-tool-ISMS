# ISMS-P Analyzer Web (Python SaaS)

기존 WPF `frontend/ui`를 FastAPI 모놀리식으로 이식한 셀프호스트 웹 UI입니다.

## 기능

- 세션 로그인 (기본 `admin` / `admin`)
- 진단 JSON 다중 업로드 (Go `[]CheckResult` / `system_info+diagnostics`)
- 대시보드 통계 · 호스트 필터
- 진단결과 상세분석
- 조치 가이드 관리
- 엑셀/xlsm 보고서 생성·다운로드

## 실행 (로컬 Python)

```bash
cd frontend/web
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

브라우저: <http://127.0.0.1:8000>

## Docker 이미지

```bash
cd frontend/web
docker build -t <NEXUS_HOST>:<PORT>/isms-web:1.0.0 .
docker push <NEXUS_HOST>:<PORT>/isms-web:1.0.0
```

클러스터 배포는 기존 매니페스트에서 위 이미지 주소만 지정하면 됩니다.

## 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `WEB_ADMIN_USER` | `admin` | 관리자 계정 |
| `WEB_ADMIN_PASSWORD` | `admin` | 관리자 비밀번호 (운영 시 반드시 변경) |
| `WEB_SECRET_KEY` | 내장 기본값 | 세션 서명 키 |
| `WEB_DATA_DIR` | `frontend/web/data` | DB/업로드/내보내기 경로 |

> 관리자 계정은 DB에 없을 때만 시드됩니다. Secret을 바꾼 뒤에도 기존 `app.db`가 있으면 비밀번호가 자동 갱신되지 않습니다.

## 데이터

- SQLite: `data/app.db`
- 업로드: `data/uploads/`
- 내보내기: `data/exports/`
- 엑셀 템플릿: `templates_excel/`

## 참고

- Linux SaaS에서는 Windows Excel COM 검증을 사용하지 않습니다. openpyxl로 템플릿에 값을 주입합니다.
- WPF 앱(`frontend/ui`)은 참고용으로 유지됩니다.
