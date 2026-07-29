# Oracle DB 취약점 점검기

이 디렉터리는 Oracle 엔진 및 로컬 Oracle 호스트 설정을 읽는 표준 라이브러리 전용 Go 스캐너입니다. D-01~D-26 전체가 등록되어 있으며 자동 판정이 불가능한 항목은 실제 판단 근거를 `RawConfig`에 기록하고 `Manual`로 반환합니다.

## 기준과 적용 범위

참조된 **2024 AWS 가이드는 클라우드/RDS 통제 가이드이지 Oracle 내부 설정 가이드가 아닙니다.** 따라서 기준을 다음 두 계층으로 분리합니다.

- 엔진 계층: `guide/주통기/주통기_database.md`의 D-01~D-26
- 클라우드/RDS 계층: AWS PDF의 2.1, 3.1, 3.2, 3.8, 4.2, 4.4, 4.9, 4.12, 4.13 항목

Oracle 엔진 계층의 구현 구분은 다음과 같습니다.

1. 자동 또는 증거 기반 점검: D-01~D-15, D-17~D-22, D-25~D-26
2. 사람의 정책·목적 확인이 필요한 경우: 실제 조회 결과와 호스트 설정을 `RawConfig`에 기록하고 `Manual`
3. Oracle 비적용 대상: D-16, D-23, D-24 (`NotApplicable`)

명백하게 안전 통제가 해제된 경우는 `Vulnerable`, 필요한 근거를 모두 수집해 자동 판정 가능한 경우는 `Good`, 조회 실패나 필수 근거 누락은 `Error`입니다. D-19 문서의 `REMOTE_OS_AUTHENTICATION` 표기는 Oracle 실제 파라미터 `REMOTE_OS_AUTHENT`에 대응합니다.

## 구현 현황과 향후 정책 연계

1. 계정·프로파일 자동 점검
   - D-01~D-06, D-09를 `DBA_USERS`, `DBA_PROFILES`, `DBA_ROLE_PRIVS` 기반으로 구현합니다.
   - 불필요 계정과 허용 DBA 계정은 조직마다 다르므로 현재는 조회 증거와 함께 `Manual`로 처리합니다. 향후 권한이 제한된 조직 정책 파일을 연계하면 자동 판정할 수 있습니다.
   - 패스워드 해시나 verifier 원문은 수집·출력하지 않고 `PASSWORD_VERSIONS`, 계정 상태 및 프로파일 이름만 증거로 사용합니다.
2. 접근·권한 자동 점검
   - D-10~D-12, D-17~D-21을 `DBA_TAB_PRIVS`, `DBA_SYS_PRIVS`, `DBA_ROLE_PRIVS`, `V$PARAMETER` 및 Listener 설정 증거로 구현합니다.
   - Listener 파일 접근이 불가능한 RDS는 엔진 쿼리 결과와 RDS API 결과를 분리하고, 확인 불가능한 값을 `Good`으로 추정하지 않습니다.
3. 호스트·파일 점검
   - D-07, D-08, D-13~D-15는 Oracle 프로세스 소유자, `ORACLE_HOME` 주요 파일, Listener 로그/trace 권한을 별도 호스트 수집기로 점검합니다.
   - D-13은 설치 목적을 자동 판단할 수 없어 인벤토리 증거를 제공하고 최종 상태는 `Manual`로 유지합니다.
4. 패치·감사 점검
   - D-25는 `DBA_REGISTRY_SQLPATCH`와 버전 정보를 수집하되 최신 보안 패치 여부는 Oracle CPU 기준 데이터와 비교합니다.
   - D-26은 `AUDIT_TRAIL`, Unified Auditing 활성화 상태 및 감사 정책을 확인합니다. 기관별 보존기간·감사 대상은 정책 입력이 없으면 `Manual`로 처리합니다.
5. AWS/RDS 통제 연계
   - AWS PDF의 RDS 서브넷, 저장 암호화, 통신 암호화, 로그 내보내기, 보존기간 및 백업 통제는 `scripts/aws` 또는 별도 AWS API 수집기로 구현합니다.
   - Oracle 엔진 결과와 AWS 리소스 결과는 DB 식별자를 기준으로 상위 보고서에서 결합하며 어느 한쪽 결과로 다른 계층을 대체하지 않습니다.

각 항목은 `checkDXX -> loadDXXInput -> evalDXX` 구조를 사용합니다. SQL 실행은 `load` 단계에만 두고 `eval`은 fixture 입력만으로 테스트 가능한 순수 판정 함수로 유지합니다.

## 현재 쿼리와 권한

스캐너는 메타데이터를 한 번 수집한 뒤 각 점검을 실행합니다.

- 메타데이터: `V$DATABASE` (`NAME`, `DB_UNIQUE_NAME`, `DATABASE_ROLE`, `OPEN_MODE`), `V$INSTANCE` (`VERSION`)
- 계정·프로파일: `DBA_USERS_WITH_DEFPWD`, `DBA_USERS`, `DBA_PROFILES`, `DBA_ROLE_PRIVS`, `V$PWFILE_USERS`
- 프로세스·네트워크·파라미터: `V$PROCESS`, `V$PARAMETER`, `V$OPTION`
- 권한·객체: `DBA_TAB_PRIVS`, `DBA_SYS_PRIVS`, `DBA_ROLE_PRIVS`, `DBA_OBJECTS`
- 패치·감사: `DBA_REGISTRY_SQLPATCH`, `AUDIT_UNIFIED_ENABLED_POLICIES`, `DBA_STMT_AUDIT_OPTS`, `DBA_PRIV_AUDIT_OPTS`, `DBA_OBJ_AUDIT_OPTS`
- 로컬 호스트: `ORACLE_HOME`, `ORACLE_BASE`, ODBC 설정 파일 및 Listener 설정·로그 파일의 존재 여부와 권한

운영 환경에는 전용 읽기 전용 감사 사용자를 권장합니다. 조직 정책에 따라 `SELECT_CATALOG_ROLE`을 부여하거나, 더 엄격한 최소 권한이 필요하면 SYS 사용자가 기반 객체에 명시적 권한을 부여합니다.

```sql
GRANT SELECT ON V_$DATABASE TO audit_user;
GRANT SELECT ON V_$INSTANCE TO audit_user;
GRANT SELECT ON V_$PARAMETER TO audit_user;
```

`SYSDBA` 연결은 장애 대응용 폴백일 뿐 상시 점검 방식으로 권장하지 않습니다. 감사 계정에는 로그인, 전송 구간 보호, 비밀번호/외부 인증 정책과 결과 파일 접근 통제를 함께 적용해야 합니다.

## 설정

| 환경 변수 | 필수 | 기본값 | 설명 |
|---|---:|---|---|
| `ORACLE_CONNECT` | 예 | 없음 | SQL*Plus `connect` 뒤에 사용할 단일 행 연결 명세 |
| `ORACLE_SQLPLUS` | 아니요 | `sqlplus` | SQL*Plus 실행 파일 경로 |
| `ORACLE_QUERY_TIMEOUT` | 아니요 | `15s` | 쿼리 제한 시간(1초~5분) |
| `ORACLE_OUTPUT_DIR` | 아니요 | 현재 디렉터리 | JSON 및 stdout 로그 디렉터리 |

지갑 또는 외부 인증을 우선 사용합니다. 리터럴 비밀번호를 명령 이력에 넣지 마십시오.

```sh
ORACLE_CONNECT='/@wallet_alias' go run .
ORACLE_CONNECT='/' ORACLE_QUERY_TIMEOUT='20s' go run .
# 로컬 관리 작업에서만 필요한 경우:
ORACLE_CONNECT='/ as sysdba' go run .
```

애플리케이션 감사 계정의 연결 명세도 지원하지만, 비밀번호를 예제·스크립트·프로세스 인자에 직접 기록하지 마십시오. 실행 환경의 비밀 주입 기능이나 Oracle Wallet을 사용하십시오.

## 빌드, 테스트, 실행

저장소의 Go 버전과 동일한 Go 1.26.3을 사용합니다.

```sh
go test ./...
go vet ./...
go build .
ORACLE_CONNECT='/@wallet_alias' ./oracleDB
```

출력 파일명은 `oracle_<정제된 DB_UNIQUE_NAME 또는 호스트>_<UTC 타임스탬프>.json` 및 `.stdout.log` 형식입니다. 두 파일은 신규 생성 시 `0600` 권한으로 제한됩니다. JSON에는 `engine: ORACLE`, DB 메타데이터, 생성 시각, D 코드 기반 결과가 포함됩니다.

## 안전 설계

- `sqlplus`는 셸 없이 `exec.CommandContext`와 고정 인자 `-L -S /nolog`로만 실행합니다.
- 연결 명세는 표준 입력의 `connect` 문에만 전달하며 argv, 로그, JSON, 반환 오류에 기록하지 않습니다.
- `ORACLE_CONNECT`는 단일 행만 허용해 SQL*Plus 입력 삽입을 차단합니다.
- SQL*Plus의 heading, feedback, echo, verify를 끄고 고정 구분자 `|~|`를 사용합니다.
- `QueryRunner`에 전달하는 SQL은 소스에 정의된 상수 `SELECT`만 허용합니다. 환경 변수, 연결 명세, 사용자 입력을 SQL 문자열에 결합하면 안 됩니다.
- Oracle 오류는 연결 문자열과 자격 증명 패턴을 제거한 뒤 결과에 기록합니다.
- 쿼리 실패, 필수 행 누락, 메타데이터 실패는 `Good`으로 간주하지 않고 `Error`로 처리합니다.
- `RawConfig`에는 파라미터 이름과 불리언 값 같은 정제된 증거만 저장합니다.

## Amazon RDS for Oracle 제약

RDS에서는 호스트 접근과 일반적인 `SYSDBA` 사용이 제공되지 않습니다. RDS가 허용하는 마스터/감사 계정 권한과 조회 가능 뷰만 사용하고, 접근 불가능한 엔진 증거를 억지로 추론하지 마십시오. VPC, 백업, 암호화, 로깅, IAM 및 RDS 구성 같은 클라우드 통제는 RDS API와 별도 AWS 스캐너로 점검해야 하며, 이 엔진 스캐너 결과로 대체할 수 없습니다.
