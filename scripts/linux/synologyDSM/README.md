# Synology DSM 6.2.x 취약점 진단 스캐너

## 범위

이 디렉터리는 Synology DSM 6.2.x 전용 U-01~U-67 취약점 진단 스캐너를 제공합니다.
DSM 메타데이터, 프로세스, 수신 포트, 패키지 정보를 한 번 수집하고 서비스 상태를
식별한 뒤 JSON 보고서와 실행 로그를 생성합니다.

`checkU01.go`~`checkU67.go`가 등록되어 있습니다. DSM UI나 조직 정책, 서비스 사용
목적처럼 자동 확정할 수 없는 항목은 수집한 근거와 함께 `Manual`로 반환하며, 필수
근거를 읽지 못한 경우 빈 값을 `Good`으로 간주하지 않습니다.

## 지원 대상과 DSM 경로

- 지원 판정 대상: DSM 6.2.x
- 버전: `/etc/VERSION`, 대체 경로 `/etc.defaults/VERSION`
- 시스템 정보: `/etc/synoinfo.conf`, 대체 경로 `/etc.defaults/synoinfo.conf`
- 모델: `/proc/sys/kernel/syno_hw_version`

`/etc` 파일을 `/etc.defaults`보다 먼저 사용합니다. DSM이 아니거나 DSM 6.2.x가
아니어도 보고서는 생성하지만, 콘솔과 `.stdout.log`에 비지원 경고를 기록합니다.
메타데이터가 누락된 시스템을 지원 대상으로 판단하지 않습니다.

## 권한과 안전한 실행

실제 DSM 설정과 모든 프로세스·수신 포트를 확인하려면 `root` 권한이 필요할 수
있습니다. 최소 권한으로 먼저 실행하고, 수집 누락이 실제 점검을 방해하는 경우에만
DSM 관리 정책에 따라 권한을 높이십시오.

- 외부 명령은 셸 없이 고정된 프로그램명과 인자로 실행합니다.
- 설정을 변경하거나 서비스를 시작·중지하지 않습니다.
- 파일과 명령의 원문 대소문자는 보존하며, 탐지 비교 때만 소문자로 처리합니다.
- 상세 설정 원문은 실행 요약에 출력하지 않습니다.
- 출력 파일은 기존 파일을 덮어쓰지 않고 `0600` 권한으로 생성합니다.
- 패키지 목록 수집 실패는 전체 실행을 중단하지 않고 수집 오류로 기록합니다.

## 실행과 빌드

개발 환경에서:

```sh
go run .
go build .
```

DSM 장비로 바이너리를 복사한 뒤 해당 장비에서 실행하십시오. 출력 디렉터리는 실행
전에 존재해야 합니다.

## 환경 변수

- `DSM_OUTPUT_DIR`: JSON과 로그를 저장할 기존 디렉터리. 기본값은 현재 디렉터리(`.`).
- `DSM_COMMAND_TIMEOUT`: 개별 명령 제한 시간. 기본값 `5s`, 허용 범위 `1s`~`1m`.

예:

```sh
DSM_OUTPUT_DIR=/volume1/security DSM_COMMAND_TIMEOUT=10s ./synologyDSM
```

## 출력

파일명은 Ubuntu 스캐너·웹 UI `frontend/ui/test_data/*.json`과 동일하게
`<hostname>_<ip>.json` 형식입니다.

- `<hostname>_<ip>.json`: U-01~U-67 `CheckResult` 배열
  (`RawConfig`, `VulnerableConfig`, `ErrMsg`, `Description`, `Status`,
  `ProcessedConfig`, `MitreAttack`, `Code`)
- `<hostname>_<ip>.stdout.log`: 콘솔에 표시한 비민감 실행 요약·경고

`Status`는 정수입니다: 0 Good, 1 Vulnerable, 2 Interview, 3 Manual, 4 N/A, 5 Error.

프로세스 목록, 포트 목록, 패키지 목록은 서비스 탐지에만 사용하며 보고서나 로그에
원문 그대로 노출하지 않습니다.

## 점검 구현 규칙

각 U-01~U-67 점검은 다음 흐름을 따릅니다.

1. `check`: `ScanContext`에 한 번 수집된 자료에서 필요한 근거를 선택합니다.
2. `load`: 파일 읽기나 추가 자료가 꼭 필요하면 읽기 실패를 숨기지 않고 반환합니다.
3. `eval`: 수집과 분리된 순수 판정 로직으로 상태와 근거를 생성합니다.

점검 코드는 시스템을 변경하지 않아야 하며, 사용자 입력으로 명령명이나 인자를
조합하지 않아야 합니다. 민감한 설정 전체 대신 판정에 필요한 최소 근거만 결과에
포함해야 합니다.

## 테스트와 실제 DSM 검증

호스트 명령을 실행하지 않는 단위 테스트:

```sh
go test ./...
go vet ./...
```

테스트는 DSM 6.2/7.x/메타데이터 누락 파싱, BusyBox 명령 대체 순서, IPv4/IPv6
수신 포트 식별, 설정 파싱과 `/etc` 우선순위 및 U-01~U-67 판정 fixture를 다룹니다.

정적 크로스 빌드:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/synologyDSM-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/synologyDSM-arm64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o /tmp/synologyDSM-armv7 .
```

크로스 빌드 성공은 해당 아키텍처에서 컴파일된다는 사실만 증명합니다. DSM의
BusyBox 도구 구성, 권한, 포트 출력 형식과 실제 서비스 동작은 DSM 6.2.x 실장비에서
반드시 별도로 검증해야 합니다.
