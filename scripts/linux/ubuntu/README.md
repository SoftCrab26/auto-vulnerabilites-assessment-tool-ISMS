# Linux Vulnerability Check

이 폴더는 Linux U-01 ~ U-67 취약점 점검 Go 프로그램과 Docker 기반 테스트 환경을 포함합니다.

## 폴더 구조

```text
scripts/linux/
├── checkU01.go ... checkU67.go
├── main.go
├── service.go
├── util.go
├── result.go
├── go.mod
├── bin/
│   └── linux-check
├── test-output/
│   ├── vulnerable/
│   └── secure/
├── vulnerableEnviorment/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── entrypoint.sh
└── sercureEnviormenet/
    ├── Dockerfile
    ├── docker-compose.yml
    └── entrypoint.sh
```

> 디렉터리명은 현재 요청 기준에 맞춰 `vulnerableEnviorment`, `sercureEnviormenet`를 사용합니다.

## 아키텍처 구성

Linux 점검기는 하나의 Go 실행파일로 빌드되는 `package main` 구조입니다. `main.go`가 런타임 정보를 한 번 수집하고, `checkU01.go` ~ `checkU67.go`가 같은 컨텍스트를 공유해 점검합니다.

```mermaid
flowchart TD
    Start[main()] --> Runtime[collectRuntimeData()]
    Runtime --> Services[detectServices(runtime)]
    Services --> Context[ScanContext{Services, Runtime}]
    Context --> Checks[checkU01(ctx) ... checkU67(ctx)]
    Checks --> Results[CheckResult]
    Results --> Console[Terminal Output]
    Results --> JSON[JSON File Output]
```

### 주요 파일 책임

| 파일 | 역할 |
|------|------|
| `main.go` | 실행 시작점, 런타임/서비스 수집, U-01 ~ U-67 호출, 콘솔/JSON 출력 |
| `service.go` | `ps`, `ss` 기반 런타임 수집, 서비스 카탈로그, 서비스 실행/포트 감지 |
| `result.go` | `CheckResult`, `Status`, `MitreAttack` 타입 정의 |
| `util.go` | 파일 수집, 설정값 파싱, 에러 누적, 공통 문자열 빌더 |
| `checkUXX.go` | 각 U 항목별 입력 수집, 판정, 결과 생성 |
| `vulnerableEnviorment/` | 취약 설정과 열린 서비스가 많은 Docker 테스트 환경 |
| `sercureEnviormenet/` | 보안 설정과 불필요 서비스가 꺼진 Docker 테스트 환경 |

### 실행 흐름

1. `collectRuntimeData()`가 `ps -ef`, `ss -lntup`을 한 번만 실행합니다.
2. `detectServices(runtime)`가 서비스 키워드와 포트를 기반으로 `map[string]Service`를 만듭니다.
3. `ScanContext`에 `Services`와 `Runtime`을 담습니다.
4. 모든 `checkUXX(ctx)`가 같은 `ScanContext`를 재사용합니다.
5. 각 check는 `CheckResult`를 반환합니다.
6. 결과는 터미널에 출력되고 `<hostname>_<ip>.json` 파일로 저장됩니다.

### 서비스 재사용 구조

서비스 상태를 check마다 다시 `ps`/`ss`로 검사하지 않습니다. 서비스 관련 점검은 `ctx.Services` 또는 `ctx.Runtime`을 사용합니다.

예:

```go
func checkU58(ctx ScanContext) CheckResult {
    input, errs := loadU58Input(ctx)
    result := evalU58(input)
    return resultWithErrors(result, errs)
}
```

서비스 카탈로그는 `service.go`의 `detectServices()` 안에 있습니다. 새 서비스 감지가 필요하면 check 파일에서 명령어를 직접 반복하지 말고, 먼저 `Service` 정의에 키워드/포트를 추가하세요.

## 코딩 양식

### checkUXX 파일 기본 구조

각 점검 파일은 아래 순서를 따릅니다.

```go
package main

import (
    "strings"
)

type UXXInput struct {
    RawConfig string
}

func checkUXX(ctx ScanContext) CheckResult {
    const code = "U-XX"
    const description = "..."
    mitreAttack := MitreAttack{
        tactic:      "...",
        techniques:  []string{"..."},
        mitigations: []string{"..."},
    }

    input, errs := loadUXXInput(ctx)

    result := evalUXX(input)
    result.Code = code
    result.Description = description
    result.MitreAttack = mitreAttack
    return resultWithErrors(result, errs)
}

func loadUXXInput(ctx ScanContext) (UXXInput, []string) {
    files, errs := collectFiles("/path/to/config")
    if len(files) == 0 {
        return UXXInput{}, errs
    }
    return UXXInput{RawConfig: files[0].Content}, errs
}

func evalUXX(input UXXInput) CheckResult {
    status := StatusGood
    vulnerableConfig := ""

    // 판단 로직

    return CheckResult{
        Status:           status,
        RawConfig:        input.RawConfig,
        ProcessedConfig:  buildProcessedConfig("key=value"),
        VulnerableConfig: vulnerableConfig,
    }
}
```

### 함수 분리 규칙

| 함수 | 책임 |
|------|------|
| `checkUXX(ctx)` | 메타데이터 설정, load/eval 연결, 에러 누적 |
| `loadUXXInput(ctx)` | 파일/서비스/런타임 입력 수집 |
| `evalUXX(input)` | 순수 판정 로직, `CheckResult` 생성 |

`evalUXX`는 가능하면 파일 시스템이나 외부 명령어를 직접 호출하지 않는 방향을 권장합니다. 예외적으로 `stat`, `find`처럼 해당 점검의 본질인 경우만 사용합니다.

### 에러 처리 규칙

파일 일부를 못 읽었다고 바로 `StatusError`로 처리하지 않습니다.

- 점검 가능한 데이터가 있으면 계속 점검합니다.
- 읽기 실패나 명령 실패는 `ErrMsg`에 남깁니다.
- 온전히 점검이 불가능할 때만 `StatusError`를 사용합니다.

권장 패턴:

```go
input, errs := loadUXXInput(ctx)

result := evalUXX(input)
result.Code = code
result.Description = description
result.MitreAttack = mitreAttack
return resultWithErrors(result, errs)
```

금지 패턴:

```go
if len(errs) > 0 {
    return errorResult(code, description, mitreAttack, errs)
}
```

### 서비스 점검 규칙

서비스 실행 여부는 `ctx.Services`를 우선 사용합니다.

권장:

```go
ftp := ctx.Services["ftp"]
if ftp.IsActive() {
    // vulnerable
}
```

지양:

```go
run("ps -ef | grep -i ftp | grep -v grep")
run("ss -lntup | grep :21")
```

새로운 서비스가 필요하면 `service.go`의 서비스 맵에 추가합니다.

### CheckResult 필드 작성 기준

JSON 파일은 `[{...}, ...]` 배열이며, 웹 UI `frontend/ui/test_data/*.json`과 동일한 스키마입니다.

| 필드 | JSON 키 | 작성 기준 |
|------|---------|-----------|
| `RawConfig` | `RawConfig` | 읽은 원본 설정 또는 명령 결과 |
| `VulnerableConfig` | `VulnerableConfig` | 취약일 때 근거와 문제점 |
| `ErrMsg` | `ErrMsg` | 읽기 실패, 명령 실패 등 stderr성 정보 |
| `Description` | `Description` | 점검 목적을 한 문장으로 설명 |
| `Status` | `Status` | 정수: 0 Good, 1 Vulnerable, 2 Interview, 3 Manual, 4 N/A, 5 Error |
| `ProcessedConfig` | `ProcessedConfig` | 판정에 사용한 핵심 값 요약 |
| `MitreAttack` | `MitreAttack` | `{ "tactic", "techniques", "mitigations" }` |
| `Code` | `Code` | `U-01` 형식 |

파일명: `{hostname}_{ip}.json` (예: `dns_srv_192.168.1.15.json`)

### Status 판단 기준

| Status | 사용 시점 |
|--------|-----------|
| `StatusGood` | 가이드 기준을 만족 |
| `StatusVulnerable` | 가이드 기준을 만족하지 않음 |
| `StatusInterview` | 자동 판정이 어렵고 운영 정책/버전 확인이 필요 |
| `StatusManual` | 수동 확인 전용 항목 |
| `StatusNotApplicable` | 대상 서비스/파일이 없어 해당 없음으로 볼 수 있음 |
| `StatusError` | 입력이 전혀 없어 점검 자체가 불가능 |

### 설정 파싱 규칙

- `findConfigValue(raw, key)`를 우선 사용합니다.
- `key=value`, `key value` 형식을 모두 고려합니다.
- 주석 라인은 제외합니다.
- 취약 근거는 `buildVulnerableConfig()`로 여러 줄 구성합니다.
- 처리 요약은 `buildProcessedConfig()`로 한 줄 구성합니다.

### Go 스타일

- 파일명은 `checkU01.go`처럼 U 코드와 맞춥니다.
- 타입명은 `U01Input`처럼 check 코드와 맞춥니다.
- 함수명은 `checkU01`, `loadU01Input`, `evalU01` 패턴을 사용합니다.
- 불필요한 전역 상태를 추가하지 않습니다.
- 공통 로직은 `util.go` 또는 `service.go`에 둡니다.
- Go 포맷은 항상 `gofmt`를 적용합니다.
- 새 check 추가 후 `go build`와 `go vet`를 실행합니다.

### Docker 테스트 환경 작성 규칙

- 컨테이너 안에는 Go를 설치하지 않습니다.
- 호스트에서 빌드한 `bin/linux-check`만 마운트합니다.
- 취약 환경은 의도적으로 취약한 설정과 열린 서비스를 포함합니다.
- secure 환경은 동일 항목을 비교할 수 있도록 안전한 설정을 포함합니다.
- 결과는 각각 `test-output/vulnerable`, `test-output/secure`에 저장합니다.

## 사전 준비

- Docker Desktop 또는 Docker Engine
- Docker Compose v2
- Go

컨테이너에는 Go를 설치하지 않습니다. Go 빌드는 호스트에서 수행하고, 빌드 산출물만 컨테이너에 마운트해서 실행합니다.

## 실행파일 빌드

프로젝트 루트에서:

```bash
cd scripts/linux
GOOS=linux GOARCH=$(go env GOARCH) go build -o bin/linux-check .
```

빌드 결과:

```text
scripts/linux/bin/linux-check
```

Docker compose 파일은 이 파일을 컨테이너의 `/usr/local/bin/linux-check`로 읽기 전용 마운트합니다.

## 취약 환경 실행

```bash
cd scripts/linux/vulnerableEnviorment
docker compose run --build --rm linux-check-vulnerable
```

결과 JSON은 아래 폴더에 생성됩니다.

```text
scripts/linux/test-output/vulnerable/
```

## 보안 환경 실행

```bash
cd scripts/linux/sercureEnviormenet
docker compose run --build --rm linux-check-secure
```

결과 JSON은 아래 폴더에 생성됩니다.

```text
scripts/linux/test-output/secure/
```

## 한 번에 실행

취약 환경:

```bash
cd scripts/linux
GOOS=linux GOARCH=$(go env GOARCH) go build -o bin/linux-check .
cd vulnerableEnviorment
docker compose run --build --rm linux-check-vulnerable
```

보안 환경:

```bash
cd scripts/linux
GOOS=linux GOARCH=$(go env GOARCH) go build -o bin/linux-check .
cd sercureEnviormenet
docker compose run --build --rm linux-check-secure
```

## 테스트 환경 구성 방식

두 Docker 환경 모두 `rockylinux:9` 기반입니다.

공통 설치 패키지:

- `iproute`
- `nmap-ncat`
- `procps-ng`
- `sudo`
- `which`

`rockylinux:9`에는 `coreutils-single`, `findutils`, `passwd`, `shadow-utils`가 기본 포함되어 있어 별도 설치하지 않습니다. full `coreutils`를 추가 설치하면 `coreutils-single`과 충돌할 수 있습니다.

`nmap-ncat`은 실제 데몬 대신 테스트용 리스너를 띄우기 위해 사용합니다. 점검기는 `ps -ef`, `ss -lntup` 결과를 기반으로 서비스 실행 여부를 감지하므로, entrypoint에서 프로세스명과 포트를 맞춰 시뮬레이션합니다.

## 취약 환경 설정

위치:

```text
scripts/linux/vulnerableEnviorment/
```

주요 취약 설정:

- SSH root 로그인 허용: `PermitRootLogin yes`
- 약한 패스워드 정책:
  - `minlen = 6`
  - `ucredit = 0`
  - `lcredit = 0`
  - `dcredit = 0`
  - `ocredit = 0`
- `/etc/login.defs`:
  - `PASS_MIN_LEN 6`
  - `PASS_MAX_DAYS 99999`
  - `PASS_MIN_DAYS 0`
  - `UMASK 002`
  - `ENCRYPT_METHOD MD5`
- `/etc/profile`:
  - `PATH=.:...`
  - `TMOUT=900`
  - `umask 002`
- csh timeout:
  - `set autologout=30`
- FTP anonymous 허용:
  - `anonymous_enable=YES`
- Samba guest 허용:
  - `guest ok = yes`
  - `map to guest = bad user`
- 중복 UID 0 계정 생성:
  - `uidzero`
- MD5 해시 계정 설정:
  - `root`
  - `legacyadmin`
- 취약 권한:
  - `/etc/shadow` -> `644`
  - `/tmp` -> `777`

entrypoint에서 열어두는 테스트 서비스:

- SSH: `22`
- DNS: `53`
- SNMP: `161`
- FTP: `21`
- Web: `80`
- MySQL: `3306`
- PostgreSQL: `5432`
- Telnet: `23`
- Finger: `79`
- NFS: `2049`
- RPC: `111`
- NIS: `834`
- TFTP: `69`
- Talk: `517`, `518`
- SMTP: `25`
- RSH: `514`
- DoS 취약 서비스: `7`, `9`, `13`, `19`

## 보안 환경 설정

위치:

```text
scripts/linux/sercureEnviormenet/
```

주요 보안 설정:

- SSH root 로그인 차단: `PermitRootLogin no`
- PAM 패스워드 품질 모듈 설정:
  - `pam_pwquality.so`
  - `pam_faillock.so`
- 강한 패스워드 정책:
  - `minlen = 8`
  - `ucredit = -1`
  - `lcredit = -1`
  - `dcredit = -1`
  - `ocredit = -1`
- `/etc/login.defs`:
  - `PASS_MIN_LEN 8`
  - `PASS_MAX_DAYS 90`
  - `PASS_MIN_DAYS 1`
  - `UMASK 022`
  - `ENCRYPT_METHOD SHA512`
- `/etc/profile`:
  - 안전한 PATH
  - `TMOUT=600`
  - `readonly TMOUT`
  - `umask 022`
- csh timeout:
  - `set autologout=10`
- FTP anonymous 차단:
  - `anonymous_enable=NO`
- Samba guest 차단:
  - `guest ok = no`
  - `map to guest = never`
- SHA-512 해시 계정:
  - `auditor`
- 보안 권한:
  - `/etc/passwd` -> `644`
  - `/etc/shadow` -> `400`
- 불필요 서비스 리스너를 띄우지 않음

## 결과 확인

실행 후 출력 파일명은 컨테이너 hostname과 IP를 기반으로 생성됩니다.

예:

```text
scripts/linux/test-output/vulnerable/<hostname>_<ip>.json
scripts/linux/test-output/secure/<hostname>_<ip>.json
```

터미널 stdout도 같은 출력 폴더에 저장됩니다.

```text
scripts/linux/test-output/vulnerable/<hostname>_<ip>.stdout.log
scripts/linux/test-output/secure/<hostname>_<ip>.stdout.log
```

터미널 출력에서도 각 점검 항목의 `CODE`, `STATUS`, `DESCRIPTION`, `PROCESSED`, `VULNERABLE CONFIG`, `ERROR`를 확인할 수 있습니다.

## Docker 구성 검증

취약 환경:

```bash
cd scripts/linux/vulnerableEnviorment
docker compose config
```

보안 환경:

```bash
cd scripts/linux/sercureEnviormenet
docker compose config
```

## 개발 중 검증

Go 코드 검증:

```bash
cd scripts/linux
go build -o /dev/null .
go vet ./...
```

Linux 실행파일 재빌드:

```bash
cd scripts/linux
GOOS=linux GOARCH=$(go env GOARCH) go build -o bin/linux-check .
```

## 주의사항

- `bin/linux-check`는 빌드 산출물입니다. 소스가 바뀌면 다시 빌드해야 합니다.
- Docker 환경에는 Go가 없으므로 컨테이너 안에서 빌드하지 않습니다.
- `vulnerableEnviorment`와 `sercureEnviormenet`는 테스트 환경이므로 실제 운영 서버 설정으로 사용하지 마세요.
- 취약 환경은 의도적으로 위험한 설정을 포함합니다.
