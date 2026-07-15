# Windows Vulnerability Check

이 폴더는 Windows W-01 ~ W-43 취약점 점검 Go 프로그램을 포함합니다.

`checkW01.go` ~ `checkW43.go`는 Linux 점검기와 같은 `check/load/eval` 구조로 구현되어 있습니다. 가이드에 명확한 기준이 있는 항목은 자동 판정하고, 임계값이나 허용 목록이 없는 항목은 수집한 근거와 함께 `Manual` 또는 `Interview`로 반환합니다.

## 폴더 구조

```text
scripts/windows/
├── README.md
├── go.mod
├── main.go
├── service.go
├── util.go
├── result.go
└── checkW01.go ... checkW43.go
```

## 아키텍처 구성

Windows 점검기는 하나의 Go 실행파일로 빌드되는 `package main` 구조입니다. `main.go`가 런타임 정보를 한 번 수집하고, `checkWXX.go`가 같은 컨텍스트를 공유해 점검합니다.

```mermaid
flowchart TD
    Start[main()] --> Runtime[collectRuntimeData()]
    Runtime --> Services[detectServices(runtime)]
    Services --> Context[ScanContext{Services, Runtime}]
    Context --> Checks[checkW01(ctx) ... checkW43(ctx)]
    Checks --> Results[CheckResult]
    Results --> Console[Terminal Output]
    Results --> JSON[JSON File Output]
```

`main.go`는 `checkW01(ctx)`부터 `checkW43(ctx)`까지 코드 순서대로 실행합니다.

## 주요 파일 책임

| 파일 | 역할 |
|------|------|
| `main.go` | 실행 시작점, 런타임/서비스 수집, 콘솔/JSON 출력 |
| `service.go` | PowerShell 기반 런타임 수집, 서비스 카탈로그, 서비스 실행/포트 감지 |
| `result.go` | `CheckResult`, `Status`, `MitreAttack` 타입 정의 |
| `util.go` | 명령 결과 수집, 설정값 파싱, 에러 누적, 공통 문자열 빌더 |
| `checkWXX.go` | 각 W 항목별 입력 수집, 판정, 결과 생성 |

## 실행 흐름

1. `collectRuntimeData()`가 PowerShell 명령으로 프로세스, 포트, 서비스, OS, 방화벽, Defender 상태를 수집합니다.
2. `detectServices(runtime)`가 서비스명, 프로세스명, 포트를 기반으로 `map[string]Service`를 만듭니다.
3. `ScanContext`에 `Services`와 `Runtime`을 담습니다.
4. 모든 `checkWXX(ctx)`가 같은 `ScanContext`를 재사용합니다.
5. 각 check는 `CheckResult`를 반환합니다.
6. 결과는 터미널에 출력되고 `<hostname>_<ip>.json` 파일로 저장됩니다.

## 서비스 재사용 구조

서비스 상태를 check마다 다시 PowerShell로 검사하지 않습니다. 서비스 관련 점검은 `ctx.Services` 또는 `ctx.Runtime`을 사용합니다.

예:

```go
func checkW20(ctx ScanContext) CheckResult {
    input, errs := loadW20Input(ctx)
    result := evalW20(input)
    return resultWithErrors(result, errs)
}
```

서비스 카탈로그는 `service.go`의 `detectServices()` 안에 있습니다. 새 서비스 감지가 필요하면 check 파일에서 명령어를 직접 반복하지 말고, 먼저 `Service` 정의에 키워드/서비스명/포트를 추가하세요.

현재 기본 서비스 키:

- `rdp`
- `remoteRegistry`
- `iis`
- `mssql`
- `snmp`
- `ftp`
- `telnet`
- `smtp`
- `smb`
- `defender`
- `firewall`
- `windowsUpdate`

## 코딩 양식

### checkWXX 파일 기본 구조

각 점검 파일은 아래 순서를 따릅니다.

```go
package main

import (
    "strings"
)

type WXXInput struct {
    RawConfig string
}

func checkWXX(ctx ScanContext) CheckResult {
    const code = "W-XX"
    const description = "..."
    mitreAttack := MitreAttack{
        tactic:      "...",
        techniques:  []string{"..."},
        mitigations: []string{"..."},
    }

    input, errs := loadWXXInput(ctx)

    result := evalWXX(input)
    result.Code = code
    result.Description = description
    result.MitreAttack = mitreAttack
    return resultWithErrors(result, errs)
}

func loadWXXInput(ctx ScanContext) (WXXInput, []string) {
    commands, errs := collectCommands("Get-LocalUser | Format-List | Out-String")
    if len(commands) == 0 {
        return WXXInput{}, errs
    }
    return WXXInput{RawConfig: commands[0].Output}, errs
}

func evalWXX(input WXXInput) CheckResult {
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
| `checkWXX(ctx)` | 메타데이터 설정, load/eval 연결, 에러 누적 |
| `loadWXXInput(ctx)` | 명령/서비스/런타임 입력 수집 |
| `evalWXX(input)` | 순수 판정 로직, `CheckResult` 생성 |

`evalWXX`는 가능하면 외부 명령어를 직접 호출하지 않는 방향을 권장합니다. 입력 수집은 `loadWXXInput`에서 끝내고, 판정은 수집된 문자열과 구조체를 기준으로 수행합니다.

## CheckResult 필드 작성 기준

| 필드 | 작성 기준 |
|------|-----------|
| `Code` | `W-01` 형식 |
| `Description` | 점검 목적을 한 문장으로 설명 |
| `Status` | `Good`, `Vulnerable`, `Interview`, `Manual`, `NotApplicable`, `Error` |
| `RawConfig` | 읽은 원본 명령 결과 또는 설정 내용 |
| `ProcessedConfig` | 판정에 사용한 핵심 값 요약 |
| `VulnerableConfig` | 취약일 때 근거와 문제점 |
| `ErrMsg` | 명령 실패 등 stderr성 정보 |
| `MitreAttack` | 관련 tactic/technique/mitigation |

## Status 판단 기준

| Status | 사용 시점 |
|--------|-----------|
| `StatusGood` | 가이드 기준을 만족 |
| `StatusVulnerable` | 가이드 기준을 만족하지 않음 |
| `StatusInterview` | 자동 판정이 어렵고 운영 정책/버전 확인이 필요 |
| `StatusManual` | 수동 확인 전용 항목 |
| `StatusNotApplicable` | 대상 서비스/설정이 없어 해당 없음으로 볼 수 있음 |
| `StatusError` | 입력이 전혀 없어 점검 자체가 불가능 |

## PowerShell 사용 규칙

- 런타임 수집은 `service.go`의 `collectRuntimeData()`에서 한 번 수행합니다.
- 개별 점검에서 추가 명령이 필요하면 `collectCommands()`를 사용합니다.
- 서비스 실행 여부는 `ctx.Services`를 우선 사용합니다.
- 설정 출력은 `findConfigValue(raw, key)`로 `key=value`, `key: value`, `key value` 형식을 우선 파싱합니다.
- 취약 근거는 `buildVulnerableConfig()`로 여러 줄 구성합니다.
- 처리 요약은 `buildProcessedConfig()`로 한 줄 구성합니다.

## Go 스타일

- 파일명은 `checkW01.go`처럼 W 코드와 맞춥니다.
- 타입명은 `W01Input`처럼 check 코드와 맞춥니다.
- 함수명은 `checkW01`, `loadW01Input`, `evalW01` 패턴을 사용합니다.
- 불필요한 전역 상태를 추가하지 않습니다.
- 공통 로직은 `util.go` 또는 `service.go`에 둡니다.
- Go 포맷은 항상 `gofmt`를 적용합니다.
- 새 check 추가 후 `go build`와 `go vet`를 실행합니다.

## 사전 준비

- Windows Server 또는 Windows 클라이언트
- PowerShell 5.1 이상 또는 PowerShell 7
- Go

일부 점검은 관리자 권한 PowerShell에서 실행해야 정확한 결과를 얻을 수 있습니다.

## 실행파일 빌드

Windows 환경에서:

```powershell
cd scripts/windows
go build -o bin/windows-check.exe .
```

macOS/Linux에서 Windows 대상 바이너리를 교차 빌드할 경우:

```bash
cd scripts/windows
GOOS=windows GOARCH=amd64 go build -o bin/windows-check.exe .
```

## 실행

Windows 환경에서:

```powershell
go run .
```

또는 빌드된 실행파일을 실행합니다.

```powershell
.\bin\windows-check.exe
```

실행 후 출력 파일명은 hostname과 IP를 기반으로 생성됩니다.

```text
<hostname>_<ip>.json
<hostname>_<ip>.stdout.log
```

터미널 출력에서도 각 서비스 감지 결과와 각 점검 항목의 `CODE`, `STATUS`, `DESCRIPTION`, `PROCESSED`, `VULNERABLE CONFIG`, `ERROR`를 확인할 수 있습니다.

## 개발 중 검증

Go 코드 검증:

```bash
cd scripts/windows
go build -o /dev/null .
go vet ./...
```

Windows 실행파일 재빌드:

```bash
cd scripts/windows
GOOS=windows GOARCH=amd64 go build -o bin/windows-check.exe .
```

## 주의사항

- 정확한 계정, 레지스트리, ACL, 감사 정책 수집을 위해 관리자 권한 PowerShell에서 실행하세요.
- `go run main.go`는 다른 Go 파일을 포함하지 않아 컴파일되지 않으므로 반드시 `go run .`을 사용하세요.
- 조직별 임계값이나 허용 목록이 필요한 항목은 `Manual` 또는 `Interview`로 출력됩니다.
- 일부 PowerShell cmdlet은 Windows 버전 또는 권한에 따라 결과가 비어 있을 수 있습니다.
- 실제 운영 서버에서 실행하기 전 테스트 서버에서 결과 형식을 먼저 확인하세요.
