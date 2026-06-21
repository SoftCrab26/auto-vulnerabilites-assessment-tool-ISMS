# AWS Vulnerability Check

이 폴더는 SK Shieldus 2024 클라우드 보안가이드(AWS) 기준 AWS-01 ~ AWS-63 점검 Go 프로그램입니다.

## 폴더 구조

```text
scripts/aws/
├── checkAWS01.go ... checkAWS63.go
├── main.go
├── service.go
├── util.go
├── result.go
├── go.mod
└── README.md
```

## 가이드 매핑

| 코드 | 가이드 | 영역 |
|------|--------|------|
| AWS-01 ~ AWS-13 | 1.1 ~ 1.13 | 계정 관리 |
| AWS-14 ~ AWS-16 | 2.1 ~ 2.3 | 권한 관리 |
| AWS-17 ~ AWS-26 | 3.1 ~ 3.10 | 가상 리소스 관리 |
| AWS-27 ~ AWS-41 | 4.1 ~ 4.15 | 운영 관리 |
| AWS-42 ~ AWS-63 | 예비 항목 | 가이드 미정의 (stub) |

상세 판단 기준은 `guide/SK쉴더스/SK_AWS.md`를 참고합니다.

## 아키텍처 구성

Linux 점검기와 동일하게 `package main` 단일 바이너리 구조입니다. `main.go`가 AWS CLI 데이터를 한 번 수집하고, `checkAWS01.go` ~ `checkAWS63.go`가 같은 `ScanContext`를 공유합니다.

```mermaid
flowchart TD
    Start[main()] --> Runtime[collectAWSRuntimeData()]
    Runtime --> Resources[detectAWSResources(runtime)]
    Resources --> Context[ScanContext{Resources, Runtime}]
    Context --> Checks[checkAWS01(ctx) ... checkAWS63(ctx)]
    Checks --> Results[CheckResult]
    Results --> Console[Terminal Output]
    Results --> JSON[JSON File Output]
```

### 주요 파일 책임

| 파일 | 역할 |
|------|------|
| `main.go` | 실행 시작점, AWS 런타임/리소스 수집, AWS-01 ~ AWS-63 호출, 콘솔/JSON 출력 |
| `service.go` | `aws` CLI 기반 런타임 수집, 리소스 가용성 감지 |
| `result.go` | `CheckResult`, `Status`, `MitreAttack` 타입 정의 |
| `util.go` | 에러 누적, 공통 문자열 빌더, JSON 보조 함수 |
| `checkAWSXX.go` | 각 AWS 항목별 입력 수집, 판정, 결과 생성 (현재 stub) |

### 실행 흐름

1. `collectAWSRuntimeData()`가 IAM, EC2, S3, RDS, EKS 등 `aws` CLI 명령을 한 번만 실행합니다.
2. `detectAWSResources(runtime)`가 수집 결과를 기반으로 `map[string]AWSResource`를 만듭니다.
3. `ScanContext`에 `Resources`와 `Runtime`을 담습니다.
4. 모든 `checkAWSXX(ctx)`가 같은 `ScanContext`를 재사용합니다.
5. 결과는 터미널에 출력되고 `<accountId>_<region>.json` 파일로 저장됩니다.

## 사전 준비

- Go 1.26+
- AWS CLI v2
- 유효한 AWS 자격 증명 (`aws configure` 또는 환경 변수)

필요 시 credential report 생성 권한:

```bash
aws iam generate-credential-report
```

## 빌드

```bash
cd scripts/aws
go build -o bin/aws-check .
```

## 실행

```bash
cd scripts/aws
./bin/aws-check
```

출력 예:

```text
<accountId>_<region>.json
<accountId>_<region>.stdout.log
```

## 코딩 양식

Linux 점검기와 동일한 3단 함수 구조를 사용합니다.

| 함수 | 책임 |
|------|------|
| `checkAWSXX(ctx)` | 메타데이터 설정, load/eval 연결, 에러 누적 |
| `loadAWSXXInput(ctx)` | `ctx.Runtime` / `ctx.Resources`에서 입력 수집 |
| `evalAWSXX(input)` | 순수 판정 로직, `CheckResult` 생성 |

현재 AWS-01 ~ AWS-63은 stub 상태이며 `StatusManual` 또는 `StatusNotApplicable`을 반환합니다. 실제 판정 로직은 `evalAWSXX`에 구현하면 됩니다.

## 개발 중 검증

```bash
cd scripts/aws
go build -o /dev/null .
go vet ./...
```

## 주의사항

- `aws` CLI가 PATH에 있어야 합니다.
- 일부 항목은 EKS/RDS/S3 등 해당 리소스가 없으면 `StatusNotApplicable` 처리가 필요할 수 있습니다.
- AWS-42 ~ AWS-63은 가이드 확장용 예비 항목입니다.
