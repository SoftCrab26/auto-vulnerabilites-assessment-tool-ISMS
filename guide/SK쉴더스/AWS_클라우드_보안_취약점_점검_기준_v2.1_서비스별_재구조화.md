# 🔐 AWS 클라우드 보안 취약점 점검 기준
## v2.1 — 서비스·도메인별 재구조화 버전 (2026.06)

> **실제 공격자·펜테스트 관점**에서 가장 위험도가 높은 항목들을 중심으로 재구성했습니다.  
> 기존 번호 체계 대신 **서비스/도메인별**로 그룹핑하여 실무에서 더 쉽게 찾아보고, 감사 보고서 작성 시에도 편리하게 사용할 수 있도록 만들었습니다.

---

## 📋 목차 (Table of Contents)

- [1. Identity & Access Management (IAM) 🔑](#1-identity--access-management-iam-)
- [2. Network & Perimeter Security 🌐](#2-network--perimeter-security-)
- [3. Compute & Container Security 🖥️](#3-compute--container-security-)
- [4. Storage Security 🗄️](#4-storage-security-)
- [5. Database Security 🗃️](#5-database-security-)
- [6. Secrets & Key Management 🔐](#6-secrets--key-management-)
- [7. Logging, Monitoring & Detection 📡](#7-logging-monitoring--detection-)
- [8. Backup & Resilience 💾](#8-backup--resilience-)

---

## 1. Identity & Access Management (IAM) 🔑

**목표**: 과도한 권한, Root 계정 남용, 자격증명 유출, Privilege Escalation 방지

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **IAM-01** | Root 계정 관리 | Root Access Key 없음 + MFA 필수 + 일상 업무 미사용 + 보안 연락처 등록 | Root Access Key 존재 또는 MFA 미적용 |
| **IAM-02** | MFA 설정 | Console 로그인 시 모든 사용자 MFA 활성화 | MFA 미적용 계정 존재 |
| **IAM-03** | IAM 최소 권한 원칙 | `AdministratorAccess` 극소수에게만 부여, `*` 정책 최소화 | AdministratorAccess 남용 또는 `*` 정책 다수 |
| **IAM-04** | IAM Role Trust Policy | AssumeRole 대상이 특정 계정/서비스로 엄격 제한 + External ID 사용 | `*` 또는 광범위한 principal 허용 |
| **IAM-05** | Access Key 관리 | 90일 이내 순환 + 90일 이상 미사용 키 자동 비활성화 | 90일 초과 사용 또는 미사용 키 장기 방치 |
| **IAM-06** | Secrets Management | Secrets Manager / SSM SecureString 사용, 코드·UserData·env에 하드코딩 금지 | 자격증명 평문 노출 (코드, Lambda, EC2 UserData 등) |
| **IAM-07** | IAM Access Analyzer | Access Analyzer 활성화 + 미사용 자격증명 자동 정리 | Analyzer 미사용 또는 장기 미사용 키 방치 |
| **IAM-08** | Organizations SCP | 위험한 IAM 작업(`iam:CreateUser`, `AttachUserPolicy` 등) SCP로 계정 수준 차단 | SCP 미적용 또는 약한 정책 |
| **IAM-09** | IAM Identity Center (SSO) | SSO + Permission Set으로 최소 권한 관리, 직접 IAM 사용자 최소화 | 직접 IAM 사용자 과다 또는 SSO 미도입 |
| **IAM-10** | 패스워드 정책 | 복잡성 + 만료 + 재사용 제한 + 이력 관리 모두 적용 | 기준 미달 또는 설정 미적용 |
| **IAM-11** | 사용자 계정 관리 | 관리자 권한 계정 최소화 + 불필요한 계정 없음 | 관리자 권한 계정 다수 또는 불필요 계정 다수 |
| **IAM-12** | Key Pair 보관 | Key Pair를 Secrets Manager 또는 안전한 비공개 저장소에 보관 | 퍼블릭 S3, Git, EC2 콘솔 등에 노출 |

---

## 2. Network & Perimeter Security 🌐

**목표**: 불필요한 퍼블릭 노출 차단, lateral movement 방지, DDoS/App 공격 방어

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **NET-01** | 보안 그룹 ANY 포트 개방 | `0.0.0.0/0` Any 포트(특히 22, 3389, DB 포트) 허용 없음 | 위험 포트가 `0.0.0.0/0`으로 개방 |
| **NET-02** | 보안 그룹 Source/Destination 제한 | Source/Destination이 최소 신뢰 구간으로 제한 | 불필요하게 광범위한 Source/Destination 존재 |
| **NET-03** | 네트워크 ACL | 모든 트래픽(`0.0.0.0/0` ALLOW) 규칙 없음 | 모든 트래픽 허용 규칙 존재 |
| **NET-04** | 라우팅 테이블 | 불필요한 `0.0.0.0/0` IGW 라우팅 없음 + Private Subnet 적절 격리 | 불필요한 퍼블릭 라우팅 존재 |
| **NET-05** | EC2 IMDSv2 강제 | 모든 EC2에서 IMDSv2 **강제** + Hop Limit = 1 | IMDSv1 활성화 또는 optional (SSRF 위험) |
| **NET-06** | Public Accessibility 차단 | RDS, EC2, Redshift 등 Public IP/접근 비활성화 | Public으로 노출된 리소스 존재 |
| **NET-07** | VPC Endpoints / PrivateLink | S3, KMS, Secrets Manager, DynamoDB 등 Private Endpoint 사용 | Public 인터넷 경유 접근 |
| **NET-08** | WAF + Shield | 인터넷 노출 ALB/API Gateway/CloudFront에 WAF + Shield 적용 | WAF/Shield 미적용 |
| **NET-09** | 인터넷 게이트웨이 / NAT 관리 | 불필요한 리소스가 IGW/NAT에 연결되지 않음 | 목적 불분명 리소스가 퍼블릭에 연결 |
| **NET-10** | Security Group 정기 Audit | 0.0.0.0/0 규칙 정기 검토 및 최소화 | 방치된 광범위 규칙 다수 존재 |

---

## 3. Compute & Container Security 🖥️

**목표**: EC2, EKS, Lambda, ECS 등 워크로드 보안

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **COMP-01** | EC2 Instance Profile / Role | 최소 권한으로 설정 | 과도한 권한 (`*` 또는 AdministratorAccess) |
| **COMP-02** | EKS RBAC (ConfigMap) | 인가된 사용자만 최소 권한으로 설정 | 불필요한 사용자 또는 과도한 권한 존재 |
| **COMP-03** | EKS ServiceAccount Token | `automountServiceAccountToken: false` 적용 | 기본값(true)으로 노출 |
| **COMP-04** | EKS 익명 접근 차단 | `system:anonymous` / `unauthenticated` 바인딩 없음 | 익명 그룹 바인딩 존재 |
| **COMP-05** | EKS Pod Security Standards | PSS Baseline 이상 + PSA Enforce/Audit + NetworkPolicy 적용 | PSS Privileged 또는 NetworkPolicy 미적용 |
| **COMP-06** | EKS Network Policy | Pod 간 통신 최소 권한으로 제어 | NetworkPolicy 미적용 |
| **COMP-07** | EKS Pod IAM (IRSA) | IRSA 사용 + Secrets CSI / External Secrets Operator | Node IAM Role 상속 또는 Secret 평문 노출 |
| **COMP-08** | ECR 이미지 보안 | Image Scanning 활성화 + Signed 이미지 Admission 적용 | 스캔 미적용 또는 unsigned 이미지 허용 |
| **COMP-09** | EKS Control Plane 로깅 | API, Audit, Authenticator 등 모든 로그 활성화 | 일부 또는 전체 로그 비활성화 |
| **COMP-10** | EKS Secrets 암호화 | KMS를 통한 Secrets encryption 활성화 | 암호화 미적용 |
| **COMP-11** | Lambda 보안 | 환경변수 KMS 암호화 + Code Signing + 최소 권한 Execution Role | 평문 env var 또는 과도한 권한 Role |
| **COMP-12** | EC2 User Data / 하드코딩 방지 | User Data에 자격증명 하드코딩 금지 | 평문 자격증명 노출 |

---

## 4. Storage Security 🗄️

**목표**: S3, EBS, 스냅샷 등 저장 데이터 보호

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **STOR-01** | S3 Block Public Access | 계정 수준 + 버킷 수준 Block Public Access 강제 | Block Public Access 미적용 |
| **STOR-02** | S3 Bucket Policy / ACL | Bucket Ownership = BucketOwnerEnforced + 최소 권한 Policy | Public ACL 또는 과도한 Policy 존재 |
| **STOR-03** | S3 암호화 | SSE-KMS 또는 SSE-S3 + Bucket Key 적용 | 암호화 미적용 |
| **STOR-04** | EBS 암호화 | EBS 볼륨 암호화(KMS CMK 권장) 활성화 | 암호화 비활성화 |
| **STOR-05** | 퍼블릭 스냅샷 차단 | EBS, RDS, AMI 스냅샷 Public 공유 금지 | Public 스냅샷 존재 (누구나 복사 가능) |
| **STOR-06** | S3 Object Lock + Versioning | 중요한 버킷에 Object Lock(Compliance) + Versioning + MFA Delete 적용 | Ransomware 공격에 취약 |
| **STOR-07** | S3 서버 액세스 로깅 | Server Access Logging + CloudTrail Data Events 활성화 | 로깅 미적용 |

---

## 5. Database Security 🗃️

**목표**: RDS, Aurora 등 데이터베이스 보안

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **DB-01** | RDS Public Accessibility | Public Accessibility 비활성화 | Public으로 노출 |
| **DB-02** | RDS 암호화 | 저장 암호화 + 전송 구간 SSL/TLS 강제 | 암호화 미적용 또는 전송 암호화 미강제 |
| **DB-03** | RDS Deletion Protection | Deletion Protection 활성화 | Deletion Protection 미적용 |
| **DB-04** | RDS 백업 및 PITR | Automated Backup + Point-in-Time Recovery 활성화 | 백업 또는 PITR 미적용 |
| **DB-05** | RDS 로깅 | CloudWatch Logs + Audit Log 활성화 | 로깅 미흡 |
| **DB-06** | RDS 서브넷 / 보안 그룹 | 최소한의 AZ + 엄격한 보안 그룹 적용 | 불필요한 AZ 또는 과도한 SG 규칙 |

---

## 6. Secrets & Key Management 🔐

**목표**: KMS, Secrets Manager를 통한 키 및 비밀 관리

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **KEY-01** | KMS Key Policy | 특정 principal/action으로 엄격 제한 | `*` 또는 광범위한 계정 허용 |
| **KEY-02** | KMS Key Rotation | Customer Managed Key 자동 순환 활성화 | Rotation 비활성화 |
| **KEY-03** | CloudTrail / CloudWatch Logs 암호화 | SSE-KMS 암호화 적용 | 암호화 미적용 |
| **KEY-04** | Secrets Manager 사용 | 중요한 자격증명을 Secrets Manager에 저장 | 평문 또는 SSM Parameter Store 미암호화 사용 |

---

## 7. Logging, Monitoring & Detection 📡

**목표**: 가시성 확보 + 이상 징후 조기 탐지

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **LOG-01** | CloudTrail 고급 설정 | Multi-Region + Management + Data Events(S3, Lambda 등) + Log File Validation | Data Events 미로깅 또는 Validation 미적용 |
| **LOG-02** | VPC Flow Logs | 모든 서브넷에 Flow Logs 활성화 | Flow Logs 미적용 |
| **LOG-03** | Detective Services | GuardDuty + Security Hub + Inspector + Macie 모두 활성화 | 하나 이상 미활성화 |
| **LOG-04** | 실시간 알림 | CloudWatch Alarms + SNS로 Critical 이벤트(Root 로그인, IAM 변경, GuardDuty Finding) 즉시 알림 | Critical 이벤트 알림 체계 미구축 |
| **LOG-05** | 로그 보관 기간 | 최소 1년 이상 + Object Lock 적용 (가능한 경우) | 1년 미만 또는 삭제 용이 |
| **LOG-06** | 인스턴스 / RDS / S3 로깅 | CloudWatch + CloudTrail Data Events로 수집 | 로깅 미흡 또는 미적용 |

---

## 8. Backup & Resilience 💾

**목표**: 데이터 손실 및 랜섬웨어로부터 복구 가능성 확보

| 코드 | 점검항목 | 양호 기준 | 취약 기준 |
|------|----------|-----------|-----------|
| **BKP-01** | AWS Backup 정책 | 정기 백업 정책 존재 및 수행 | 백업 정책 미존재 또는 미수행 |
| **BKP-02** | AWS Backup Vault Lock | Vault Lock 적용으로 immutable backup 보장 | Vault Lock 미적용 |
| **BKP-03** | S3 Object Lock | 중요한 버킷에 Compliance 모드 Object Lock 적용 | Object Lock 미적용 |
| **BKP-04** | RDS / EBS 스냅샷 관리 | 자동 스냅샷 + Cross-Region/Account 백업 | 스냅샷 관리 미흡 |

---

## 📌 참고 사항

### 실제 공격자 우선순위 Top 10 (펜테스트에서 가장 먼저 확인)
1. Public S3 버킷
2. IMDSv1 + 애플리케이션 SSRF
3. 과도한 IAM 권한 (`*` 또는 AdministratorAccess)
4. Public RDS / Public 스냅샷 (EBS, RDS, AMI)
5. Root 계정 Access Key 존재
6. CloudTrail Data Events 미로깅
7. GuardDuty / Security Hub 미활성화
8. 코드·환경변수에 자격증명 하드코딩
9. EKS anonymous access 또는 과도한 RBAC
10. Security Group `0.0.0.0/0` 위험 포트 개방

### 자동화 점검 추천 도구
- **AWS Security Hub + CIS AWS Foundations Benchmark v5.0**
- Prowler (가장 상세)
- ScoutSuite, Steampipe

---

**버전 히스토리**
- v2.1 (2026.06) : 서비스·도메인별 재구조화 + 시각적 가독성 대폭 향상
- v2.0 : 기존 41개 항목 + 19개 신규 고위험 항목 추가

이 버전은 실무 보안 점검, 내부 감사, 고객사 보고서 작성에 바로 활용하기 좋습니다.

필요하면 이 파일을 기반으로 **Excel 버전**이나 특정 카테고리(예: EKS 전용, IAM Privesc 경로 상세)만 따로 추출해 드릴 수 있어요!