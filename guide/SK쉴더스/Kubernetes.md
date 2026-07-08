# Kubernetes 보안 취약점 판단 기준 (K8S-1.1 ~ K8S-8.3) - 풀 텍스트

| 항목분류 | 코드 | 점검항목 제목 | 판단 기준 (양호) | 판단 기준 (취약) |
|----------|------|---------------|------------------|------------------|
| IAM | **K8S-1.1** | system:masters 그룹 사용 제한 | 클러스터 부트스트랩 이후 사용자 또는 컴포넌트 인증에 system:masters 그룹을 사용하지 않고 비상용 break-glass 용도로만 관리하는 경우 | 클러스터 부트스트랩 이후에도 일반 사용자, 관리자, 컴포넌트 인증에 system:masters 그룹을 사용하는 경우 |
| IAM | **K8S-1.2** | kube-controller-manager 서비스 계정 자격 증명 사용 | kube-controller-manager가 --use-service-account-credentials 옵션을 활성화하여 컨트롤러별 서비스 계정 권한으로 동작하는 경우 | kube-controller-manager가 --use-service-account-credentials 옵션 없이 과도한 단일 권한으로 동작하는 경우 |
| IAM | **K8S-1.3** | 루트 인증서 보호 | 루트 인증서가 오프라인 CA로 보호되거나 접근 통제가 적용된 관리형 온라인 CA로 보호되는 경우 | 루트 인증서가 일반 접근 가능하거나 효과적인 접근 통제 없이 운영되는 경우 |
| IAM | **K8S-1.4** | 인증서 만료 기간 관리 | 중간 인증서 및 리프 인증서의 만료일이 발급 시점 기준 3년 이내로 설정되어 있는 경우 | 중간 인증서 또는 리프 인증서의 만료일이 3년을 초과하거나 만료 관리 기준이 없는 경우 |
| IAM | **K8S-1.5** | 접근 권한 정기 검토 | 접근 권한 검토 프로세스가 존재하고 최소 24개월 이내 주기로 검토가 수행되는 경우 | 접근 권한 검토 프로세스가 없거나 24개월을 초과하여 검토가 수행되는 경우 |
| IAM | **K8S-1.6** | RBAC 모범 사례 준수 | 인증 및 인가 관리를 위해 Kubernetes RBAC Good Practices를 준수하고 최소 권한 원칙을 적용하는 경우 | RBAC 권한이 과도하게 부여되어 있거나 Kubernetes RBAC Good Practices를 준수하지 않는 경우 |
| Network | **K8S-2.1** | NetworkPolicy 지원 CNI 사용 | 사용 중인 CNI 플러그인이 Kubernetes NetworkPolicy를 지원하는 경우 | 사용 중인 CNI 플러그인이 NetworkPolicy를 지원하지 않거나 정책 적용 기능이 비활성화된 경우 |
| Network | **K8S-2.2** | 워크로드 인그레스/이그레스 정책 적용 | 클러스터 내 모든 워크로드에 필요한 인그레스 및 이그레스 NetworkPolicy가 적용되어 있는 경우 | 워크로드에 인그레스 또는 이그레스 NetworkPolicy가 적용되어 있지 않아 통신이 과도하게 허용되는 경우 |
| Network | **K8S-2.3** | 네임스페이스 기본 차단 정책 적용 | 각 네임스페이스에 모든 Pod를 대상으로 기본 인그레스/이그레스 차단 정책이 적용되어 allow list 방식으로 통신을 허용하는 경우 | 네임스페이스 기본 차단 정책이 없어 별도 정책이 없는 Pod의 통신이 기본 허용되는 경우 |
| Network | **K8S-2.4** | 클러스터 내부 통신 암호화 | 필요 시 서비스 메시 또는 CNI 암호화 기능 등을 통해 클러스터 내부 통신이 암호화되어 있는 경우 | 민감한 내부 통신이 평문으로 전송되거나 통신 암호화 대책이 적용되어 있지 않은 경우 |
| Network | **K8S-2.5** | Kubernetes API, kubelet API, etcd 외부 노출 제한 | Kubernetes API, kubelet API, etcd가 인터넷에 공개되지 않고 허용된 관리 경로에서만 접근 가능한 경우 | Kubernetes API, kubelet API, etcd가 인터넷에 공개되어 있거나 접근 제한 없이 노출된 경우 |
| Network | **K8S-2.6** | 클라우드 메타데이터 API 접근 제한 | Pod에서 클라우드 메타데이터 API(169.254.169.254 등)로의 접근이 필요 최소한으로 필터링 또는 차단되어 있는 경우 | Pod가 클라우드 메타데이터 API에 제한 없이 접근할 수 있는 경우 |
| Network | **K8S-2.7** | LoadBalancer 및 ExternalIPs 사용 제한 | LoadBalancer 및 Service ExternalIPs 사용이 승인된 서비스로 제한되고 관련 admission 정책이 적용되어 있는 경우 | LoadBalancer 또는 ExternalIPs를 임의로 사용할 수 있어 중간자 공격 등 네트워크 우회 위험이 존재하는 경우 |
| Pod | **K8S-3.1** | 워크로드 변경 RBAC 권한 제한 | workloads 리소스의 create, update, patch, delete 권한이 업무상 필요한 주체에게만 부여되어 있는 경우 | workloads 리소스 변경 권한이 불필요한 사용자 또는 서비스 계정에 부여되어 있는 경우 |
| Pod | **K8S-3.2** | Pod Security Standards 적용 | 모든 네임스페이스에 적절한 Pod Security Standards 정책이 적용되고 enforce 모드 등으로 강제되는 경우 | 네임스페이스에 Pod Security Standards 정책이 없거나 privileged 수준으로 과도하게 허용되는 경우 |
| Pod | **K8S-3.3** | 메모리 리소스 제한 설정 | 워크로드에 메모리 request 및 limit이 설정되어 있고 limit이 request와 같거나 더 낮은 기준으로 관리되는 경우 | 워크로드에 메모리 limit이 없거나 request보다 과도하게 높아 노드 OOM 위험이 존재하는 경우 |
| Pod | **K8S-3.4** | 민감 워크로드 CPU 제한 설정 | 민감한 워크로드에 CPU limit이 업무 특성에 맞게 설정되어 리소스 남용을 방지하는 경우 | 민감한 워크로드에 CPU limit이 없거나 리소스 사용량 제한 기준이 없는 경우 |
| Pod | **K8S-3.5** | Seccomp 프로파일 적용 | Linux 노드 등 지원 가능한 환경에서 RuntimeDefault 또는 적절한 Seccomp 프로파일이 Pod/컨테이너에 적용되어 있는 경우 | Seccomp가 비활성화되어 있거나 Pod/컨테이너가 unconfined 상태로 실행되는 경우 |
| Pod | **K8S-3.6** | AppArmor 또는 SELinux 프로파일 적용 | 지원 가능한 노드에서 AppArmor 또는 SELinux 프로파일이 워크로드 특성에 맞게 적용되어 있는 경우 | AppArmor 또는 SELinux가 적용되지 않거나 프로파일 없이 컨테이너가 실행되는 경우 |
| Logs and auditing | **K8S-4.1** | 감사 로그 접근 보호 | 감사 로그가 활성화된 경우 일반 사용자 접근으로부터 보호되고 무결성 및 보관 기준에 따라 관리되는 경우 | 감사 로그가 일반 사용자에게 노출되거나 접근 통제 없이 변경 또는 삭제 가능한 경우 |
| Pod placement | **K8S-5.1** | 민감도 기반 Pod 배치 | 애플리케이션 민감도 등급에 따라 Pod가 적절한 노드 또는 격리 영역에 배치되도록 정책이 적용되어 있는 경우 | 민감도가 다른 워크로드가 동일 노드에 무분별하게 배치되어 격리 기준이 없는 경우 |
| Pod placement | **K8S-5.2** | 민감 애플리케이션 노드 격리 및 샌드박스 런타임 사용 | 민감 애플리케이션이 전용 노드, 노드 셀렉터, taint/toleration, RuntimeClass 등으로 격리되어 실행되는 경우 | 민감 애플리케이션이 일반 워크로드와 동일 노드에서 실행되며 별도 격리 또는 샌드박스 런타임이 적용되지 않은 경우 |
| Secrets | **K8S-6.1** | ConfigMap 내 기밀정보 저장 금지 | 기밀정보가 ConfigMap에 저장되지 않고 Kubernetes Secret 또는 승인된 외부 Secret 저장소를 사용하는 경우 | 비밀번호, 토큰, 키 등 기밀정보가 ConfigMap에 저장되어 있는 경우 |
| Secrets | **K8S-6.2** | Secret API 저장 데이터 암호화 | Secret 리소스가 etcd에 저장될 때 encryption at rest 설정을 통해 암호화되는 경우 | Secret 리소스가 etcd에 평문으로 저장되거나 저장 데이터 암호화가 설정되어 있지 않은 경우 |
| Secrets | **K8S-6.3** | 외부 Secret 주입 메커니즘 사용 | 필요 시 Secrets Store CSI Driver 등 승인된 메커니즘으로 외부 Secret 저장소의 기밀정보를 안전하게 주입하는 경우 | 외부 Secret을 직접 환경변수, ConfigMap, 이미지 등에 저장하거나 안전한 주입 메커니즘이 없는 경우 |
| Secrets | **K8S-6.4** | 불필요한 서비스 계정 토큰 자동 마운트 제한 | 서비스 계정 토큰이 필요하지 않은 Pod에는 automountServiceAccountToken=false가 적용되어 있는 경우 | 서비스 계정 토큰이 필요하지 않은 Pod에도 토큰이 자동 마운트되는 경우 |
| Secrets | **K8S-6.5** | Bound Service Account Token 사용 | Kubernetes v1.22 이상에서 만료되지 않는 토큰 대신 Bound Service Account Token Volume 등 시간 제한 토큰을 사용하는 경우 | 장기 또는 무기한 서비스 계정 토큰을 계속 사용하거나 토큰 만료 및 회전 기준이 없는 경우 |
| Images | **K8S-7.1** | 컨테이너 이미지 최소화 | 운영 이미지에 애플리케이션 실행에 필요한 최소 구성만 포함하고 불필요한 쉘, 디버깅 도구, 패키지를 제거한 경우 | 운영 이미지에 불필요한 도구, 패키지, 쉘 등이 포함되어 공격 표면이 증가한 경우 |
| Images | **K8S-7.2** | 비권한 사용자로 컨테이너 실행 | 컨테이너 이미지 또는 SecurityContext가 비권한 사용자로 실행되도록 설정되어 있는 경우 | 컨테이너가 root 또는 과도한 권한 사용자로 실행되는 경우 |
| Images | **K8S-7.3** | 이미지 digest 또는 서명 검증 사용 | 이미지가 sha256 digest로 참조되거나 배포 시 디지털 서명 검증을 통해 출처와 무결성을 확인하는 경우 | latest 등 변경 가능한 태그만 사용하고 이미지 서명 또는 무결성 검증이 없는 경우 |
| Images | **K8S-7.4** | 이미지 취약점 스캔 및 패치 | 이미지 생성 및 배포 과정에서 정기적으로 취약점 스캔을 수행하고 알려진 취약점이 패치된 이미지만 배포하는 경우 | 이미지 취약점 스캔이 수행되지 않거나 알려진 취약점이 포함된 이미지가 배포되는 경우 |
| Admission controllers | **K8S-8.1** | 적절한 Admission Controller 활성화 | 보안 요구사항에 맞는 admission controller가 활성화되어 있고 기본 보안 admission plugin을 유지하는 경우 | 필요한 admission controller가 비활성화되어 있거나 보안 정책을 API 요청 단계에서 검증하지 않는 경우 |
| Admission controllers | **K8S-8.2** | Pod 보안 정책 Admission 강제 | Pod Security Admission 또는 검증/변경 admission webhook을 통해 Pod 보안 정책이 강제되는 경우 | Pod 보안 정책이 admission 단계에서 강제되지 않아 부적절한 PodSpec 배포가 가능한 경우 |
| Admission controllers | **K8S-8.3** | Admission chain 및 webhook 보안 설정 | admission plugin 및 webhook이 TLS, 인증, 권한, 실패 정책 등 보안 기준에 따라 안전하게 구성되어 있는 경우 | admission webhook이 인증 없이 호출되거나 실패 정책, TLS, 권한 설정이 부적절하여 우회 또는 장애 위험이 있는 경우 |

*(Kubernetes 공식 Security Checklist 기준으로 IAM(1.1~1.6), Network(2.1~2.7), Pod(3.1~3.6), Logs and auditing(4.1), Pod placement(5.1~5.2), Secrets(6.1~6.5), Images(7.1~7.4), Admission controllers(8.1~8.3) 총 34개 항목 추출 완료. 출처: https://kubernetes.io/docs/concepts/security/security-checklist/)*
