package main

func checkAWS13(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-13", "1.13", "EKS 불필요한 익명 접근 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1026"}}

	result := evalEKS(ctx.Runtime.EKSClusters, "ClusterRoleBinding 설정 검토 필요\nsystem:anonymous, unauthenticated 그룹 바인딩 여부 확인\n명령어: kubectl get clusterrolebinding -o yaml | grep -E 'system:anonymous|unauthenticated'")
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}
