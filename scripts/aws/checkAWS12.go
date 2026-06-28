package main

func checkAWS12(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-12", "1.12", "EKS 서비스 어카운트 관리"
	mitre := MitreAttack{tactic: "Credential Access", techniques: []string{"T1555"}, mitigations: []string{"M1015"}}

	result := evalEKS(ctx.Runtime.EKSClusters, "서비스 어카운트 설정 검토 필요\nautomountServiceAccountToken 값이 False로 설정되어 있는지 확인\n명령어: kubectl get serviceaccount -A -o yaml | grep automountServiceAccountToken")
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}
