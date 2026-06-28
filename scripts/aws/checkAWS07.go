package main

func checkAWS07(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-07", "1.7", "Admin Console 관리자 정책 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1026"}}

	result := CheckResult{
		Status:           StatusManual,
		RawConfig:        ctx.Runtime.IAMUsers,
		ProcessedConfig:  buildProcessedConfig("implementation=requires_admin_activity_review"),
		VulnerableConfig: "Root/Admin 계정의 최근 활동 및 로그인 이력 검토 필요",
	}
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}
