package main

func checkAWS04(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-04", "1.4", "IAM 그룹 사용자 계정 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1026"}}

	result := CheckResult{
		Status:           StatusManual,
		RawConfig:        ctx.Runtime.IAMGroups,
		ProcessedConfig:  buildProcessedConfig("implementation=requires_group_membership_review"),
		VulnerableConfig: "각 IAM 그룹의 사용자 목록 검토 필요: 불필요한 계정 존재 여부 확인",
	}
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}
