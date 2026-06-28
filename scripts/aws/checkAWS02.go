package main

func checkAWS02(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-02", "1.2", "IAM 사용자 계정 단일화 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078"}, mitigations: []string{"M1026"}}

	result := CheckResult{
		Status:           StatusManual,
		RawConfig:        ctx.Runtime.IAMUsers,
		ProcessedConfig:  buildProcessedConfig("implementation=requires_activity_analysis"),
		VulnerableConfig: "각 사용자 활동 이력 확인 필요: ConsoleLogin 및 AccessKey 활동 기록 분석",
	}
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}
