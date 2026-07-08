package main

func checkAWS05(ctx ScanContext) CheckResult {
	const code, guideCode, description = "AWS-05", "1.5", "Key Pair 접근 관리"
	mitre := MitreAttack{tactic: "Initial Access", techniques: []string{"T1078.004"}, mitigations: []string{"M1040"}}

	result := CheckResult{
		Status:           StatusManual,
		RawConfig:        ctx.Runtime.KeyPairs,
		ProcessedConfig:  buildProcessedConfig("implementation=requires_ec2_ssh_config_review"),
		VulnerableConfig: "EC2 인스턴스 SSH 설정 검토 필요: Key Pair 사용 여부 vs 패스워드 로그인 확인",
	}
	return checkAWSGeneric(code, guideCode, description, mitre, result)
}
