package main

type AWS18Input struct {
	RawData string
}

func checkAWS18(ctx ScanContext) CheckResult {
	const code = "AWS-18"
	const description = "3.2 보안 그룹 인/아웃바운드 불필요 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS18Input(ctx)

	result := evalAWS18(input)
	result.Code = code
	result.GuideCode = "3.2"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS18Input(ctx ScanContext) (AWS18Input, []string) {
	return AWS18Input{RawData: ctx.Runtime.SecurityGroups}, nil
}

func evalAWS18(input AWS18Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.2", "implementation=stub"),
		VulnerableConfig: "",
	}
}
