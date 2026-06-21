package main

type AWS17Input struct {
	RawData string
}

func checkAWS17(ctx ScanContext) CheckResult {
	const code = "AWS-17"
	const description = "3.1 보안 그룹 인/아웃바운드 ANY 설정 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS17Input(ctx)

	result := evalAWS17(input)
	result.Code = code
	result.GuideCode = "3.1"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS17Input(ctx ScanContext) (AWS17Input, []string) {
	return AWS17Input{RawData: ctx.Runtime.SecurityGroups}, nil
}

func evalAWS17(input AWS17Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.1", "implementation=stub"),
		VulnerableConfig: "",
	}
}
