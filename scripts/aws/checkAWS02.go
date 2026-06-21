package main

type AWS02Input struct {
	RawData string
}

func checkAWS02(ctx ScanContext) CheckResult {
	const code = "AWS-02"
	const description = "1.2 IAM 사용자 계정 단일화 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS02Input(ctx)

	result := evalAWS02(input)
	result.Code = code
	result.GuideCode = "1.2"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS02Input(ctx ScanContext) (AWS02Input, []string) {
	return AWS02Input{RawData: ctx.Runtime.IAMUsers}, nil
}

func evalAWS02(input AWS02Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.2", "implementation=stub"),
		VulnerableConfig: "",
	}
}
