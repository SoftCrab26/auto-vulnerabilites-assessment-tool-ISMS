package main

type AWS20Input struct {
	RawData string
}

func checkAWS20(ctx ScanContext) CheckResult {
	const code = "AWS-20"
	const description = "3.4 라우팅 테이블 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS20Input(ctx)

	result := evalAWS20(input)
	result.Code = code
	result.GuideCode = "3.4"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS20Input(ctx ScanContext) (AWS20Input, []string) {
	return AWS20Input{RawData: ctx.Runtime.RouteTables}, nil
}

func evalAWS20(input AWS20Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.4", "implementation=stub"),
		VulnerableConfig: "",
	}
}
