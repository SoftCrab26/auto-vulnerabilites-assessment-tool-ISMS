package main

type AWS46Input struct {
	RawData string
}

func checkAWS46(ctx ScanContext) CheckResult {
	const code = "AWS-46"
	const description = "예비 점검 항목 AWS-46 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS46Input(ctx)

	result := evalAWS46(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS46Input(ctx ScanContext) (AWS46Input, []string) {
	return AWS46Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS46(input AWS46Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-46", "implementation=stub"),
		VulnerableConfig: "",
	}
}
