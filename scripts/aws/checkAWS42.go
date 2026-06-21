package main

type AWS42Input struct {
	RawData string
}

func checkAWS42(ctx ScanContext) CheckResult {
	const code = "AWS-42"
	const description = "예비 점검 항목 AWS-42 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS42Input(ctx)

	result := evalAWS42(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS42Input(ctx ScanContext) (AWS42Input, []string) {
	return AWS42Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS42(input AWS42Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-42", "implementation=stub"),
		VulnerableConfig: "",
	}
}
