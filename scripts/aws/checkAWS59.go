package main

type AWS59Input struct {
	RawData string
}

func checkAWS59(ctx ScanContext) CheckResult {
	const code = "AWS-59"
	const description = "예비 점검 항목 AWS-59 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS59Input(ctx)

	result := evalAWS59(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS59Input(ctx ScanContext) (AWS59Input, []string) {
	return AWS59Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS59(input AWS59Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-59", "implementation=stub"),
		VulnerableConfig: "",
	}
}
