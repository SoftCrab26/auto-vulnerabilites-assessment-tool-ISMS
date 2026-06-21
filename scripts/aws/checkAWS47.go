package main

type AWS47Input struct {
	RawData string
}

func checkAWS47(ctx ScanContext) CheckResult {
	const code = "AWS-47"
	const description = "예비 점검 항목 AWS-47 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS47Input(ctx)

	result := evalAWS47(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS47Input(ctx ScanContext) (AWS47Input, []string) {
	return AWS47Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS47(input AWS47Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-47", "implementation=stub"),
		VulnerableConfig: "",
	}
}
