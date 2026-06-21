package main

type AWS55Input struct {
	RawData string
}

func checkAWS55(ctx ScanContext) CheckResult {
	const code = "AWS-55"
	const description = "예비 점검 항목 AWS-55 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS55Input(ctx)

	result := evalAWS55(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS55Input(ctx ScanContext) (AWS55Input, []string) {
	return AWS55Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS55(input AWS55Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-55", "implementation=stub"),
		VulnerableConfig: "",
	}
}
