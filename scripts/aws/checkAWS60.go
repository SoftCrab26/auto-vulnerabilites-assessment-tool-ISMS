package main

type AWS60Input struct {
	RawData string
}

func checkAWS60(ctx ScanContext) CheckResult {
	const code = "AWS-60"
	const description = "예비 점검 항목 AWS-60 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS60Input(ctx)

	result := evalAWS60(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS60Input(ctx ScanContext) (AWS60Input, []string) {
	return AWS60Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS60(input AWS60Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-60", "implementation=stub"),
		VulnerableConfig: "",
	}
}
