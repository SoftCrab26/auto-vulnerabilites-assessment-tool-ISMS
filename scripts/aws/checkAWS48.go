package main

type AWS48Input struct {
	RawData string
}

func checkAWS48(ctx ScanContext) CheckResult {
	const code = "AWS-48"
	const description = "예비 점검 항목 AWS-48 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS48Input(ctx)

	result := evalAWS48(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS48Input(ctx ScanContext) (AWS48Input, []string) {
	return AWS48Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS48(input AWS48Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-48", "implementation=stub"),
		VulnerableConfig: "",
	}
}
