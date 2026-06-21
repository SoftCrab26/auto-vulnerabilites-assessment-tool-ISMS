package main

type AWS45Input struct {
	RawData string
}

func checkAWS45(ctx ScanContext) CheckResult {
	const code = "AWS-45"
	const description = "예비 점검 항목 AWS-45 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS45Input(ctx)

	result := evalAWS45(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS45Input(ctx ScanContext) (AWS45Input, []string) {
	return AWS45Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS45(input AWS45Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-45", "implementation=stub"),
		VulnerableConfig: "",
	}
}
