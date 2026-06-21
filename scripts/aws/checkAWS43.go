package main

type AWS43Input struct {
	RawData string
}

func checkAWS43(ctx ScanContext) CheckResult {
	const code = "AWS-43"
	const description = "예비 점검 항목 AWS-43 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS43Input(ctx)

	result := evalAWS43(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS43Input(ctx ScanContext) (AWS43Input, []string) {
	return AWS43Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS43(input AWS43Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-43", "implementation=stub"),
		VulnerableConfig: "",
	}
}
