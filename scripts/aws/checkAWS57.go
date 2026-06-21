package main

type AWS57Input struct {
	RawData string
}

func checkAWS57(ctx ScanContext) CheckResult {
	const code = "AWS-57"
	const description = "예비 점검 항목 AWS-57 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS57Input(ctx)

	result := evalAWS57(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS57Input(ctx ScanContext) (AWS57Input, []string) {
	return AWS57Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS57(input AWS57Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-57", "implementation=stub"),
		VulnerableConfig: "",
	}
}
