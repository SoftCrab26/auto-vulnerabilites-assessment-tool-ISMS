package main

type AWS58Input struct {
	RawData string
}

func checkAWS58(ctx ScanContext) CheckResult {
	const code = "AWS-58"
	const description = "예비 점검 항목 AWS-58 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS58Input(ctx)

	result := evalAWS58(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS58Input(ctx ScanContext) (AWS58Input, []string) {
	return AWS58Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS58(input AWS58Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-58", "implementation=stub"),
		VulnerableConfig: "",
	}
}
