package main

type AWS53Input struct {
	RawData string
}

func checkAWS53(ctx ScanContext) CheckResult {
	const code = "AWS-53"
	const description = "예비 점검 항목 AWS-53 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS53Input(ctx)

	result := evalAWS53(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS53Input(ctx ScanContext) (AWS53Input, []string) {
	return AWS53Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS53(input AWS53Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-53", "implementation=stub"),
		VulnerableConfig: "",
	}
}
