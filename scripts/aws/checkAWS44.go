package main

type AWS44Input struct {
	RawData string
}

func checkAWS44(ctx ScanContext) CheckResult {
	const code = "AWS-44"
	const description = "예비 점검 항목 AWS-44 (가이드 미정의)"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS44Input(ctx)

	result := evalAWS44(input)
	result.Code = code
	result.GuideCode = ""
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS44Input(ctx ScanContext) (AWS44Input, []string) {
	return AWS44Input{RawData: ctx.Runtime.CallerIdentity}, nil
}

func evalAWS44(input AWS44Input) CheckResult {
	return CheckResult{
		Status:           StatusNotApplicable,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=reserved", "item=AWS-44", "implementation=stub"),
		VulnerableConfig: "",
	}
}
