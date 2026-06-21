package main

type AWS10Input struct {
	RawData string
}

func checkAWS10(ctx ScanContext) CheckResult {
	const code = "AWS-10"
	const description = "1.10 AWS 계정 패스워드 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS10Input(ctx)

	result := evalAWS10(input)
	result.Code = code
	result.GuideCode = "1.10"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS10Input(ctx ScanContext) (AWS10Input, []string) {
	return AWS10Input{RawData: ctx.Runtime.PasswordPolicy}, nil
}

func evalAWS10(input AWS10Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.10", "implementation=stub"),
		VulnerableConfig: "",
	}
}
