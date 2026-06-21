package main

type AWS08Input struct {
	RawData string
}

func checkAWS08(ctx ScanContext) CheckResult {
	const code = "AWS-08"
	const description = "1.8 Admin Console 계정 Access Key 활성화 및 사용주기 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS08Input(ctx)

	result := evalAWS08(input)
	result.Code = code
	result.GuideCode = "1.8"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS08Input(ctx ScanContext) (AWS08Input, []string) {
	return AWS08Input{RawData: ctx.Runtime.CredentialReport}, nil
}

func evalAWS08(input AWS08Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=1.8", "implementation=stub"),
		VulnerableConfig: "",
	}
}
