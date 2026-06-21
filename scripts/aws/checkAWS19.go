package main

type AWS19Input struct {
	RawData string
}

func checkAWS19(ctx ScanContext) CheckResult {
	const code = "AWS-19"
	const description = "3.3 네트워크 ACL 인/아웃바운드 트래픽 정책 관리"
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadAWS19Input(ctx)

	result := evalAWS19(input)
	result.Code = code
	result.GuideCode = "3.3"
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadAWS19Input(ctx ScanContext) (AWS19Input, []string) {
	return AWS19Input{RawData: ctx.Runtime.NetworkACLs}, nil
}

func evalAWS19(input AWS19Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RawData,
		ProcessedConfig:  buildProcessedConfig("guide=3.3", "implementation=stub"),
		VulnerableConfig: "",
	}
}
