package main

type W21Input struct {
	ServiceActive bool
	ServiceStatus string
}

func checkW21(ctx ScanContext) CheckResult {
	const code = "W-21"
	const description = "Active SMTP services should restrict relay and require appropriate authentication."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1190"},
		mitigations: []string{"M1037"},
	}

	input, errs := loadW21Input(ctx)
	result := evalW21(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW21Input(ctx ScanContext) (W21Input, []string) {
	service := ctx.Services["smtp"]
	return W21Input{ServiceActive: service.IsActive(), ServiceStatus: formatServiceStatus(service)}, nil
}

func evalW21(input W21Input) CheckResult {
	if !input.ServiceActive {
		return CheckResult{
			Status:          StatusNotApplicable,
			RawConfig:       input.ServiceStatus,
			ProcessedConfig: buildProcessedConfig("smtp=inactive"),
		}
	}
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       input.ServiceStatus,
		ProcessedConfig: buildProcessedConfig("smtp=active", "relay_and_authentication=interview_required"),
	}
}
