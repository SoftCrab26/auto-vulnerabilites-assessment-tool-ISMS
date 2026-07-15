package main

type W20Input struct {
	ServiceActive bool
	ServiceStatus string
}

func checkW20(ctx ScanContext) CheckResult {
	const code = "W-20"
	const description = "The Telnet service should be inactive."
	mitreAttack := MitreAttack{
		tactic:      "Lateral Movement",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1042"},
	}

	input, errs := loadW20Input(ctx)
	result := evalW20(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW20Input(ctx ScanContext) (W20Input, []string) {
	service := ctx.Services["telnet"]
	return W20Input{ServiceActive: service.IsActive(), ServiceStatus: formatServiceStatus(service)}, nil
}

func evalW20(input W20Input) CheckResult {
	status := StatusGood
	vulnerable := ""
	if input.ServiceActive {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(input.ServiceStatus, "Telnet is active.")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.ServiceStatus,
		ProcessedConfig:  buildProcessedConfig("telnet_active=" + boolTextW20(input.ServiceActive)),
		VulnerableConfig: vulnerable,
	}
}

func boolTextW20(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
