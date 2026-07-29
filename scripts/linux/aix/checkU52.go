package main

type U52Input struct {
	Telnet Service
}

func checkU52(ctx ScanContext) CheckResult {
	input, errs := loadU52Input(ctx)
	result := evalU52(input)
	result.Code = "U-52"
	result.Description = "Telnet service should be disabled."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU52Input(ctx ScanContext) (U52Input, []string) {
	return U52Input{Telnet: ctx.Services["telnet"]}, nil
}

func evalU52(input U52Input) CheckResult {
	active := input.Telnet.IsActive()
	result := CheckResult{Status: StatusGood, RawConfig: formatServiceStatus(input.Telnet), ProcessedConfig: "telnet_active=" + boolString(active)}
	if active {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "Telnet is active; use SSH instead."
	}
	return result
}
