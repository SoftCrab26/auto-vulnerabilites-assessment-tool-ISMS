package main

type U58Input struct {
	SNMP Service
}

func checkU58(ctx ScanContext) CheckResult {
	const code = "U-58"
	const description = "SNMP service should not be running if it is not required."
	mitre := MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}

	input, errs := loadU58Input(ctx)
	result := evalU58(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU58Input(ctx ScanContext) (U58Input, []string) {
	return U58Input{SNMP: ctx.Services["snmp"]}, nil
}

func evalU58(input U58Input) CheckResult {
	active := input.SNMP.IsActive()
	result := CheckResult{
		Status:          StatusGood,
		RawConfig:       formatServiceStatus(input.SNMP),
		ProcessedConfig: buildProcessedConfig("snmp_active=", u58BoolText(active)),
	}
	if active {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "SNMP service is active; disable it when it is not required."
	}
	return result
}

func u58BoolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
