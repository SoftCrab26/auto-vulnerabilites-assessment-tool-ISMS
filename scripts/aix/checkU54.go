package main

type U54Input struct {
	FTP Service
}

func checkU54(ctx ScanContext) CheckResult {
	input, errs := loadU54Input(ctx)
	result := evalU54(input)
	result.Code = "U-54"
	result.Description = "Unencrypted FTP service should be disabled."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU54Input(ctx ScanContext) (U54Input, []string) {
	return U54Input{FTP: ctx.Services["ftp"]}, nil
}

func evalU54(input U54Input) CheckResult {
	active := input.FTP.IsActive()
	result := CheckResult{Status: StatusGood, RawConfig: formatServiceStatus(input.FTP), ProcessedConfig: "ftp_active=" + boolString(active)}
	if active {
		result.Status = StatusVulnerable
		result.VulnerableConfig = "Cleartext FTP is active."
	}
	return result
}
