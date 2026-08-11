package main

type U54Input struct {
	FTP Service
}

func checkU54(ctx ScanContext) CheckResult {
	const code = "U-54"
	const description = "Unencrypted FTP service should be disabled."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU54Input(ctx)

	result := evalU54(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU54Input(ctx ScanContext) (U54Input, []string) {
	return U54Input{FTP: ctx.Services["ftp"]}, nil
}

func evalU54(input U54Input) CheckResult {
	ftp := input.FTP
	status := StatusGood
	vulnerableConfig := ""

	if ftp.IsActive() {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(ftp),
			"문제점1. 암호화되지 않은 FTP 서비스가 활성화되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        formatServiceStatus(ftp),
		ProcessedConfig:  buildProcessedConfig("ftp_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
