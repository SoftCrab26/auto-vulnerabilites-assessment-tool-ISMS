package main

type W03Input struct {
	LockoutConfig string
}

func checkW03(ctx ScanContext) CheckResult {
	const code = "W-03"
	const description = "The account lockout threshold should be configured to 10 or fewer failed attempts."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1110"},
		mitigations: []string{"M1036"},
	}
	input, errs := loadW03Input(ctx)
	result := evalW03(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW03Input(ctx ScanContext) (W03Input, []string) {
	results, errs := collectCommands(`$p=Join-Path $env:TEMP "w03-security.cfg"; secedit /export /cfg $p /areas SECURITYPOLICY | Out-Null; $line=Select-String -Path $p -Pattern '^\s*LockoutBadCount\s*=' | Select-Object -First 1; if($line){$line.Line.Trim()}else{"LockoutBadCount=NOT_FOUND"}; Remove-Item $p -Force -ErrorAction SilentlyContinue`)
	return W03Input{LockoutConfig: firstCommandOutput(results)}, errs
}

func evalW03(input W03Input) CheckResult {
	value := findConfigValue(input.LockoutConfig, "LockoutBadCount")
	threshold := safeAtoi(value)
	status := StatusGood
	vulnerable := ""
	if value == "NOT_FOUND" || threshold <= 0 || threshold > 10 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(
			"LockoutBadCount="+value,
			"The account lockout threshold is missing, disabled, or greater than 10.",
		)
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.LockoutConfig,
		ProcessedConfig:  "LockoutBadCount=" + value,
		VulnerableConfig: vulnerable,
	}
}
