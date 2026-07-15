package main

type W04Input struct {
	PasswordPolicy string
}

func checkW04(ctx ScanContext) CheckResult {
	const code = "W-04"
	const description = "Password length, complexity, and maximum age policies should be configured."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1110"},
		mitigations: []string{"M1027", "M1036"},
	}
	input, errs := loadW04Input(ctx)
	result := evalW04(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW04Input(ctx ScanContext) (W04Input, []string) {
	results, errs := collectCommands(`$p=Join-Path $env:TEMP "w04-security.cfg"; secedit /export /cfg $p /areas SECURITYPOLICY | Out-Null; foreach($name in @('MinimumPasswordLength','PasswordComplexity','MaximumPasswordAge')){$line=Select-String -Path $p -Pattern ("^\s*"+$name+"\s*=") | Select-Object -First 1; if($line){$line.Line.Trim()}else{"$name=NOT_FOUND"}}; Remove-Item $p -Force -ErrorAction SilentlyContinue`)
	return W04Input{PasswordPolicy: firstCommandOutput(results)}, errs
}

func evalW04(input W04Input) CheckResult {
	minLength := findConfigValue(input.PasswordPolicy, "MinimumPasswordLength")
	complexity := findConfigValue(input.PasswordPolicy, "PasswordComplexity")
	maxAge := findConfigValue(input.PasswordPolicy, "MaximumPasswordAge")
	status := StatusGood
	vulnerable := ""
	if safeAtoi(minLength) <= 0 || safeAtoi(complexity) != 1 || safeAtoi(maxAge) <= 0 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(
			"MinimumPasswordLength="+minLength,
			"PasswordComplexity="+complexity,
			"MaximumPasswordAge="+maxAge,
			"Password length, complexity, and expiration must all be configured.",
		)
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.PasswordPolicy,
		ProcessedConfig:  buildProcessedConfig("MinimumPasswordLength="+minLength, "PasswordComplexity="+complexity, "MaximumPasswordAge="+maxAge),
		VulnerableConfig: vulnerable,
	}
}
