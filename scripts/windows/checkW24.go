package main

import "strings"

type W24Input struct {
	RawConfig string
}

func checkW24(ctx ScanContext) CheckResult {
	const code = "W-24"
	const description = "The built-in Guest account should be disabled."
	mitreAttack := MitreAttack{
		tactic:      "Persistence",
		techniques:  []string{"T1136.001"},
		mitigations: []string{"M1018"},
	}

	input, errs := loadW24Input(ctx)
	result := evalW24(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW24Input(ctx ScanContext) (W24Input, []string) {
	commands, errs := collectCommands(`$u=Get-CimInstance Win32_UserAccount -ErrorAction SilentlyContinue | Where-Object {$_.LocalAccount -and $_.SID -match '-501$'} | Select-Object -First 1; if($null -eq $u){"EXISTS=false"}else{"EXISTS=true";"NAME=$($u.Name)";"ENABLED=$(-not [bool]$u.Disabled)"}`)
	return W24Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW24(input W24Input) CheckResult {
	exists := strings.ToLower(findConfigValue(input.RawConfig, "EXISTS"))
	enabled := strings.ToLower(findConfigValue(input.RawConfig, "ENABLED"))
	status := StatusManual
	vulnerable := ""
	if exists == "true" && enabled == "false" {
		status = StatusGood
	} else if exists == "true" && enabled == "true" {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("guest_enabled=true", "The built-in Guest account is enabled.")
	} else if exists == "false" {
		status = StatusNotApplicable
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("guest_exists="+exists, "guest_enabled="+enabled),
		VulnerableConfig: vulnerable,
	}
}
