package main

import (
	"strconv"
	"strings"
)

type W33Input struct {
	MaximumKilobytes int
	Found            bool
	Raw              string
}

func checkW33(ctx ScanContext) CheckResult {
	const code = "W-33"
	const description = "The Security event log maximum size should be sufficiently configured."
	mitreAttack := MitreAttack{tactic: "Defense Evasion", techniques: []string{"T1070.001"}, mitigations: []string{"M1047"}}

	input, errs := loadW33Input()
	result := evalW33(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW33Input() (W33Input, []string) {
	command := `$log=Get-WinEvent -ListLog Security; Write-Output ('MAXIMUM_KB=' + [string]([math]::Floor($log.MaximumSizeInBytes/1KB))); Write-Output ('LOG_MODE=' + [string]$log.LogMode); Write-Output ('IS_ENABLED=' + [string]$log.IsEnabled)`
	results, errs := collectCommands(command)
	raw := firstCommandOutput(results)
	value := findConfigValue(raw, "MAXIMUM_KB")
	size, err := strconv.Atoi(strings.TrimSpace(value))
	return W33Input{MaximumKilobytes: size, Found: err == nil, Raw: raw}, errs
}

func evalW33(input W33Input) CheckResult {
	status := StatusInterview
	vulnerable := ""
	if !input.Found || input.MaximumKilobytes <= 0 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("security_log_maximum_kb="+strconv.Itoa(input.MaximumKilobytes), "Security log maximum size is zero or missing.")
	}
	return CheckResult{Status: status, RawConfig: input.Raw, ProcessedConfig: "security_log_maximum_kb=" + strconv.Itoa(input.MaximumKilobytes), VulnerableConfig: vulnerable}
}
