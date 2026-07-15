package main

import "strings"

type W25Input struct {
	RawConfig string
}

func checkW25(ctx ScanContext) CheckResult {
	const code = "W-25"
	const description = "The effective PowerShell execution policy should be restricted."
	mitreAttack := MitreAttack{
		tactic:      "Execution",
		techniques:  []string{"T1059.001"},
		mitigations: []string{"M1042"},
	}

	input, errs := loadW25Input(ctx)
	result := evalW25(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW25Input(ctx ScanContext) (W25Input, []string) {
	commands, errs := collectCommands(`$p=Get-ExecutionPolicy -ErrorAction SilentlyContinue; "EXECUTION_POLICY=$(if([string]::IsNullOrWhiteSpace([string]$p)){'Undefined'}else{$p})"`)
	return W25Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW25(input W25Input) CheckResult {
	policy := strings.ToLower(findConfigValue(input.RawConfig, "EXECUTION_POLICY"))
	status := StatusManual
	vulnerable := ""
	switch policy {
	case "restricted", "allsigned", "remotesigned":
		status = StatusGood
	case "unrestricted", "bypass", "undefined":
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("execution_policy="+policy, "The effective PowerShell execution policy is not restricted.")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("execution_policy=" + policy),
		VulnerableConfig: vulnerable,
	}
}
