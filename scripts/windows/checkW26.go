package main

import "strings"

type W26Input struct {
	RawConfig string
}

func checkW26(ctx ScanContext) CheckResult {
	const code = "W-26"
	const description = "Microsoft Defender real-time protection should be enabled."
	mitreAttack := MitreAttack{
		tactic:      "Defense Evasion",
		techniques:  []string{"T1562.001"},
		mitigations: []string{"M1049"},
	}

	input, errs := loadW26Input(ctx)
	result := evalW26(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW26Input(ctx ScanContext) (W26Input, []string) {
	commands, errs := collectCommands(`$s=Get-MpComputerStatus -ErrorAction SilentlyContinue; if($null -eq $s){"DEFENDER_STATUS=NOT_FOUND"}else{"REAL_TIME_PROTECTION=$($s.RealTimeProtectionEnabled)";"ANTIVIRUS_ENABLED=$($s.AntivirusEnabled)"}`)
	return W26Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW26(input W26Input) CheckResult {
	realTime := strings.ToLower(findConfigValue(input.RawConfig, "REAL_TIME_PROTECTION"))
	status := StatusManual
	vulnerable := ""
	if realTime == "true" {
		status = StatusGood
	} else if realTime == "false" {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("real_time_protection=false", "Microsoft Defender real-time protection is disabled.")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("defender_real_time_protection=" + realTime),
		VulnerableConfig: vulnerable,
	}
}
