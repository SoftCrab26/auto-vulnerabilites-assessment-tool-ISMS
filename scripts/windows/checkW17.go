package main

import "strings"

type W17Input struct {
	RawConfig string
}

func checkW17(ctx ScanContext) CheckResult {
	const code = "W-17"
	const description = "Windows automatic updates should be enabled."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1190"},
		mitigations: []string{"M1051"},
	}

	input, errs := loadW17Input(ctx)
	result := evalW17(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW17Input(ctx ScanContext) (W17Input, []string) {
	commands, errs := collectCommands(`$au=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue; $s=Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue; "NO_AUTO_UPDATE=$(if($null -eq $au.NoAutoUpdate){'NOT_FOUND'}else{$au.NoAutoUpdate})"; "AU_OPTIONS=$(if($null -eq $au.AUOptions){'NOT_FOUND'}else{$au.AUOptions})"; "SERVICE_EXISTS=$($null -ne $s)"; if($null -ne $s){"SERVICE_STATE=$($s.State)";"SERVICE_START_MODE=$($s.StartMode)"}`)
	return W17Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW17(input W17Input) CheckResult {
	noAuto := strings.ToLower(findConfigValue(input.RawConfig, "NO_AUTO_UPDATE"))
	options := findConfigValue(input.RawConfig, "AU_OPTIONS")
	exists := strings.ToLower(findConfigValue(input.RawConfig, "SERVICE_EXISTS"))
	startMode := strings.ToLower(findConfigValue(input.RawConfig, "SERVICE_START_MODE"))
	status := StatusManual
	vulnerable := ""

	if noAuto == "1" || exists == "false" || startMode == "disabled" {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("NoAutoUpdate="+noAuto+" AUOptions="+options+" service_start_mode="+startMode, "Automatic updates are explicitly disabled or unavailable.")
	} else if noAuto == "0" && startMode != "disabled" {
		switch options {
		case "2", "3", "4", "5":
			status = StatusGood
		}
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("no_auto_update="+noAuto, "au_options="+options, "service_start_mode="+startMode),
		VulnerableConfig: vulnerable,
	}
}
