package main

import "strings"

type W16Input struct {
	RawConfig string
}

func checkW16(ctx ScanContext) CheckResult {
	const code = "W-16"
	const description = "Remote Registry access should be restricted by stopping and disabling the service."
	mitreAttack := MitreAttack{
		tactic:      "Discovery",
		techniques:  []string{"T1012"},
		mitigations: []string{"M1042"},
	}

	input, errs := loadW16Input(ctx)
	result := evalW16(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW16Input(ctx ScanContext) (W16Input, []string) {
	commands, errs := collectCommands(`$s=Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue; if($null -eq $s){"EXISTS=false"}else{"EXISTS=true";"STATE=$($s.State)";"START_MODE=$($s.StartMode)"}`)
	return W16Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW16(input W16Input) CheckResult {
	exists := strings.ToLower(findConfigValue(input.RawConfig, "EXISTS"))
	state := strings.ToLower(findConfigValue(input.RawConfig, "STATE"))
	startMode := strings.ToLower(findConfigValue(input.RawConfig, "START_MODE"))
	status := StatusManual
	vulnerable := ""

	switch {
	case exists == "false":
		status = StatusNotApplicable
	case state == "stopped" && startMode == "disabled":
		status = StatusGood
	case exists == "true" && (state == "running" || startMode != "disabled"):
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("state="+state+" start_mode="+startMode, "RemoteRegistry is not both stopped and disabled.")
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("remote_registry_state="+state, "start_mode="+startMode),
		VulnerableConfig: vulnerable,
	}
}
