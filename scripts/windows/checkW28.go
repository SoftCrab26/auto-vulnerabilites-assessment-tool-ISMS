package main

type W28Input struct {
	RawConfig string
}

func checkW28(ctx ScanContext) CheckResult {
	const code = "W-28"
	const description = "An appropriate session inactivity timeout should be configured."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1550"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadW28Input(ctx)
	result := evalW28(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW28Input(ctx ScanContext) (W28Input, []string) {
	commands, errs := collectCommands(`$m=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs; $r=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -ErrorAction SilentlyContinue).MaxIdleTime; "MACHINE_INACTIVITY_SECONDS=$(if($null -eq $m){'NOT_FOUND'}else{$m})"; "RDP_MAX_IDLE_MILLISECONDS=$(if($null -eq $r){'NOT_FOUND'}else{$r})"`)
	return W28Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW28(input W28Input) CheckResult {
	if input.RawConfig == "" {
		return CheckResult{
			Status:          StatusManual,
			ProcessedConfig: buildProcessedConfig("session_timeout=collection_unavailable"),
		}
	}

	machine := findConfigValue(input.RawConfig, "MACHINE_INACTIVITY_SECONDS")
	rdp := findConfigValue(input.RawConfig, "RDP_MAX_IDLE_MILLISECONDS")
	status := StatusInterview
	vulnerable := ""

	machineMissing := machine == "NOT_FOUND" || machine == "0"
	rdpMissing := rdp == "NOT_FOUND" || rdp == "0"
	if machineMissing && rdpMissing {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("machine_inactivity="+machine+" rdp_max_idle="+rdp, "No session inactivity timeout is configured.")
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("machine_inactivity_seconds="+machine, "rdp_max_idle_milliseconds="+rdp, "threshold=interview_required"),
		VulnerableConfig: vulnerable,
	}
}
