package main

type W23Input struct {
	ServiceActive bool
	RawConfig     string
}

func checkW23(ctx ScanContext) CheckResult {
	const code = "W-23"
	const description = "Network Level Authentication should be enabled for Remote Desktop."
	mitreAttack := MitreAttack{
		tactic:      "Lateral Movement",
		techniques:  []string{"T1021.001"},
		mitigations: []string{"M1032"},
	}

	input, errs := loadW23Input(ctx)
	result := evalW23(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW23Input(ctx ScanContext) (W23Input, []string) {
	active := anyServiceActive(ctx.Services, "rdp")
	if !active {
		return W23Input{ServiceActive: false}, nil
	}
	commands, errs := collectCommands(`$v=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication; "USER_AUTHENTICATION=$(if($null -eq $v){'NOT_FOUND'}else{$v})"`)
	return W23Input{ServiceActive: true, RawConfig: firstCommandOutput(commands)}, errs
}

func evalW23(input W23Input) CheckResult {
	if !input.ServiceActive {
		return CheckResult{Status: StatusNotApplicable, ProcessedConfig: buildProcessedConfig("rdp=inactive")}
	}

	nla := findConfigValue(input.RawConfig, "USER_AUTHENTICATION")
	status := StatusManual
	vulnerable := ""
	if nla == "1" {
		status = StatusGood
	} else if nla == "0" {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("UserAuthentication=0", "RDP Network Level Authentication is disabled.")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("rdp=active", "nla="+nla),
		VulnerableConfig: vulnerable,
	}
}
