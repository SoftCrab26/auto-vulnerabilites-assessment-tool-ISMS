package main

import "strings"

type W29Input struct {
	ServiceActive bool
	RawConfig     string
}

func checkW29(ctx ScanContext) CheckResult {
	const code = "W-29"
	const description = "SNMP community strings should not be default or demonstrably weak."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1552"},
		mitigations: []string{"M1027"},
	}

	input, errs := loadW29Input(ctx)
	result := evalW29(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW29Input(ctx ScanContext) (W29Input, []string) {
	active := anyServiceActive(ctx.Services, "snmp")
	if !active {
		return W29Input{ServiceActive: false}, nil
	}
	commands, errs := collectCommands(`$p=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -ErrorAction SilentlyContinue; if($null -eq $p){"COMMUNITY_CONFIG=NOT_FOUND"}else{$p.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {"COMMUNITY=$($_.Name)"}}`)
	return W29Input{ServiceActive: true, RawConfig: firstCommandOutput(commands)}, errs
}

func evalW29(input W29Input) CheckResult {
	if !input.ServiceActive {
		return CheckResult{Status: StatusNotApplicable, ProcessedConfig: buildProcessedConfig("snmp=inactive")}
	}

	status := StatusManual
	vulnerable := ""
	for _, line := range strings.Split(input.RawConfig, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "COMMUNITY=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "COMMUNITY="))
		if strings.EqualFold(value, "public") || strings.EqualFold(value, "private") || strings.TrimSpace(value) == "" {
			status = StatusVulnerable
			vulnerable = buildVulnerableConfig("weak_community="+value, "SNMP uses a default or empty community string.")
			break
		}
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("snmp=active", "community_complexity=manual_review"),
		VulnerableConfig: vulnerable,
	}
}
