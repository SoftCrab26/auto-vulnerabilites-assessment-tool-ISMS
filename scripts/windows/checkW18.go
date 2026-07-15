package main

import "strings"

type W18Input struct {
	ServiceActive bool
	RawConfig     string
}

func checkW18(ctx ScanContext) CheckResult {
	const code = "W-18"
	const description = "SNMP community strings should not use the default public or private values."
	mitreAttack := MitreAttack{
		tactic:      "Discovery",
		techniques:  []string{"T1046"},
		mitigations: []string{"M1042"},
	}

	input, errs := loadW18Input(ctx)
	result := evalW18(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW18Input(ctx ScanContext) (W18Input, []string) {
	active := anyServiceActive(ctx.Services, "snmp")
	if !active {
		return W18Input{ServiceActive: false}, nil
	}
	commands, errs := collectCommands(`$p=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -ErrorAction SilentlyContinue; if($null -eq $p){"COMMUNITY_CONFIG=NOT_FOUND"}else{$p.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {"COMMUNITY=$($_.Name)"}}`)
	return W18Input{ServiceActive: true, RawConfig: firstCommandOutput(commands)}, errs
}

func evalW18(input W18Input) CheckResult {
	if !input.ServiceActive {
		return CheckResult{Status: StatusNotApplicable, ProcessedConfig: buildProcessedConfig("snmp=inactive")}
	}

	status := StatusManual
	vulnerable := ""
	for _, line := range strings.Split(input.RawConfig, "\n") {
		value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "COMMUNITY="))
		if strings.HasPrefix(strings.TrimSpace(line), "COMMUNITY=") &&
			(strings.EqualFold(value, "public") || strings.EqualFold(value, "private")) {
			status = StatusVulnerable
			vulnerable = buildVulnerableConfig("default_community="+value, `SNMP uses the default community string "public" or "private".`)
			break
		}
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("snmp=active", "community_strength=manual_review"),
		VulnerableConfig: vulnerable,
	}
}
