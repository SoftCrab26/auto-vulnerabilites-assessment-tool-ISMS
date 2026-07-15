package main

import (
	"strconv"
	"strings"
)

type W41Input struct {
	RDPActive bool
	Port      int
	PortFound bool
	Raw       string
}

func checkW41(ctx ScanContext) CheckResult {
	const code = "W-41"
	const description = "The RDP listening port should differ from the default port 3389."
	mitreAttack := MitreAttack{tactic: "Lateral Movement", techniques: []string{"T1021.001"}, mitigations: []string{"M1030"}}

	input, errs := loadW41Input(ctx)
	result := evalW41(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW41Input(ctx ScanContext) (W41Input, []string) {
	command := `$p=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Write-Output ('PORT_NUMBER=' + [string]$p.PortNumber)`
	results, errs := collectCommands(command)
	raw := firstCommandOutput(results)
	port, err := strconv.Atoi(strings.TrimSpace(findConfigValue(raw, "PORT_NUMBER")))
	return W41Input{RDPActive: ctx.Services["rdp"].IsActive(), Port: port, PortFound: err == nil && port > 0, Raw: raw}, errs
}

func evalW41(input W41Input) CheckResult {
	if !input.RDPActive {
		return CheckResult{Status: StatusNotApplicable, RawConfig: input.Raw, ProcessedConfig: "rdp_active=false"}
	}
	if !input.PortFound {
		return CheckResult{Status: StatusInterview, RawConfig: input.Raw, ProcessedConfig: "rdp_active=true rdp_port=unknown"}
	}
	if input.Port == 3389 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        input.Raw,
			ProcessedConfig:  "rdp_active=true rdp_port=3389",
			VulnerableConfig: "RDP uses the default port 3389.",
		}
	}
	return CheckResult{Status: StatusGood, RawConfig: input.Raw, ProcessedConfig: "rdp_active=true rdp_port=" + strconv.Itoa(input.Port)}
}
