package main

import (
	"strconv"
	"strings"
)

type W14Input struct {
	RawConfig string
}

func checkW14(ctx ScanContext) CheckResult {
	const code = "W-14"
	const description = "Windows Firewall should be enabled for every network profile."
	mitreAttack := MitreAttack{
		tactic:      "Command and Control",
		techniques:  []string{"T1043"},
		mitigations: []string{"M1037"},
	}

	input, errs := loadW14Input(ctx)
	result := evalW14(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW14Input(ctx ScanContext) (W14Input, []string) {
	commands, errs := collectCommands(
		`Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { "PROFILE=$($_.Name);ENABLED=$($_.Enabled);INBOUND=$($_.DefaultInboundAction);OUTBOUND=$($_.DefaultOutboundAction)" }`,
	)
	return W14Input{RawConfig: firstCommandOutput(commands)}, errs
}

func evalW14(input W14Input) CheckResult {
	lines := strings.Split(input.RawConfig, "\n")
	profiles := 0
	disabled := []string{}
	for _, line := range lines {
		if !containsAnyFold(line, "PROFILE=") {
			continue
		}
		profiles++
		if !containsAnyFold(line, "ENABLED=True") {
			disabled = append(disabled, strings.TrimSpace(line))
		}
	}

	status := StatusGood
	vulnerable := ""
	if profiles < 3 || len(disabled) > 0 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(
			"profiles_found="+strconv.Itoa(profiles),
			"disabled_or_missing="+strings.Join(disabled, ","),
		)
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.RawConfig,
		ProcessedConfig:  buildProcessedConfig("profiles_found="+strconv.Itoa(profiles), "disabled_count="+strconv.Itoa(len(disabled))),
		VulnerableConfig: vulnerable,
	}
}
