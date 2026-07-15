package main

import "strings"

type W31Input struct {
	Bindings string
}

func checkW31(ctx ScanContext) CheckResult {
	const code = "W-31"
	const description = "Unnecessary legacy protocols such as IPX and NetBEUI should be disabled."
	mitreAttack := MitreAttack{tactic: "Lateral Movement", techniques: []string{"T1021"}, mitigations: []string{"M1042"}}

	input, errs := loadW31Input()
	result := evalW31(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW31Input() (W31Input, []string) {
	command := `Get-NetAdapterBinding -AllBindings | Sort-Object Name,ComponentID | ForEach-Object { Write-Output ($_.Name + '|' + $_.ComponentID + '|' + $_.DisplayName + '|' + [string]$_.Enabled) }`
	results, errs := collectCommands(command)
	return W31Input{Bindings: firstCommandOutput(results)}, errs
}

func evalW31(input W31Input) CheckResult {
	var enabledLegacy []string
	for _, line := range strings.Split(input.Bindings, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if (strings.Contains(lower, "ipx") || strings.Contains(lower, "netbeui")) && strings.HasSuffix(lower, "|true") {
			enabledLegacy = append(enabledLegacy, strings.TrimSpace(line))
		}
	}

	status := StatusManual
	vulnerable := ""
	processed := "legacy_protocol_review=manual"
	if len(enabledLegacy) > 0 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(strings.Join(enabledLegacy, "\n"), "Enabled IPX or NetBEUI binding was found.")
		processed = "enabled_known_legacy_protocol=true"
	}
	return CheckResult{Status: status, RawConfig: input.Bindings, ProcessedConfig: processed, VulnerableConfig: vulnerable}
}
