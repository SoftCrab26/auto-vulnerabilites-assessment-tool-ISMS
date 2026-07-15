package main

import "strings"

type W09Input struct {
	ShareACLEvidence string
}

func checkW09(ctx ScanContext) CheckResult {
	const code = "W-09"
	const description = "The Everyone principal should not be granted access to shared folders."
	mitreAttack := MitreAttack{
		tactic:      "Lateral Movement",
		techniques:  []string{"T1021.002"},
		mitigations: []string{"M1018", "M1022"},
	}
	input, errs := loadW09Input(ctx)
	result := evalW09(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW09Input(ctx ScanContext) (W09Input, []string) {
	results, errs := collectCommands(`$all=Get-SmbShare | ForEach-Object {Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue}; "AccessEntryCount=$(@($all).Count)"; $all | ForEach-Object {"Share=$($_.Name)|Account=$($_.AccountName)|Type=$($_.AccessControlType)|Right=$($_.AccessRight)"}`)
	return W09Input{ShareACLEvidence: firstCommandOutput(results)}, errs
}

func evalW09(input W09Input) CheckResult {
	count := findConfigValue(input.ShareACLEvidence, "AccessEntryCount")
	var everyoneEntries []string
	for _, line := range strings.Split(input.ShareACLEvidence, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Share=") && containsAnyFold(trimmed, "|Account=Everyone|", "|Account=S-1-1-0|") {
			everyoneEntries = append(everyoneEntries, trimmed)
		}
	}
	status := StatusGood
	vulnerable := ""
	if count == "NOT_FOUND" {
		status = StatusManual
		vulnerable = "Share ACL evidence could not be evaluated."
	} else if len(everyoneEntries) > 0 {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig(strings.Join(everyoneEntries, "\n"), "Everyone has access to one or more shares.")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.ShareACLEvidence,
		ProcessedConfig:  buildProcessedConfig("AccessEntryCount="+count, "EveryoneEntryCount="+string(rune(len(everyoneEntries)+'0'))),
		VulnerableConfig: vulnerable,
	}
}
