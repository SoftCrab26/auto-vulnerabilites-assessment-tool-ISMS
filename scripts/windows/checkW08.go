package main

import "strings"

type W08Input struct {
	ShareConfig string
}

func checkW08(ctx ScanContext) CheckResult {
	const code = "W-08"
	const description = "Non-default shared folders should be removed when they are not required."
	mitreAttack := MitreAttack{
		tactic:      "Discovery",
		techniques:  []string{"T1135"},
		mitigations: []string{"M1042"},
	}
	input, errs := loadW08Input(ctx)
	result := evalW08(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW08Input(ctx ScanContext) (W08Input, []string) {
	results, errs := collectCommands(`$s=Get-SmbShare | Where-Object {$_.Name -notmatch '\$$'}; "NonDefaultShareCount=$(@($s).Count)"; $s | ForEach-Object {"Share=$($_.Name)|Path=$($_.Path)|Description=$($_.Description)"}`)
	return W08Input{ShareConfig: firstCommandOutput(results)}, errs
}

func evalW08(input W08Input) CheckResult {
	count := safeAtoi(findConfigValue(input.ShareConfig, "NonDefaultShareCount"))
	status := StatusGood
	vulnerable := ""
	if count > 0 {
		status = StatusVulnerable
		var shares []string
		for _, line := range strings.Split(input.ShareConfig, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Share=") {
				shares = append(shares, strings.TrimSpace(line))
			}
		}
		vulnerable = buildVulnerableConfig(strings.Join(shares, "\n"), "Non-default shares exist and should be reviewed and removed if unnecessary.")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        input.ShareConfig,
		ProcessedConfig:  buildProcessedConfig("NonDefaultShareCount=" + findConfigValue(input.ShareConfig, "NonDefaultShareCount")),
		VulnerableConfig: vulnerable,
	}
}
