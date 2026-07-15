package main

type W02Input struct {
	AccountEvidence string
}

func checkW02(ctx ScanContext) CheckResult {
	const code = "W-02"
	const description = "Unnecessary local accounts should be removed."
	mitreAttack := MitreAttack{
		tactic:      "Persistence",
		techniques:  []string{"T1078.003", "T1136.001"},
		mitigations: []string{"M1042"},
	}
	input, errs := loadW02Input(ctx)
	result := evalW02(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW02Input(ctx ScanContext) (W02Input, []string) {
	results, errs := collectCommands(`Get-LocalUser | Sort-Object Name | ForEach-Object {"Name=$($_.Name)|Enabled=$($_.Enabled)|LastLogon=$($_.LastLogon)|Description=$($_.Description)"}`)
	return W02Input{AccountEvidence: firstCommandOutput(results)}, errs
}

func evalW02(input W02Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.AccountEvidence,
		ProcessedConfig:  "manual_review=required reason=no_unnecessary_account_list_defined",
		VulnerableConfig: "Review each local account against the organization's approved account inventory.",
	}
}
