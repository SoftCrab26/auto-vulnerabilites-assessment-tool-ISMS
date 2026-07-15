package main

type W10Input struct {
	RegistryEvidence string
}

func checkW10(ctx ScanContext) CheckResult {
	const code = "W-10"
	const description = "Access to security-sensitive registry keys should be restricted to authorized principals."
	mitreAttack := MitreAttack{
		tactic:      "Defense Evasion",
		techniques:  []string{"T1112"},
		mitigations: []string{"M1022"},
	}
	input, errs := loadW10Input(ctx)
	result := evalW10(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW10Input(ctx ScanContext) (W10Input, []string) {
	results, errs := collectCommands(`Get-PSDrive -PSProvider Registry | ForEach-Object {$a=Get-Acl ($_.Name+':\'); "Hive=$($_.Name)|Root=$($_.Root)|Owner=$($a.Owner)|SDDL=$($a.Sddl)|Protected=$($a.AreAccessRulesProtected)"}`)
	return W10Input{RegistryEvidence: firstCommandOutput(results)}, errs
}

func evalW10(input W10Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.RegistryEvidence,
		ProcessedConfig:  "manual_review=required reason=important_registry_key_list_not_defined",
		VulnerableConfig: "Identify the organization's important registry keys and verify that their ACLs grant only required access.",
	}
}
