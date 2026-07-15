package main

type W05Input struct {
	SAMEvidence string
}

func checkW05(ctx ScanContext) CheckResult {
	const code = "W-05"
	const description = "The SAM password database should be encrypted and protected from unauthorized access."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1003.002"},
		mitigations: []string{"M1022", "M1041"},
	}
	input, errs := loadW05Input(ctx)
	result := evalW05(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadW05Input(ctx ScanContext) (W05Input, []string) {
	results, errs := collectCommands(`$p=Join-Path $env:SystemRoot 'System32\Config\SAM'; "Path=$p"; "Exists=$(Test-Path $p)"; if(Test-Path $p){$a=Get-Acl $p; "Owner=$($a.Owner)"; "SDDL=$($a.Sddl)"; "AreAccessRulesProtected=$($a.AreAccessRulesProtected)"}`)
	return W05Input{SAMEvidence: firstCommandOutput(results)}, errs
}

func evalW05(input W05Input) CheckResult {
	return CheckResult{
		Status:           StatusManual,
		RawConfig:        input.SAMEvidence,
		ProcessedConfig:  "manual_review=required reason=sam_encryption_not_proven_by_acl",
		VulnerableConfig: "Verify that the SAM is cryptographically protected and that its ACL permits only authorized system principals.",
	}
}
