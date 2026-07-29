package main

type U39Input struct {
	NFS               Service
	EvidenceAvailable bool
}

func checkU39(ctx ScanContext) CheckResult {
	const code = "U-39"
	const description = "The operational need for active NFS services should be reviewed."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU39Input(ctx)
	result := evalU39(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU39Input(ctx ScanContext) (U39Input, []string) {
	return U39Input{NFS: ctx.Services["nfs"], EvidenceAvailable: serviceEvidenceAvailable(ctx)}, nil
}

func evalU39(input U39Input) CheckResult {
	raw := formatServiceStatus(input.NFS)
	if input.NFS.IsActive() {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "nfs=active review_required"}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "nfs=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "nfs=inactive"}
}
