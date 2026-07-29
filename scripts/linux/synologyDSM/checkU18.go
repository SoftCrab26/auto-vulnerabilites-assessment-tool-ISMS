package main

type U18Input struct {
	Shadow dsmU14AuditFile
}

func checkU18(ScanContext) CheckResult {
	input, errs := loadU18Input()
	result := evalU18(input)
	result.Code = "U-18"
	result.Description = "/etc/shadow must be root-owned with mode 0400 or more restrictive."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1003.008"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU18Input() (U18Input, []string) {
	file, err := dsmU14ReadAuditFile("/etc/shadow", false)
	if err != nil {
		return U18Input{}, []string{err.Error()}
	}
	return U18Input{Shadow: file}, nil
}

func evalU18(input U18Input) CheckResult {
	return dsmU14PermissionResult(input.Shadow, 0o400, 0)
}
