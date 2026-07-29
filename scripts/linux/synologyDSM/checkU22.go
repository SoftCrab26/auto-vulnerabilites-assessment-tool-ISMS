package main

type U22Input struct {
	Services dsmU14AuditFile
}

func checkU22(ScanContext) CheckResult {
	input, errs := loadU22Input()
	result := evalU22(input)
	result.Code = "U-22"
	result.Description = "/etc/services must be root-owned with mode 0644 or more restrictive."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU22Input() (U22Input, []string) {
	file, err := dsmU14ReadAuditFile("/etc/services", false)
	if err != nil {
		return U22Input{}, []string{err.Error()}
	}
	return U22Input{Services: file}, nil
}

func evalU22(input U22Input) CheckResult {
	return dsmU14PermissionResult(input.Services, 0o644, 0, 1, 3)
}
