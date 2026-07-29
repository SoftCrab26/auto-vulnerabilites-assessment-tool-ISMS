package main

type U19Input struct {
	Hosts dsmU14AuditFile
}

func checkU19(ScanContext) CheckResult {
	input, errs := loadU19Input()
	result := evalU19(input)
	result.Code = "U-19"
	result.Description = "/etc/hosts must be root-owned with mode 0644 or more restrictive."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU19Input() (U19Input, []string) {
	file, err := dsmU14ReadAuditFile("/etc/hosts", false)
	if err != nil {
		return U19Input{}, []string{err.Error()}
	}
	return U19Input{Hosts: file}, nil
}

func evalU19(input U19Input) CheckResult {
	return dsmU14PermissionResult(input.Hosts, 0o644, 0)
}
