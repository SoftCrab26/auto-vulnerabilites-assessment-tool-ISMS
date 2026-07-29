package main

type U16Input struct {
	Passwd dsmU14AuditFile
}

func checkU16(ScanContext) CheckResult {
	input, errs := loadU16Input()
	result := evalU16(input)
	result.Code = "U-16"
	result.Description = "/etc/passwd must be root-owned with mode 0644 or more restrictive."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1003.008"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU16Input() (U16Input, []string) {
	file, err := dsmU14ReadAuditFile("/etc/passwd", false)
	if err != nil {
		return U16Input{}, []string{err.Error()}
	}
	return U16Input{Passwd: file}, nil
}

func evalU16(input U16Input) CheckResult {
	return dsmU14PermissionResult(input.Passwd, 0o644, 0)
}
