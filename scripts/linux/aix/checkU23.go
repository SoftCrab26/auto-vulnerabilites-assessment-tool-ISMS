package main

import (
	"os"
	"strconv"
	"strings"
)

type U23Input struct {
	Privileged []auditFile
	Errors     []string
	Truncated  bool
}

func checkU23(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU23(loadU23Input())
	result.Code = "U-23"
	result.Description = "SUID and SGID executables must be inventoried and justified."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1548.001"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU23Input() U23Input {
	files, errs, truncated := boundedRegularFiles(
		[]string{"/usr/bin", "/usr/sbin", "/usr/lib", "/etc"},
		30000,
		func(mode os.FileMode) bool { return mode&(os.ModeSetuid|os.ModeSetgid) != 0 },
	)
	return U23Input{Privileged: files, Errors: errs, Truncated: truncated}
}

func evalU23(input U23Input) CheckResult {
	return CheckResult{
		Status: StatusInterview, RawConfig: inventoryRaw(input.Privileged),
		ProcessedConfig:  "suid_sgid_files=" + strconv.Itoa(len(input.Privileged)) + " truncated=" + strconv.FormatBool(input.Truncated),
		VulnerableConfig: "Review each SUID/SGID file against the approved AIX baseline.",
		ErrMsg:           strings.Join(input.Errors, "\n"),
	}
}
