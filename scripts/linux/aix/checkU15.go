package main

import (
	"os"
	"strconv"
	"strings"
)

type U15Input struct {
	Orphans   []auditFile
	Errors    []string
	Truncated bool
}

func checkU15(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU15(loadU15Input())
	result.Code = "U-15"
	result.Description = "Files and directories without a valid owner must be reviewed and removed or reassigned."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1003"}, Mitigations: []string{"M1026"}}
	return result
}

func loadU15Input() U15Input {
	files, errs, truncated := boundedRegularFiles(
		[]string{"/etc", "/usr/bin", "/usr/sbin", "/var", "/home", "/root"},
		20000,
		func(os.FileMode) bool { return true },
	)
	var orphans []auditFile
	for _, file := range files {
		if _, err := strconv.ParseUint(file.Owner, 10, 64); err == nil {
			orphans = append(orphans, file)
		}
	}
	return U15Input{Orphans: orphans, Errors: errs, Truncated: truncated}
}

func evalU15(input U15Input) CheckResult {
	notes := []string{"bounded_inventory=true", "orphan_candidates=" + strconv.Itoa(len(input.Orphans))}
	if input.Truncated {
		notes = append(notes, "truncated=true")
	}
	return CheckResult{
		Status: StatusInterview, RawConfig: inventoryRaw(input.Orphans),
		ProcessedConfig:  strings.Join(notes, " "),
		VulnerableConfig: "Review numeric-owner candidates and validate excluded filesystems.",
		ErrMsg:           strings.Join(input.Errors, "\n"),
	}
}
