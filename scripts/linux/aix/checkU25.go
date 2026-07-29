package main

import (
	"os"
	"strconv"
	"strings"
)

type U25Input struct {
	WorldWritable []auditFile
	Errors        []string
	Truncated     bool
}

func checkU25(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU25(loadU25Input())
	result.Code = "U-25"
	result.Description = "World-writable regular files must be inventoried and justified."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1222.002"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU25Input() U25Input {
	files, errs, truncated := boundedRegularFiles(
		[]string{"/etc", "/usr", "/var", "/home", "/root"},
		30000,
		func(mode os.FileMode) bool { return mode.Perm()&0002 != 0 },
	)
	return U25Input{WorldWritable: files, Errors: errs, Truncated: truncated}
}

func evalU25(input U25Input) CheckResult {
	return CheckResult{
		Status: StatusInterview, RawConfig: inventoryRaw(input.WorldWritable),
		ProcessedConfig:  "world_writable_files=" + strconv.Itoa(len(input.WorldWritable)) + " truncated=" + strconv.FormatBool(input.Truncated),
		VulnerableConfig: "Review each world-writable file and document its operational requirement.",
		ErrMsg:           strings.Join(input.Errors, "\n"),
	}
}
