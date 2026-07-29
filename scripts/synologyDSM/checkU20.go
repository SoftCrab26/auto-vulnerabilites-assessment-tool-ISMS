package main

import (
	"fmt"
	"os"
	"strings"
)

type U20Input struct {
	Files  []dsmU14AuditFile
	Active bool
}

func checkU20(ctx ScanContext) CheckResult {
	input, errs := loadU20Input(ctx)
	result := evalU20(input)
	result.Code = "U-20"
	result.Description = "Active inetd configuration must be root-owned with mode 0600 or more restrictive."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU20Input(ctx ScanContext) (U20Input, []string) {
	input := U20Input{Active: containsAnyWord(ctx.Runtime.ProcessList, []string{"inetd", "xinetd"})}
	for _, path := range []string{"/etc/inetd.conf", "/etc.defaults/inetd.conf"} {
		file, err := dsmU14ReadAuditFile(path, false)
		if err == nil {
			input.Files = append(input.Files, file)
			break
		}
		if !os.IsNotExist(err) {
			return input, []string{err.Error()}
		}
	}
	return input, nil
}

func evalU20(input U20Input) CheckResult {
	if len(input.Files) == 0 || !input.Active {
		reason := "inetd configuration absent"
		if len(input.Files) > 0 {
			reason = "inetd inactive"
		}
		return CheckResult{Status: NotApplicable, RawConfig: reason, ProcessedConfig: "applicable=false"}
	}
	var evidence, bad []string
	for _, file := range input.Files {
		line := dsmU14Metadata(file)
		evidence = append(evidence, line)
		if file.UID != 0 || file.Mode.Perm()&^os.FileMode(0o600) != 0 {
			bad = append(bad, line)
		}
	}
	status := Good
	if len(bad) > 0 {
		status = Vulnerable
	}
	return CheckResult{Status: status, RawConfig: strings.Join(evidence, "\n"), VulnerableConfig: strings.Join(bad, "\n"),
		ProcessedConfig: fmt.Sprintf("active=true checked=%d issues=%d", len(input.Files), len(bad))}
}
