package main

import (
	"fmt"
	"os"
	"strings"
)

type U21Input struct {
	Files []dsmU14AuditFile
}

func checkU21(ScanContext) CheckResult {
	input, errs := loadU21Input()
	result := evalU21(input)
	result.Code = "U-21"
	result.Description = "DSM syslog configuration must be root-owned with mode 0640 or more restrictive."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1562"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU21Input() (U21Input, []string) {
	groups := [][]string{
		{"/etc/syslog-ng/syslog-ng.conf", "/etc.defaults/syslog-ng/syslog-ng.conf"},
		{"/etc/rsyslog.conf", "/etc.defaults/rsyslog.conf"},
	}
	var input U21Input
	var failures []string
	for _, paths := range groups {
		for _, path := range paths {
			file, err := dsmU14ReadAuditFile(path, false)
			if err == nil {
				input.Files = append(input.Files, file)
				break
			}
			if !os.IsNotExist(err) {
				failures = append(failures, err.Error())
			}
		}
	}
	if len(input.Files) == 0 {
		failures = append(failures, "DSM syslog-ng/rsyslog configuration not found")
	}
	return input, failures
}

func evalU21(input U21Input) CheckResult {
	if len(input.Files) == 0 {
		return dsmU14Error("required DSM logging configuration is unavailable")
	}
	var evidence, bad []string
	for _, file := range input.Files {
		line := dsmU14Metadata(file)
		evidence = append(evidence, line)
		if (file.UID != 0 && file.UID != 1 && file.UID != 3) || file.Mode.Perm()&^os.FileMode(0o640) != 0 {
			bad = append(bad, line)
		}
	}
	status := Good
	if len(bad) > 0 {
		status = Vulnerable
	}
	return CheckResult{Status: status, RawConfig: strings.Join(evidence, "\n"), VulnerableConfig: strings.Join(bad, "\n"),
		ProcessedConfig: fmt.Sprintf("checked=%d issues=%d", len(input.Files), len(bad))}
}
