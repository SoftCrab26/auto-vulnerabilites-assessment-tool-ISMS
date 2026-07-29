package main

import (
	"fmt"
	"os"
	"strings"
)

type U17Input struct {
	Files  []dsmU14AuditFile
	Errors []string
}

func checkU17(ScanContext) CheckResult {
	input, errs := loadU17Input()
	result := evalU17(input)
	result.Code = "U-17"
	result.Description = "DSM startup scripts must be root-owned and not writable by group or others."
	result.MitreAttack = MitreAttack{Tactic: "Persistence", Techniques: []string{"T1037"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU17Input() (U17Input, []string) {
	input := U17Input{}
	files := []string{"/etc/rc", "/etc/rc.local", "/etc.defaults/rc", "/usr/syno/etc/rc.sysv"}
	directories := []string{"/usr/syno/etc/rc.d", "/etc/rc.d"}
	for _, path := range files {
		file, err := dsmU14ReadAuditFile(path, false)
		if err == nil {
			input.Files = append(input.Files, file)
		} else if !os.IsNotExist(err) {
			input.Errors = append(input.Errors, err.Error())
		}
	}
	for _, directory := range directories {
		found, err := dsmU14DirectFiles(directory, 200)
		if err == nil {
			input.Files = append(input.Files, found...)
		} else if !os.IsNotExist(err) {
			input.Errors = append(input.Errors, fmt.Sprintf("%s: %v", directory, err))
		}
	}
	if len(input.Files) == 0 {
		input.Errors = append(input.Errors, "no DSM startup scripts found in fixed paths")
	}
	return input, input.Errors
}

func evalU17(input U17Input) CheckResult {
	if len(input.Files) == 0 {
		return dsmU14Error("DSM startup script metadata is unavailable")
	}
	var evidence, bad []string
	for _, file := range input.Files {
		line := dsmU14Metadata(file)
		evidence = append(evidence, line)
		if file.UID != 0 || file.Mode.Perm()&0o022 != 0 {
			bad = append(bad, line)
		}
	}
	status := Good
	if len(bad) > 0 {
		status = Vulnerable
	}
	return CheckResult{Status: status, RawConfig: dsmU14JoinEvidence(evidence),
		VulnerableConfig: dsmU14JoinEvidence(bad), ProcessedConfig: fmt.Sprintf("checked=%d issues=%d", len(input.Files), len(bad)),
		ErrMsg: strings.Join(input.Errors, "\n")}
}
