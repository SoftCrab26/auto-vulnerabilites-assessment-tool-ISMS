package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type U26Input struct {
	DevExists    bool
	RegularFiles []dsmU14AuditFile
}

func checkU26(ScanContext) CheckResult {
	input, errs := loadU26Input()
	result := evalU26(input)
	result.Code = "U-26"
	result.Description = "Regular files must not exist directly under /dev."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1036"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU26Input() (U26Input, []string) {
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return U26Input{}, []string{fmt.Sprintf("/dev: %v", err)}
	}
	input := U26Input{DevExists: true}
	for _, entry := range entries {
		if len(input.RegularFiles) >= dsmU14EvidenceLimit {
			break
		}
		path := filepath.Join("/dev", entry.Name())
		file, err := dsmU14ReadAuditFile(path, false)
		if err == nil {
			input.RegularFiles = append(input.RegularFiles, file)
		}
	}
	return input, nil
}

func evalU26(input U26Input) CheckResult {
	if !input.DevExists {
		return dsmU14Error("/dev directory data is unavailable")
	}
	var evidence []string
	for _, file := range input.RegularFiles {
		evidence = append(evidence, dsmU14Metadata(file))
	}
	if len(evidence) == 0 {
		evidence = append(evidence, "no regular files directly under /dev")
	}
	status := Good
	vulnerable := ""
	if len(input.RegularFiles) > 0 {
		status = Vulnerable
		vulnerable = dsmU14JoinEvidence(evidence)
	}
	return CheckResult{Status: status, RawConfig: dsmU14JoinEvidence(evidence), VulnerableConfig: vulnerable,
		ProcessedConfig: fmt.Sprintf("direct_regular_files=%d", len(input.RegularFiles))}
}
