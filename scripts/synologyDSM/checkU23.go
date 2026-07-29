package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type U23Input struct {
	Roots      []string
	Privileged []dsmU14AuditFile
	Scanned    int
}

func checkU23(ScanContext) CheckResult {
	input, errs := loadU23Input()
	result := evalU23(input)
	result.Code = "U-23"
	result.Description = "SUID and SGID executables must be inventoried and justified."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1548.001"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU23Input() (U23Input, []string) {
	input := U23Input{Roots: []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/syno/bin", "/usr/syno/sbin"}}
	var errs []string
	for _, root := range input.Roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			input.Scanned++
			info, err := entry.Info()
			if err == nil && info.Mode().IsRegular() && info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				file, readErr := dsmU14ReadAuditFile(path, false)
				if readErr == nil && len(input.Privileged) < dsmU14EvidenceLimit {
					input.Privileged = append(input.Privileged, file)
				}
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("%s: %v", root, err))
		}
	}
	if input.Scanned == 0 {
		errs = append(errs, "no fixed executable root could be inventoried")
	}
	return input, errs
}

func evalU23(input U23Input) CheckResult {
	if input.Scanned == 0 {
		return dsmU14Error("SUID/SGID inventory data is unavailable")
	}
	evidence := []string{fmt.Sprintf("bounded roots=%v scanned=%d", input.Roots, input.Scanned)}
	for _, file := range input.Privileged {
		evidence = append(evidence, dsmU14Metadata(file))
	}
	return CheckResult{Status: Manual, RawConfig: dsmU14JoinEvidence(evidence),
		ProcessedConfig: fmt.Sprintf("bounded_inventory=true candidates=%d", len(input.Privileged))}
}
