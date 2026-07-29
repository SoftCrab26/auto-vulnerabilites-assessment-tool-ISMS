package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type U25Input struct {
	Roots         []string
	WorldWritable []dsmU14AuditFile
	Scanned       int
}

func checkU25(ScanContext) CheckResult {
	input, errs := loadU25Input()
	result := evalU25(input)
	result.Code = "U-25"
	result.Description = "World-writable files in fixed system roots must be inventoried and justified."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1222.002"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU25Input() (U25Input, []string) {
	input := U25Input{Roots: []string{"/etc", "/etc.defaults", "/usr/syno/etc", "/usr/local/etc"}}
	var errs []string
	for _, root := range input.Roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			input.Scanned++
			info, err := entry.Info()
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o002 != 0 {
				file, readErr := dsmU14ReadAuditFile(path, false)
				if readErr == nil && len(input.WorldWritable) < dsmU14EvidenceLimit {
					input.WorldWritable = append(input.WorldWritable, file)
				}
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("%s: %v", root, err))
		}
	}
	if input.Scanned == 0 {
		errs = append(errs, "no fixed system root could be inventoried")
	}
	return input, errs
}

func evalU25(input U25Input) CheckResult {
	if input.Scanned == 0 {
		return dsmU14Error("world-writable inventory data is unavailable")
	}
	evidence := []string{fmt.Sprintf("bounded roots=%v scanned=%d", input.Roots, input.Scanned)}
	for _, file := range input.WorldWritable {
		evidence = append(evidence, dsmU14Metadata(file))
	}
	return CheckResult{Status: Manual, RawConfig: dsmU14JoinEvidence(evidence),
		ProcessedConfig: fmt.Sprintf("bounded_inventory=true candidates=%d", len(input.WorldWritable))}
}
