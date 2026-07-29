package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type U15Input struct {
	Roots   []string
	Orphans []string
	Scanned int
	Capped  bool
	Errors  []string
}

func checkU15(ScanContext) CheckResult {
	input, errs := loadU15Input()
	result := evalU15(input)
	result.Code = "U-15"
	result.Description = "Files without a valid owner must be identified and reviewed."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1003"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU15Input() (U15Input, []string) {
	input := U15Input{Roots: []string{"/etc", "/etc.defaults", "/usr/syno/etc"}}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return input, []string{fmt.Sprintf("/etc/passwd: %v", err)}
	}
	knownUIDs := dsmU15KnownUIDs(string(passwd))
	for _, root := range input.Roots {
		if err := dsmU15Walk(root, knownUIDs, &input); err != nil {
			if !os.IsNotExist(err) {
				input.Errors = append(input.Errors, fmt.Sprintf("%s: %v", root, err))
			}
		}
	}
	if input.Scanned == 0 {
		return input, []string{"no fixed system configuration root could be inventoried"}
	}
	return input, input.Errors
}

func evalU15(input U15Input) CheckResult {
	if input.Scanned == 0 {
		return dsmU14Error("orphan inventory data is unavailable")
	}
	evidence := []string{fmt.Sprintf("bounded roots=%v scanned=%d", input.Roots, input.Scanned)}
	evidence = append(evidence, input.Orphans...)
	vulnerable := ""
	if len(input.Orphans) > 0 {
		vulnerable = dsmU14JoinEvidence(input.Orphans)
	}
	status := Manual
	if len(input.Orphans) > 0 && !input.Capped && len(input.Errors) == 0 {
		status = Vulnerable
	}
	return CheckResult{Status: status, RawConfig: dsmU14JoinEvidence(evidence), VulnerableConfig: vulnerable,
		ProcessedConfig: fmt.Sprintf("bounded_inventory=true orphan_candidates=%d", len(input.Orphans))}
}

func dsmU15KnownUIDs(passwd string) map[uint32]bool {
	known := make(map[uint32]bool)
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err == nil {
			known[uint32(uid)] = true
		}
	}
	return known
}

func dsmU15Walk(root string, knownUIDs map[uint32]bool, input *U15Input) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		input.Scanned++
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && !knownUIDs[stat.Uid] {
			if len(input.Orphans) < dsmU14EvidenceLimit {
				input.Orphans = append(input.Orphans, dsmU14Sanitize(path)+" uid=unknown")
			} else {
				input.Capped = true
			}
		}
		return nil
	})
}
