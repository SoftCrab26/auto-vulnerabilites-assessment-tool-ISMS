package main

import (
	"os"
	"strconv"
	"strings"
)

type U37Path struct {
	Path   string
	Exists bool
	Owner  string
	Mode   os.FileMode
	IsDir  bool
}

type U37Input struct {
	Paths []U37Path
}

func checkU37(ctx ScanContext) CheckResult {
	const code = "U-37"
	const description = "AIX cron and at files and directories should have restrictive ownership and permissions."
	mitre := MitreAttack{Tactic: "Persistence", Techniques: []string{"T1053"}, Mitigations: []string{"M1022"}}
	input, errs := loadU37Input()
	result := evalU37(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	if len(errs) > 0 && result.Status == StatusGood {
		result.Status = StatusInterview
		result.ProcessedConfig = "cron_permissions=incomplete"
	}
	return resultWithErrors(result, errs)
}

func loadU37Input() (U37Input, []string) {
	paths := []string{
		"/var/adm/cron",
		"/var/spool/cron/crontabs",
		"/var/adm/cron/cron.allow",
		"/var/adm/cron/cron.deny",
		"/var/adm/cron/at.allow",
		"/var/adm/cron/at.deny",
	}
	input := U37Input{}
	var errs []string
	for _, path := range paths {
		entry := U37Path{Path: path}
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			input.Paths = append(input.Paths, entry)
			continue
		}
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		owner, err := fileOwnerName(path)
		if err != nil {
			errs = append(errs, err.Error())
		}
		entry.Exists, entry.Owner, entry.Mode, entry.IsDir = true, owner, info.Mode(), info.IsDir()
		input.Paths = append(input.Paths, entry)
	}
	return input, errs
}

func evalU37(input U37Input) CheckResult {
	var observed, issues []string
	for _, entry := range input.Paths {
		if !entry.Exists {
			continue
		}
		line := entry.Path + " owner=" + entry.Owner + " mode=" + strconv.FormatUint(uint64(entry.Mode.Perm()), 8)
		observed = append(observed, line)
		if entry.Owner == "" {
			return CheckResult{Status: StatusInterview, RawConfig: strings.Join(observed, "\n"), ProcessedConfig: "cron_permissions=metadata_incomplete"}
		}
		allowed := os.FileMode(0640)
		if entry.IsDir || entry.Mode.IsDir() {
			allowed = 0750
		}
		if entry.Owner != "root" || entry.Mode.Perm()&^allowed != 0 {
			issues = append(issues, line)
		}
	}
	if len(observed) == 0 {
		return CheckResult{Status: StatusInterview, ProcessedConfig: "cron_permissions=evidence_unavailable"}
	}
	if len(issues) > 0 {
		return CheckResult{Status: StatusVulnerable, RawConfig: strings.Join(observed, "\n"), ProcessedConfig: "cron_permissions=noncompliant", VulnerableConfig: strings.Join(issues, "\n")}
	}
	return CheckResult{Status: StatusGood, RawConfig: strings.Join(observed, "\n"), ProcessedConfig: "cron_permissions=compliant"}
}
