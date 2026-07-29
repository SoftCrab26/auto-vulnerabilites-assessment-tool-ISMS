package main

import (
	"fmt"
	"strings"
)

type U66Input struct {
	Files []FileResult
}

func checkU66(ctx ScanContext) CheckResult {
	input, errs := loadU66Input()
	result := evalU66(input)
	result.Code = "U-66"
	result.Description = "DSM logging facilities and destinations should satisfy the security logging policy."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1562"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU66Input() (U66Input, []string) {
	files, errs := collectFiles(
		"/etc/syslog-ng/syslog-ng.conf",
		"/etc.defaults/syslog-ng/syslog-ng.conf",
		"/etc/rsyslog.conf",
		"/etc/syslog.conf",
	)
	return U66Input{Files: files}, errs
}

func evalU66(input U66Input) CheckResult {
	if len(input.Files) == 0 {
		return CheckResult{Status: Error, ProcessedConfig: "logging_config=missing", ErrMsg: "no readable DSM logging configuration was collected"}
	}
	facilities := make(map[string]bool)
	var routes []string
	for _, file := range input.Files {
		for _, line := range dsmU59ActiveLines(file.Content) {
			lower := strings.ToLower(line)
			dsmU66CollectFacilities(lower, facilities)
			if dsmU66LoggingRoute(lower) {
				routes = append(routes, fmt.Sprintf("path=%s rule=%s", file.Path, dsmU66SafeRule(line)))
			}
		}
	}
	if len(routes) == 0 || len(facilities) == 0 {
		return CheckResult{
			Status:           Vulnerable,
			RawConfig:        strings.Join(routes, "\n"),
			ProcessedConfig:  fmt.Sprintf("facility_count=%d destination_rule_count=%d", len(facilities), len(routes)),
			VulnerableConfig: "Logging facilities or persistent/remote destinations were not found.",
		}
	}
	return CheckResult{
		Status:          Manual,
		RawConfig:       strings.Join(routes, "\n"),
		ProcessedConfig: fmt.Sprintf("facility_count=%d destination_rule_count=%d organization_facility_destination_retention_review_required=true", len(facilities), len(routes)),
	}
}

func dsmU66CollectFacilities(line string, facilities map[string]bool) {
	for _, facility := range []string{"*", "auth", "authpriv", "daemon", "kern", "mail", "syslog", "user"} {
		if strings.Contains(line, facility+".") ||
			strings.Contains(line, "facility("+facility) ||
			strings.Contains(line, "facility ("+facility) {
			facilities[facility] = true
		}
	}
}

func dsmU66LoggingRoute(line string) bool {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "destination ") || strings.Contains(lower, "destination(") {
		return true
	}
	fields := strings.Fields(line)
	return len(fields) >= 2 &&
		(strings.HasPrefix(fields[0], "*.") ||
			strings.Contains(fields[0], ".") ||
			strings.HasPrefix(fields[1], "/") ||
			strings.HasPrefix(fields[1], "@"))
}

func dsmU66SafeRule(line string) string {
	line = strings.Join(strings.Fields(line), " ")
	const limit = 256
	if len(line) > limit {
		return line[:limit] + "..."
	}
	return line
}
