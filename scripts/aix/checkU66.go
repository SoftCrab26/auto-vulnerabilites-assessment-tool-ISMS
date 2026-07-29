package main

import (
	"fmt"
	"strings"
)

type U66Input struct {
	ConfigPath string
	Config     string
}

func checkU66(ctx ScanContext) CheckResult {
	const code = "U-66"
	const description = "AIX syslog should route the required system facilities."
	mitre := MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1562"}, Mitigations: []string{"M1022"}}

	input, errs := loadU66Input()
	result := evalU66(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU66Input() (U66Input, []string) {
	file, errs := collectFirstExisting("/etc/syslog.conf")
	return U66Input{ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU66(input U66Input) CheckResult {
	required := []string{"auth", "daemon", "kern", "mail", "user"}
	covered := syslogFacilities(input.Config)
	var missing []string
	for _, facility := range required {
		if !covered["*"] && !covered[facility] {
			missing = append(missing, facility)
		}
	}

	status := StatusGood
	vulnerable := ""
	if strings.TrimSpace(input.Config) == "" || len(missing) > 0 {
		status = StatusVulnerable
		if strings.TrimSpace(input.Config) == "" {
			vulnerable = "No readable /etc/syslog.conf data was available."
		} else {
			vulnerable = "Missing syslog facility coverage: " + strings.Join(missing, ",")
		}
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s active_rules=%d", input.ConfigPath, syslogRuleCount(input.Config)),
		ProcessedConfig:  fmt.Sprintf("required_facilities=%d missing_facilities=%d", len(required), len(missing)),
		VulnerableConfig: vulnerable,
	}
}

func syslogFacilities(config string) map[string]bool {
	covered := make(map[string]bool)
	for _, line := range activeConfigLines(config) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, selector := range strings.Split(fields[0], ";") {
			parts := strings.SplitN(selector, ".", 2)
			if len(parts) != 2 || strings.EqualFold(parts[1], "none") {
				continue
			}
			for _, facility := range strings.Split(parts[0], ",") {
				facility = strings.ToLower(strings.TrimSpace(facility))
				if facility != "" {
					covered[facility] = true
				}
			}
		}
	}
	return covered
}

func syslogRuleCount(config string) int {
	count := 0
	for _, line := range activeConfigLines(config) {
		if len(strings.Fields(line)) >= 2 {
			count++
		}
	}
	return count
}
