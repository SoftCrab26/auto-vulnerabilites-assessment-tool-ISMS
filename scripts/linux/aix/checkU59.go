package main

import (
	"fmt"
	"strings"
)

type U59Input struct {
	SNMP       Service
	ConfigPath string
	Config     string
}

func checkU59(ctx ScanContext) CheckResult {
	const code = "U-59"
	const description = "Active SNMP should use SNMPv3 with authentication."
	mitre := MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}

	input, errs := loadU59Input(ctx)
	result := evalU59(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU59Input(ctx ScanContext) (U59Input, []string) {
	file, errs := collectFirstExisting("/etc/snmpd.conf", "/usr/etc/snmpd.conf")
	return U59Input{SNMP: ctx.Services["snmp"], ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU59(input U59Input) CheckResult {
	if !input.SNMP.IsActive() {
		return CheckResult{
			Status:          StatusNotApplicable,
			RawConfig:       formatServiceStatus(input.SNMP),
			ProcessedConfig: "snmp_inactive=true",
		}
	}
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{
			Status:          StatusError,
			RawConfig:       formatServiceStatus(input.SNMP),
			ProcessedConfig: "snmp_config=missing",
			ErrMsg:          "SNMP is active but no readable snmpd.conf was collected",
		}
	}

	hasV3, hasAuth := snmpV3Authentication(input.Config)
	status := StatusGood
	vulnerable := ""
	if !hasV3 || !hasAuth {
		status = StatusVulnerable
		vulnerable = "Active SNMP is not demonstrably configured for SNMPv3 authentication."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s active_directives=%d (sensitive values redacted)", input.ConfigPath, len(activeConfigLines(input.Config))),
		ProcessedConfig:  fmt.Sprintf("snmp_v3=%t snmp_v3_auth=%t", hasV3, hasAuth),
		VulnerableConfig: vulnerable,
	}
}

func snmpV3Authentication(config string) (bool, bool) {
	hasV3, hasAuth := false, false
	for _, line := range activeConfigLines(config) {
		lower := strings.ToLower(line)
		fields := strings.Fields(lower)
		if len(fields) == 0 {
			continue
		}
		if strings.Contains(lower, "snmpv3") || strings.Contains(lower, "usm_user") ||
			strings.Contains(lower, "usmuser") || fields[0] == "createuser" ||
			fields[0] == "authuser" || fields[0] == "rouser" || fields[0] == "rwuser" {
			hasV3 = true
		}
		if strings.Contains(lower, "authnopriv") || strings.Contains(lower, "authpriv") ||
			strings.Contains(lower, " hmac-") || strings.Contains(lower, " sha") ||
			strings.Contains(lower, " md5") || fields[0] == "authuser" {
			hasAuth = true
		}
		if (fields[0] == "rouser" || fields[0] == "rwuser") && len(fields) >= 3 &&
			(fields[2] == "auth" || fields[2] == "priv") {
			hasAuth = true
		}
	}
	return hasV3, hasAuth
}

func activeConfigLines(config string) []string {
	var lines []string
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		aixComment := strings.HasPrefix(line, "*") && !strings.HasPrefix(line, "*.")
		if line == "" || strings.HasPrefix(line, "#") || aixComment {
			continue
		}
		if index := strings.Index(line, "#"); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
