package main

import (
	"fmt"
	"net"
	"strings"
)

type U61Input struct {
	SNMP       Service
	ConfigPath string
	Config     string
}

func checkU61(ctx ScanContext) CheckResult {
	const code = "U-61"
	const description = "Active SNMP should restrict access by access, view, or source ACL."
	mitre := MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}

	input, errs := loadU61Input(ctx)
	result := evalU61(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU61Input(ctx ScanContext) (U61Input, []string) {
	file, errs := collectFirstExisting("/etc/snmpd.conf", "/usr/etc/snmpd.conf")
	return U61Input{SNMP: ctx.Services["snmp"], ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU61(input U61Input) CheckResult {
	if !input.SNMP.IsActive() {
		return CheckResult{Status: StatusNotApplicable, ProcessedConfig: "snmp_inactive=true"}
	}
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{Status: StatusError, ProcessedConfig: "snmp_config=missing", ErrMsg: "SNMP is active but no readable snmpd.conf was collected"}
	}

	hasAccess, hasView, hasSource := snmpACLEvidence(input.Config)
	status := StatusGood
	vulnerable := ""
	if !hasAccess && !hasView && !hasSource {
		status = StatusVulnerable
		vulnerable = "No SNMP ACCESS, VIEW, or restricted source ACL was found."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s active_directives=%d (sensitive values redacted)", input.ConfigPath, len(activeConfigLines(input.Config))),
		ProcessedConfig:  fmt.Sprintf("access_acl=%t view_acl=%t source_acl=%t", hasAccess, hasView, hasSource),
		VulnerableConfig: vulnerable,
	}
}

func snmpACLEvidence(config string) (bool, bool, bool) {
	hasAccess, hasView, hasSource := false, false, false
	for _, line := range activeConfigLines(config) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		switch directive {
		case "access", "vacm_access":
			hasAccess = len(fields) > 1
		case "view", "vacm_view":
			hasView = len(fields) > 1
		case "com2sec", "com2sec6":
			if len(fields) >= 4 && restrictedSNMPSource(fields[len(fields)-2]) {
				hasSource = true
			}
		case "rocommunity", "rwcommunity":
			if len(fields) >= 3 && restrictedSNMPSource(fields[2]) {
				hasSource = true
			}
		case "community":
			for _, field := range fields[2:] {
				if restrictedSNMPSource(field) {
					hasSource = true
					break
				}
			}
		}
	}
	return hasAccess, hasView, hasSource
}

func restrictedSNMPSource(value string) bool {
	value = strings.ToLower(trimSNMPToken(value))
	if value == "" || value == "default" || value == "any" || value == "0.0.0.0" ||
		value == "0.0.0.0/0" || value == "::/0" || value == "*" {
		return false
	}
	if ip := net.ParseIP(strings.TrimSuffix(value, "/32")); ip != nil {
		return !ip.IsUnspecified()
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return value != "0.0.0.0/0" && value != "::/0"
	}
	return strings.Contains(value, ".") || strings.Contains(value, ":")
}
