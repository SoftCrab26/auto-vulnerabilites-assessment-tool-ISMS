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
	input, errs := loadU59Input(ctx)
	result := evalU59(input)
	result.Code = "U-59"
	result.Description = "Active SNMP should use authenticated SNMPv3."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU59Input(ctx ScanContext) (U59Input, []string) {
	snmp := dsmU58Service(ctx.Services, "snmp")
	if !snmp.IsActive {
		return U59Input{SNMP: snmp}, nil
	}
	file, errs := collectFirstExisting(
		"/etc/snmp/snmpd.conf",
		"/var/packages/SNMP/target/etc/snmpd.conf",
		"/usr/syno/etc/snmpd.conf",
		"/etc/snmpd.conf",
	)
	return U59Input{SNMP: snmp, ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU59(input U59Input) CheckResult {
	if !input.SNMP.IsActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "snmp_inactive=true"}
	}
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{Status: Error, ProcessedConfig: "snmp_config=missing", ErrMsg: "SNMP is active but its DSM configuration was not readable"}
	}

	v3, authenticated, privacy := dsmU59AuthenticationState(input.Config)
	status := Good
	vulnerable := ""
	if !v3 || !authenticated {
		status = Vulnerable
		vulnerable = "Authenticated SNMPv3 configuration was not found."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s snmpv3=%t authentication_configured=%t privacy_configured=%t (authentication material redacted)", input.ConfigPath, v3, authenticated, privacy),
		ProcessedConfig:  fmt.Sprintf("snmpv3=%t authentication_configured=%t privacy_configured=%t", v3, authenticated, privacy),
		VulnerableConfig: vulnerable,
	}
}

func dsmU59AuthenticationState(config string) (bool, bool, bool) {
	var v3, authenticated, privacy bool
	for _, line := range dsmU59ActiveLines(config) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "createuser") || strings.Contains(lower, "rouser") ||
			strings.Contains(lower, "rwuser") || strings.Contains(lower, "authuser") ||
			strings.Contains(lower, "usm") || strings.Contains(lower, "snmpv3") {
			v3 = true
		}
		if strings.Contains(lower, "authpriv") || strings.Contains(lower, "authnopriv") ||
			strings.Contains(lower, " sha") || strings.Contains(lower, " md5") ||
			strings.HasPrefix(lower, "sha ") || strings.HasPrefix(lower, "md5 ") {
			authenticated = true
		}
		if strings.Contains(lower, "authpriv") || strings.Contains(lower, " aes") ||
			strings.Contains(lower, " des") {
			privacy = true
		}
	}
	return v3, authenticated, privacy
}

func dsmU59ActiveLines(config string) []string {
	var lines []string
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(stripUnquotedComment(raw))
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
