package main

import (
	"fmt"
	"strings"
)

type U60Input struct {
	SNMP       Service
	ConfigPath string
	Config     string
}

func checkU60(ctx ScanContext) CheckResult {
	const code = "U-60"
	const description = "SNMP community strings should not use default or weak values."
	mitre := MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}

	input, errs := loadU60Input(ctx)
	result := evalU60(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU60Input(ctx ScanContext) (U60Input, []string) {
	file, errs := collectFirstExisting("/etc/snmpd.conf", "/usr/etc/snmpd.conf")
	return U60Input{SNMP: ctx.Services["snmp"], ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU60(input U60Input) CheckResult {
	if !input.SNMP.IsActive() {
		return CheckResult{Status: StatusNotApplicable, ProcessedConfig: "snmp_inactive=true"}
	}
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{Status: StatusError, ProcessedConfig: "snmp_config=missing", ErrMsg: "SNMP is active but no readable snmpd.conf was collected"}
	}

	communities := parseSNMPCommunities(input.Config)
	weak := 0
	for _, community := range communities {
		if weakSNMPCommunity(community) {
			weak++
		}
	}
	status := StatusGood
	vulnerable := ""
	if weak > 0 {
		status = StatusVulnerable
		vulnerable = fmt.Sprintf("%d weak SNMP community value(s) found; values are redacted.", weak)
	} else if len(communities) == 0 {
		status = StatusInterview
		vulnerable = "No community value was parsed; verify that SNMPv3-only operation is intended."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s community_values=%d (values redacted)", input.ConfigPath, len(communities)),
		ProcessedConfig:  fmt.Sprintf("community_values=%d weak_values=%d", len(communities), weak),
		VulnerableConfig: vulnerable,
	}
}

func parseSNMPCommunities(config string) []string {
	var values []string
	for _, line := range activeConfigLines(config) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "community", "rocommunity", "rwcommunity", "trapcommunity":
			values = append(values, trimSNMPToken(fields[1]))
		case "com2sec", "com2sec6":
			if len(fields) >= 4 {
				values = append(values, trimSNMPToken(fields[len(fields)-1]))
			}
		}
	}
	return values
}

func trimSNMPToken(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"'`)
}

func weakSNMPCommunity(value string) bool {
	value = strings.ToLower(trimSNMPToken(value))
	if value == "" {
		return true
	}
	switch value {
	case "public", "private", "community", "snmp", "default", "monitor", "read", "write":
		return true
	}
	return len(value) < 8
}
