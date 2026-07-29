package main

import (
	"fmt"
	"strings"
)

type U61Input struct {
	SNMP       Service
	ConfigPath string
	Config     string
}

func checkU61(ctx ScanContext) CheckResult {
	input, errs := loadU61Input(ctx)
	result := evalU61(input)
	result.Code = "U-61"
	result.Description = "SNMP should restrict sources and exposed object views."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU61Input(ctx ScanContext) (U61Input, []string) {
	snmp := dsmU58Service(ctx.Services, "snmp")
	if !snmp.IsActive {
		return U61Input{SNMP: snmp}, nil
	}
	file, errs := collectFirstExisting(
		"/etc/snmp/snmpd.conf",
		"/var/packages/SNMP/target/etc/snmpd.conf",
		"/usr/syno/etc/snmpd.conf",
		"/etc/snmpd.conf",
	)
	return U61Input{SNMP: snmp, ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU61(input U61Input) CheckResult {
	if !input.SNMP.IsActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "snmp_inactive=true"}
	}
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{Status: Error, ProcessedConfig: "snmp_config=missing", ErrMsg: "SNMP is active but its DSM configuration was not readable"}
	}

	sourceACL, view := dsmU61AccessState(input.Config)
	status := Good
	vulnerable := ""
	if !sourceACL || !view {
		status = Vulnerable
		vulnerable = "SNMP source restrictions and a restricted MIB view must both be configured."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s source_acl_configured=%t restricted_view_configured=%t (community and user values redacted)", input.ConfigPath, sourceACL, view),
		ProcessedConfig:  fmt.Sprintf("source_acl=%t restricted_view=%t", sourceACL, view),
		VulnerableConfig: vulnerable,
	}
}

func dsmU61AccessState(config string) (bool, bool) {
	var sourceACL, view bool
	for _, line := range dsmU59ActiveLines(config) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "com2sec", "com2sec6":
			if len(fields) >= 4 && !dsmU61UnrestrictedSource(fields[2]) {
				sourceACL = true
			}
		case "rocommunity", "rwcommunity":
			if len(fields) >= 3 && !dsmU61UnrestrictedSource(fields[2]) {
				sourceACL = true
			}
			if len(fields) >= 4 && strings.TrimSpace(fields[3]) != "" {
				view = true
			}
		case "rouser", "rwuser":
			if len(fields) >= 4 && strings.TrimSpace(fields[len(fields)-1]) != "" {
				view = true
			}
		case "view":
			if len(fields) >= 4 {
				oid := strings.TrimLeft(fields[3], ".")
				if oid != "1" && oid != "1.3" && oid != "1.3.6" && oid != "iso" {
					view = true
				}
			}
		case "access":
			if len(fields) >= 6 {
				view = true
			}
		}
	}
	return sourceACL, view
}

func dsmU61UnrestrictedSource(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default", "0.0.0.0/0", "::/0", "any", "all":
		return true
	default:
		return false
	}
}
