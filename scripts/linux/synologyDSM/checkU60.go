package main

import (
	"fmt"
	"strings"
	"unicode"
)

type U60Input struct {
	SNMP       Service
	ConfigPath string
	Config     string
}

func checkU60(ctx ScanContext) CheckResult {
	input, errs := loadU60Input(ctx)
	result := evalU60(input)
	result.Code = "U-60"
	result.Description = "SNMP community strings should not use default or weak values."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU60Input(ctx ScanContext) (U60Input, []string) {
	snmp := dsmU58Service(ctx.Services, "snmp")
	if !snmp.IsActive {
		return U60Input{SNMP: snmp}, nil
	}
	file, errs := collectFirstExisting(
		"/etc/snmp/snmpd.conf",
		"/var/packages/SNMP/target/etc/snmpd.conf",
		"/usr/syno/etc/snmpd.conf",
		"/etc/snmpd.conf",
	)
	return U60Input{SNMP: snmp, ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU60(input U60Input) CheckResult {
	if !input.SNMP.IsActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "snmp_inactive=true"}
	}
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{Status: Error, ProcessedConfig: "snmp_config=missing", ErrMsg: "SNMP is active but its DSM configuration was not readable"}
	}

	communities := dsmU60Communities(input.Config)
	weak := 0
	labels := make([]string, 0, len(communities))
	for _, community := range communities {
		if dsmU60WeakCommunity(community) {
			weak++
			labels = append(labels, "community=[REDACTED]:weak")
		} else {
			labels = append(labels, "community=[REDACTED]:strong")
		}
	}

	status := Good
	vulnerable := ""
	if weak > 0 {
		status = Vulnerable
		vulnerable = fmt.Sprintf("%d weak SNMP community value(s) found; all values are redacted.", weak)
	} else if len(communities) == 0 {
		status = Manual
		vulnerable = "No community value was parsed; verify that authenticated SNMPv3-only operation is intended."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s community_count=%d labels=[%s]", input.ConfigPath, len(communities), strings.Join(labels, ", ")),
		ProcessedConfig:  fmt.Sprintf("community_count=%d weak_count=%d values_redacted=true", len(communities), weak),
		VulnerableConfig: vulnerable,
	}
}

func dsmU60Communities(config string) []string {
	var values []string
	for _, line := range dsmU59ActiveLines(config) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "community", "rocommunity", "rwcommunity", "trapcommunity":
			values = append(values, dsmU60TrimToken(fields[1]))
		case "com2sec", "com2sec6":
			if len(fields) >= 4 {
				values = append(values, dsmU60TrimToken(fields[len(fields)-1]))
			}
		}
	}
	return values
}

func dsmU60TrimToken(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"'`)
}

func dsmU60WeakCommunity(value string) bool {
	value = dsmU60TrimToken(value)
	lower := strings.ToLower(value)
	switch lower {
	case "", "public", "private", "default", "community", "snmp":
		return true
	}
	if len([]rune(value)) < 8 {
		return true
	}
	var letters, digits, symbols bool
	for _, character := range value {
		switch {
		case unicode.IsLetter(character):
			letters = true
		case unicode.IsDigit(character):
			digits = true
		default:
			symbols = true
		}
	}
	return !(letters && (digits || symbols))
}
