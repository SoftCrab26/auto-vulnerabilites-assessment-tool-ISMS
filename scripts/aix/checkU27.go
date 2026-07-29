package main

import (
	"strconv"
	"strings"
)

type U27Input struct {
	HostsEquiv auditFile
	RootRhosts auditFile
}

func checkU27(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU27(loadU27Input())
	result.Code = "U-27"
	result.Description = "Trust files must not contain wildcard trust and, if present, must be root-owned with permissions no broader than 0600."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU27Input() U27Input {
	return U27Input{
		HostsEquiv: loadAuditFile("/etc/hosts.equiv", true),
		RootRhosts: loadAuditFile("/root/.rhosts", true),
	}
}

func hasWildcardTrust(content string) bool {
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "+") {
				return true
			}
		}
	}
	return false
}

func evalU27(input U27Input) CheckResult {
	files := []auditFile{input.HostsEquiv, input.RootRhosts}
	var existing, bad []auditFile
	var reasons []string
	for _, file := range files {
		if !file.Exists {
			continue
		}
		existing = append(existing, file)
		if !ownerAllowed(file.Owner, "root") || !hasOnlyAllowedPermissions(file.Mode, 0600) {
			bad = append(bad, file)
			reasons = append(reasons, auditFileSummary(file))
		}
		if hasWildcardTrust(file.Content) {
			if len(bad) == 0 || bad[len(bad)-1].Path != file.Path {
				bad = append(bad, file)
			}
			reasons = append(reasons, file.Path+" contains wildcard trust")
		}
	}
	if len(existing) == 0 {
		return CheckResult{Status: StatusNotApplicable, ProcessedConfig: "trust_files=0"}
	}
	status := StatusGood
	vulnerable := ""
	if len(bad) > 0 {
		status = StatusVulnerable
		vulnerable = strings.Join(reasons, "\n")
	}
	raw := make([]string, 0, len(existing))
	for _, file := range existing {
		raw = append(raw, "["+file.Path+"]\n"+file.Content)
	}
	return CheckResult{
		Status: status, RawConfig: strings.Join(raw, "\n"),
		ProcessedConfig:  "trust_files=" + strconv.Itoa(len(existing)) + " issues=" + strconv.Itoa(len(bad)),
		VulnerableConfig: vulnerable,
	}
}
