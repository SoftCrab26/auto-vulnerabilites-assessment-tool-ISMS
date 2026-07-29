package main

import (
	"os"
	"strings"
)

type U40Input struct {
	Exports       string
	ConfigPresent bool
}

func checkU40(ctx ScanContext) CheckResult {
	const code = "U-40"
	const description = "AIX NFS exports should restrict access to specific clients."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU40Input()
	result := evalU40(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	if len(errs) > 0 && result.Status == StatusNotApplicable {
		result.Status = StatusInterview
		result.ProcessedConfig = "nfs_exports=evidence_unavailable"
	}
	return resultWithErrors(result, errs)
}

func loadU40Input() (U40Input, []string) {
	data, err := os.ReadFile("/etc/exports")
	if os.IsNotExist(err) {
		return U40Input{}, nil
	}
	if err != nil {
		return U40Input{}, []string{err.Error()}
	}
	return U40Input{Exports: string(data), ConfigPresent: true}, nil
}

func evalU40(input U40Input) CheckResult {
	if !input.ConfigPresent || strings.TrimSpace(input.Exports) == "" {
		return CheckResult{Status: StatusNotApplicable, RawConfig: input.Exports, ProcessedConfig: "nfs_exports=not_configured"}
	}
	exports := logicalExportLines(input.Exports)
	if len(exports) == 0 {
		return CheckResult{Status: StatusNotApplicable, RawConfig: input.Exports, ProcessedConfig: "nfs_exports=not_configured"}
	}
	var unrestricted, ambiguous []string
	for _, line := range exports {
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "access="):
			value := exportOptionValue(lower, "access")
			if value == "" {
				ambiguous = append(ambiguous, line)
			} else if strings.ContainsAny(value, "*?") {
				unrestricted = append(unrestricted, line)
			}
		case strings.Contains(lower, "ro="):
			value := exportOptionValue(lower, "ro")
			if value == "" {
				ambiguous = append(ambiguous, line)
			} else if strings.ContainsAny(value, "*?") {
				unrestricted = append(unrestricted, line)
			}
		case strings.Contains(lower, "rw="):
			value := exportOptionValue(lower, "rw")
			if value == "" {
				ambiguous = append(ambiguous, line)
			} else if strings.ContainsAny(value, "*?") {
				unrestricted = append(unrestricted, line)
			}
		default:
			unrestricted = append(unrestricted, line)
		}
	}
	if len(unrestricted) > 0 {
		return CheckResult{Status: StatusVulnerable, RawConfig: input.Exports, ProcessedConfig: "nfs_exports=unrestricted", VulnerableConfig: strings.Join(unrestricted, "\n")}
	}
	if len(ambiguous) > 0 {
		return CheckResult{Status: StatusInterview, RawConfig: input.Exports, ProcessedConfig: "nfs_exports=ambiguous", VulnerableConfig: strings.Join(ambiguous, "\n")}
	}
	return CheckResult{Status: StatusGood, RawConfig: input.Exports, ProcessedConfig: "nfs_exports=restricted"}
}

func logicalExportLines(raw string) []string {
	var lines []string
	current := ""
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		current += " " + strings.TrimSuffix(line, "\\")
		if strings.HasSuffix(line, "\\") {
			continue
		}
		lines = append(lines, strings.TrimSpace(current))
		current = ""
	}
	if strings.TrimSpace(current) != "" {
		lines = append(lines, strings.TrimSpace(current))
	}
	return lines
}

func exportOptionValue(line, option string) string {
	index := strings.Index(line, option+"=")
	if index < 0 {
		return ""
	}
	value := line[index+len(option)+1:]
	if end := strings.IndexAny(value, " \t,"); end >= 0 {
		value = value[:end]
	}
	return strings.TrimSpace(value)
}
