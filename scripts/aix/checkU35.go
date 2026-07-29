package main

import (
	"os"
	"strings"
)

type U35Input struct {
	FTP               Service
	FTPAccess         string
	ConfigPresent     bool
	EvidenceAvailable bool
}

func checkU35(ctx ScanContext) CheckResult {
	const code = "U-35"
	const description = "Anonymous FTP access should be disabled."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU35Input(ctx)
	result := evalU35(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU35Input(ctx ScanContext) (U35Input, []string) {
	input := U35Input{FTP: ctx.Services["ftp"], EvidenceAvailable: serviceEvidenceAvailable(ctx)}
	data, err := os.ReadFile("/etc/ftpaccess")
	if os.IsNotExist(err) {
		return input, nil
	}
	if err != nil {
		return input, []string{err.Error()}
	}
	input.ConfigPresent, input.FTPAccess = true, string(data)
	return input, nil
}

func evalU35(input U35Input) CheckResult {
	raw := buildLabeledRawConfig([]FileResult{{Path: "ftp_service", Content: formatServiceStatus(input.FTP)}, {Path: "/etc/ftpaccess", Content: input.FTPAccess}})
	if !input.FTP.IsActive() {
		if !input.EvidenceAvailable {
			return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "ftp=evidence_unavailable"}
		}
		return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "ftp=disabled"}
	}
	if !input.ConfigPresent {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "ftp=active anonymous_policy=unavailable"}
	}
	policy := anonymousFTPPolicy(input.FTPAccess)
	switch policy {
	case "enabled":
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: "ftp=active anonymous=enabled", VulnerableConfig: "anonymous FTP access is enabled"}
	case "disabled":
		return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "ftp=active anonymous=disabled"}
	default:
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "ftp=active anonymous=ambiguous"}
	}
}

func anonymousFTPPolicy(raw string) string {
	policy := "ambiguous"
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.ToLower(strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0]))
		line = strings.ReplaceAll(line, "=", " ")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "anonymous" || fields[0] == "anonymous_enable" {
			value := strings.Trim(fields[1], "=")
			if value == "no" || value == "false" || value == "disable" || value == "disabled" || value == "deny" {
				policy = "disabled"
			}
			if value == "yes" || value == "true" || value == "enable" || value == "enabled" || value == "allow" {
				policy = "enabled"
			}
		}
		if fields[0] == "class" && strings.Contains(line, "anonymous") {
			policy = "enabled"
		}
	}
	return policy
}
