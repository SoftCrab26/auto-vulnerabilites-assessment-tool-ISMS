package main

import (
	"strconv"
	"strings"
)

type U30Input struct {
	SecurityUser string
	Profile      string
}

func checkU30(ctx ScanContext) CheckResult {
	const code = "U-30"
	const description = "The default AIX umask and /etc/profile umask should be 022 or more restrictive."
	mitre := MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1222"}, Mitigations: []string{"M1022"}}
	input, errs := loadU30Input()
	result := evalU30(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU30Input() (U30Input, []string) {
	files, errs := collectFiles("/etc/security/user", "/etc/profile")
	input := U30Input{}
	for _, file := range files {
		if file.Path == "/etc/security/user" {
			input.SecurityUser = file.Content
		} else {
			input.Profile = file.Content
		}
	}
	return input, errs
}

func evalU30(input U30Input) CheckResult {
	defaultMask := findStanzaValue(input.SecurityUser, "default", "umask")
	profileMask := profileUmask(input.Profile)
	raw := buildLabeledRawConfig([]FileResult{{Path: "/etc/security/user", Content: input.SecurityUser}, {Path: "/etc/profile", Content: input.Profile}})
	if strings.TrimSpace(input.SecurityUser) == "" || strings.TrimSpace(input.Profile) == "" {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: buildProcessedConfig("default_umask="+defaultMask, "profile_umask="+profileMask)}
	}
	if !secureUmask(defaultMask) || !secureUmask(profileMask) {
		issue := buildProcessedConfig("default_umask="+defaultMask, "profile_umask="+profileMask)
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: issue, VulnerableConfig: issue}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: buildProcessedConfig("default_umask="+defaultMask, "profile_umask="+profileMask)}
}

func profileUmask(raw string) string {
	value := "NOT_FOUND"
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		line = strings.Replace(line, "=", " ", 1)
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "umask") {
			value = strings.TrimPrefix(fields[1], "0")
			if value == "" {
				value = "0"
			}
		}
	}
	return value
}

func secureUmask(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "NOT_FOUND" {
		return false
	}
	value, err := strconv.ParseUint(raw, 8, 16)
	return err == nil && value >= 0022 && value <= 0777
}
