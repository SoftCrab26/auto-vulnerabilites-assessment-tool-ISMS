package main

import "strings"

type U01Input struct {
	SSHConfig string
	Source    string
	SSHActive bool
}

func checkU01(ctx ScanContext) CheckResult {
	input, errs := loadU01Input(ctx)
	result := evalU01(input)
	result.Code = "U-01"
	result.Description = "SSH root login must be disabled."
	result.MitreAttack = MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1078.002", "T1133"},
		Mitigations: []string{"M1042"},
	}
	return resultWithErrors(result, errs)
}

func loadU01Input(ctx ScanContext) (U01Input, []string) {
	file, errs := collectFirstExisting(preferredDSMPaths("ssh/sshd_config")...)
	return U01Input{
		SSHConfig: file.Content,
		Source:    file.Path,
		SSHActive: dsmU01SSHActive(ctx.Services),
	}, errs
}

func evalU01(input U01Input) CheckResult {
	if input.Source == "" || strings.TrimSpace(input.SSHConfig) == "" {
		return CheckResult{Status: Error, ErrMsg: "SSH configuration evidence is unavailable"}
	}
	value := dsmU01EffectiveSSHDDirective(input.SSHConfig, "permitrootlogin")
	raw := "# FILE: " + input.Source + "\n" + input.SSHConfig
	if strings.EqualFold(value, "no") {
		return CheckResult{
			Status:          Good,
			RawConfig:       raw,
			ProcessedConfig: "ssh_active=" + dsmU01Bool(input.SSHActive) + " permitrootlogin=no",
		}
	}
	if value == "" {
		value = "default/unspecified"
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "ssh_active=" + dsmU01Bool(input.SSHActive) + " permitrootlogin=" + value,
		VulnerableConfig: "PermitRootLogin=" + value,
	}
}

func dsmU01SSHActive(services []Service) bool {
	for _, service := range services {
		if service.Name == "ssh" {
			return service.IsActive
		}
	}
	return false
}

func dsmU01EffectiveSSHDDirective(raw, key string) string {
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(stripUnquotedComment(rawLine))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "match") {
			break
		}
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
			return fields[1]
		}
	}
	return ""
}

func dsmU01Bool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
