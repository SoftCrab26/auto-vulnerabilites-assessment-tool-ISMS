package main

import (
	"strings"
)

type U08Input struct {
	GroupContent string
}

func checkU08(ctx ScanContext) CheckResult {
	const code = "U-08"
	const description = "Administrator group (wheel/sudo) should contain only necessary accounts."
	mitreAttack := MitreAttack{
		tactic:      "Privilege Escalation",
		techniques:  []string{"T1548.003"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU08Input()

	result := evalU08(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU08Input() (U08Input, []string) {
	files, errs := collectFiles("/etc/group")
	if len(files) == 0 {
		return U08Input{}, errs
	}
	return U08Input{GroupContent: files[0].Content}, errs
}

func evalU08(input U08Input) CheckResult {
	content := input.GroupContent
	var adminMembers []string
	adminGroupFound := false

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "wheel:") || strings.HasPrefix(line, "sudo:") || strings.HasPrefix(line, "root:") {
			adminGroupFound = true
			parts := strings.Split(line, ":")
			if len(parts) >= 4 {
				members := strings.TrimSpace(parts[3])
				if members != "" {
					adminMembers = append(adminMembers, strings.Split(members, ",")...)
				}
			}
		}
	}

	// If more than just root in admin group, it may be vulnerable (depends on policy)
	status := StatusGood
	vulnerableConfig := ""
	if adminGroupFound && len(adminMembers) > 1 {
		// Simple heuristic: if non-root members exist
		hasNonRoot := false
		for _, m := range adminMembers {
			if strings.TrimSpace(m) != "root" && m != "" {
				hasNonRoot = true
				break
			}
		}
		if hasNonRoot {
			status = StatusVulnerable
			vulnerableConfig = buildVulnerableConfig(
				"admin_group_members="+strings.Join(adminMembers, ","),
				"문제점1. 관리자 그룹(wheel/sudo)에 불필요한 계정이 등록되어 있습니다.",
			)
		}
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("admin_group_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
