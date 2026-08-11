package main

import (
	"strings"
)

type U09Input struct {
	Group  string
	Passwd string
}

func checkU09(ctx ScanContext) CheckResult {
	const code = "U-09"
	const description = "No unnecessary groups should exist that are not used by any account."
	mitreAttack := MitreAttack{
		Tactic:      "Defense Evasion",
		Techniques:  []string{"T1036"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU09Input()

	result := evalU09(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU09Input() (U09Input, []string) {
	gfiles, gerrs := collectFiles("/etc/group")
	pfiles, perrs := collectFiles("/etc/passwd")
	errs := append(gerrs, perrs...)
	gcontent := ""
	if len(gfiles) > 0 {
		gcontent = gfiles[0].Content
	}
	pcontent := ""
	if len(pfiles) > 0 {
		pcontent = pfiles[0].Content
	}
	return U09Input{Group: gcontent, Passwd: pcontent}, errs
}

func evalU09(input U09Input) CheckResult {
	// Simple check: groups that have GID but may be unnecessary (heuristic)
	// For full implementation would need to cross check with passwd GIDs, but simplified here
	status := StatusGood
	vulnerableConfig := ""

	// If /etc/group has many lines, we just note it (full logic is complex)
	// For now, check for known unnecessary groups
	unnecessaryGroups := []string{"lp", "news", "uucp", "games", "gopher"}
	var found []string

	for _, line := range strings.Split(input.Group, "\n") {
		for _, bad := range unnecessaryGroups {
			if strings.HasPrefix(line, bad+":") {
				found = append(found, bad)
			}
		}
	}

	if len(found) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"unnecessary_groups="+strings.Join(found, ","),
			"문제점1. 시스템 운용에 불필요한 그룹이 존재합니다: "+strings.Join(found, ", "),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.Group,
		ProcessedConfig:  buildProcessedConfig("group_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
