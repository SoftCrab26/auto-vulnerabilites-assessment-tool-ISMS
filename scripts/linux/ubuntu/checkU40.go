package main

import (
	"strings"
)

type U40Input struct {
	Exports string
}

func checkU40(ctx ScanContext) CheckResult {
	const code = "U-40"
	const description = "NFS access control should be properly configured."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU40Input()

	result := evalU40(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU40Input() (U40Input, []string) {
	files, errs := collectFiles("/etc/exports")
	if len(files) == 0 {
		return U40Input{}, errs
	}
	return U40Input{Exports: files[0].Content}, errs
}

func evalU40(input U40Input) CheckResult {
	content := input.Exports
	hasAccessControl := strings.Contains(content, "ro") || strings.Contains(content, "rw") || strings.Contains(content, "root_squash") || strings.Contains(content, "no_root_squash") == false

	status := StatusGood
	vulnerableConfig := ""
	if strings.TrimSpace(content) != "" && !hasAccessControl {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"nfs_exports_no_control",
			"문제점1. NFS 접근 통제가 제대로 설정되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("nfs_access_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
