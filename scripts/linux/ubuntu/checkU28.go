package main

import (
	"strings"
)

type U28Input struct {
	HostsAllow string
	HostsDeny  string
}

func checkU28(ctx ScanContext) CheckResult {
	const code = "U-28"
	const description = "Specific IP and port access restrictions should be configured (hosts.allow/deny)."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1021"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU28Input()

	result := evalU28(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU28Input() (U28Input, []string) {
	files, errs := collectFiles("/etc/hosts.allow", "/etc/hosts.deny")
	hallow := ""
	hdeny := ""
	for _, f := range files {
		if strings.Contains(f.Path, "hosts.allow") {
			hallow = f.Content
		} else if strings.Contains(f.Path, "hosts.deny") {
			hdeny = f.Content
		}
	}
	return U28Input{HostsAllow: hallow, HostsDeny: hdeny}, errs
}

func evalU28(input U28Input) CheckResult {
	hasRestriction := strings.TrimSpace(input.HostsAllow) != "" || strings.TrimSpace(input.HostsDeny) != ""

	status := StatusGood
	vulnerableConfig := ""
	if !hasRestriction {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"hosts_allow_deny=NOT_CONFIGURED",
			"문제점1. 특정 호스트에 대한 IP/포트 접근 제한이 설정되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.HostsAllow + "\n" + input.HostsDeny,
		ProcessedConfig:  buildProcessedConfig("access_restriction_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
