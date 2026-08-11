package main

import (
	"os"
	"strconv"
	"strings"
)

type U19Input struct {
	HostsPath string
}

func checkU19(ctx ScanContext) CheckResult {
	const code = "U-19"
	const description = "/etc/hosts should be owned by root with permission 644 or less."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU19Input()

	result := evalU19(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU19Input() (U19Input, []string) {
	return U19Input{HostsPath: "/etc/hosts"}, nil
}

func evalU19(input U19Input) CheckResult {
	path := input.HostsPath
	info, err := os.Stat(path)
	if err != nil {
		return CheckResult{
			Status: StatusError,
			ErrMsg: err.Error(),
		}
	}

	perm := info.Mode().Perm()
	permOct := strconv.FormatUint(uint64(perm), 8)

	status := StatusGood
	vulnerableConfig := ""

	if perm&0022 != 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			path+" perm="+permOct,
			"문제점1. /etc/hosts 파일의 권한이 644 이하가 아니거나 group/other 쓰기 권한이 있습니다.",
		)
	}

	ownerOut := run("stat -c %U " + path + " 2>/dev/null || echo unknown")
	if !strings.Contains(strings.ToLower(ownerOut), "root") && status != StatusVulnerable {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			path+" owner="+strings.TrimSpace(ownerOut),
			"문제점1. /etc/hosts 파일의 소유자가 root가 아닙니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(path + " perm=" + permOct + " owner_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
