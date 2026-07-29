package main

import (
	"os"
	"strconv"
	"strings"
)

type U18Input struct {
	ShadowPath string
}

func checkU18(ctx ScanContext) CheckResult {
	const code = "U-18"
	const description = "/etc/shadow should be owned by root with permission 400 or less."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1003.008"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU18Input()

	result := evalU18(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU18Input() (U18Input, []string) {
	return U18Input{ShadowPath: "/etc/shadow"}, nil
}

func evalU18(input U18Input) CheckResult {
	path := input.ShadowPath
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

	// For shadow, should not be readable by group or other (perm & 0077 != 0 means vulnerable)
	if perm&0077 != 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			path+" perm="+permOct,
			"문제점1. /etc/shadow 파일의 권한이 400 이하가 아니거나 group/other 읽기/쓰기 권한이 있습니다.",
		)
	}

	// Owner check
	ownerOut := run("stat -c %U " + path + " 2>/dev/null || echo unknown")
	if !strings.Contains(strings.ToLower(ownerOut), "root") && status != StatusVulnerable {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			path+" owner="+strings.TrimSpace(ownerOut),
			"문제점1. /etc/shadow 파일의 소유자가 root가 아닙니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(path + " perm=" + permOct + " owner_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
