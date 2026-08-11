package main

import (
	"os"
	"strconv"
	"strings"
)

type U63Input struct {
	Path string
}

func checkU63(ctx ScanContext) CheckResult {
	const code = "U-63"
	const description = "/etc/sudoers should be owned by root with permission exactly 640."
	mitreAttack := MitreAttack{
		Tactic:      "Privilege Escalation",
		Techniques:  []string{"T1548.003"},
		Mitigations: []string{"M1026"},
	}

	input, errs := loadU63Input()

	result := evalU63(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU63Input() (U63Input, []string) {
	return U63Input{Path: "/etc/sudoers"}, nil
}

func evalU63(input U63Input) CheckResult {
	path := input.Path
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

	if perm != 0640 { // exactly 640 as per many guides (or <= 640)
		status = StatusVulnerable
	}

	ownerOut := strings.ToLower(run("stat -c %U " + path + " 2>/dev/null || echo unknown"))
	if !strings.Contains(ownerOut, "root") {
		status = StatusVulnerable
	}

	if status == StatusVulnerable {
		vulnerableConfig = buildVulnerableConfig(
			path+" perm="+permOct+" owner="+strings.TrimSpace(ownerOut),
			"문제점1. /etc/sudoers 파일의 소유자(root) 또는 권한(640)이 올바르지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(path + " perm=" + permOct),
		VulnerableConfig: vulnerableConfig,
	}
}
