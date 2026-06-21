package main

import (
	"os"
	"strconv"
	"strings"
)

type U29Input struct {
	Path string
}

func checkU29(ctx ScanContext) CheckResult {
	const code = "U-29"
	const description = "/etc/hosts.lpd should not exist or be owned by root with permission 600 or less if used."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU29Input()

	result := evalU29(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU29Input() (U29Input, []string) {
	return U29Input{Path: "/etc/hosts.lpd"}, nil
}

func evalU29(input U29Input) CheckResult {
	path := input.Path
	_, err := os.Stat(path)
	if err != nil {
		// File does not exist -> Good (as per criteria)
		return CheckResult{
			Status:          StatusGood,
			RawConfig:       path + " does not exist",
			ProcessedConfig: buildProcessedConfig(path + "=not_exist"),
		}
	}

	info, _ := os.Stat(path)
	perm := info.Mode().Perm()
	permOct := strconv.FormatUint(uint64(perm), 8)

	status := StatusGood
	vulnerableConfig := ""
	if perm&0077 != 0 {
		status = StatusVulnerable
	}

	ownerOut := strings.ToLower(run("stat -c %U " + path + " 2>/dev/null || echo unknown"))
	if !strings.Contains(ownerOut, "root") {
		status = StatusVulnerable
	}

	if status == StatusVulnerable {
		vulnerableConfig = buildVulnerableConfig(
			path+" perm="+permOct+" owner="+strings.TrimSpace(ownerOut),
			"문제점1. hosts.lpd 파일이 존재하며 소유자(root) 또는 권한(600 이하)이 올바르지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(path + " perm=" + permOct),
		VulnerableConfig: vulnerableConfig,
	}
}
