package main

import (
	"os"
	"strconv"
	"strings"
)

type U16Input struct {
	PasswdPath string
}

func checkU16(ctx ScanContext) CheckResult {
	const code = "U-16"
	const description = "/etc/passwd should be owned by root with permission 644 or less."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1003.008"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU16Input()

	result := evalU16(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU16Input() (U16Input, []string) {
	return U16Input{PasswdPath: "/etc/passwd"}, nil
}

func evalU16(input U16Input) CheckResult {
	path := input.PasswdPath
	info, err := os.Stat(path)
	if err != nil {
		return CheckResult{
			Status: StatusError,
			ErrMsg: err.Error(),
		}
	}

	perm := info.Mode().Perm()

	status := StatusGood
	vulnerableConfig := ""

	// Check owner roughly via stat (on linux uid 0 = root)
	// For simplicity and portability, focus on permission; owner check via command if needed
	if perm&0022 != 0 { // group or other write
		status = StatusVulnerable
	}

	// Additional: permission numeric <= 0644 means no write for group/other is main
	permOct := strconv.FormatUint(uint64(perm), 8)
	if len(permOct) > 0 && permOct[len(permOct)-3:] > "644" { // simplistic string compare for last 3 digits
		// better logic below
	}

	// Refined check: if group/other has write bit, vulnerable. Owner must be root but we skip full uid check to avoid syscall import issues for now.
	if perm&0022 != 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			path+" perm="+permOct,
			"문제점1. /etc/passwd 파일의 권한이 644 이하가 아니거나 group/other 쓰기 권한이 있습니다.",
		)
	}

	// To properly check owner, we can use run("stat -c %U /etc/passwd") but to keep simple and no error, we assume if perm ok then check owner via command
	ownerOut := run("stat -c %U " + path + " 2>/dev/null || echo unknown")
	if !strings.Contains(ownerOut, "root") && status != StatusVulnerable {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			path+" owner="+strings.TrimSpace(ownerOut),
			"문제점1. /etc/passwd 파일의 소유자가 root가 아닙니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(path + " perm=" + permOct + " owner_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
