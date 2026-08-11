package main

import (
	"os"
	"strconv"
	"strings"
)

type U67Input struct {
	LogDir string
}

func checkU67(ctx ScanContext) CheckResult {
	const code = "U-67"
	const description = "Log directory and files should be owned by root with permission 644 or less."
	mitreAttack := MitreAttack{
		Tactic:      "Defense Evasion",
		Techniques:  []string{"T1562"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU67Input()

	result := evalU67(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU67Input() (U67Input, []string) {
	return U67Input{LogDir: "/var/log"}, nil
}

func evalU67(input U67Input) CheckResult {
	dir := input.LogDir
	info, err := os.Stat(dir)
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
	}

	ownerOut := strings.ToLower(run("stat -c %U " + dir + " 2>/dev/null || echo unknown"))
	if !strings.Contains(ownerOut, "root") {
		status = StatusVulnerable
	}

	if status == StatusVulnerable {
		vulnerableConfig = buildVulnerableConfig(
			dir+" perm="+permOct+" owner="+strings.TrimSpace(ownerOut),
			"문제점1. 로그 디렉터리(/var/log)의 소유자(root) 또는 권한(644 이하)이 올바르지 않습니다.",
		)
	}

	// Also check a few key log files
	keyLogs := []string{"/var/log/messages", "/var/log/secure", "/var/log/syslog"}
	for _, logf := range keyLogs {
		if linfo, lerr := os.Stat(logf); lerr == nil {
			lperm := linfo.Mode().Perm()
			if lperm&0022 != 0 {
				status = StatusVulnerable
				vulnerableConfig = buildVulnerableConfig(
					logf+" perm too open",
					"문제점2. 주요 로그 파일 권한이 올바르지 않습니다.",
				)
			}
		}
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(dir + " perm=" + permOct),
		VulnerableConfig: vulnerableConfig,
	}
}
