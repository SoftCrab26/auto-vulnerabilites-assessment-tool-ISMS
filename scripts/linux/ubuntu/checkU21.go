package main

import (
	"os"
	"strconv"
	"strings"
)

type U21Input struct {
	Paths []string
}

func checkU21(ctx ScanContext) CheckResult {
	const code = "U-21"
	const description = "syslog/rsyslog config should be owned by root/bin/sys with permission 640 or less."
	mitreAttack := MitreAttack{
		tactic:      "Defense Evasion",
		techniques:  []string{"T1562"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU21Input()

	result := evalU21(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU21Input() (U21Input, []string) {
	paths := []string{
		"/etc/rsyslog.conf",
		"/etc/syslog.conf",
		"/etc/rsyslog.d",
	}
	return U21Input{Paths: paths}, nil
}

func evalU21(input U21Input) CheckResult {
	var problems []string

	for _, path := range input.Paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&0027 != 0 { // allow group read, but not other write etc.
			problems = append(problems, path+" perm="+strconv.FormatUint(uint64(perm), 8))
		}
		ownerOut := strings.ToLower(run("stat -c %U " + path + " 2>/dev/null || echo unknown"))
		if !strings.Contains(ownerOut, "root") && !strings.Contains(ownerOut, "bin") && !strings.Contains(ownerOut, "sys") {
			problems = append(problems, path+" owner="+strings.TrimSpace(ownerOut))
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(problems) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			strings.Join(problems, "\n"),
			"문제점1. syslog 설정 파일의 소유자(root/bin/sys) 또는 권한(640 이하)이 올바르지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig("syslog_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
