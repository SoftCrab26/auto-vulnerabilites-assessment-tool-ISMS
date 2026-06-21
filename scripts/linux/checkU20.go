package main

import (
	"os"
	"strconv"
	"strings"
)

type U20Input struct {
	Paths []string
}

func checkU20(ctx ScanContext) CheckResult {
	const code = "U-20"
	const description = "/etc/(x)inetd.conf should be owned by root with permission 600 or less."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU20Input()

	result := evalU20(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU20Input() (U20Input, []string) {
	paths := []string{"/etc/inetd.conf", "/etc/xinetd.conf", "/etc/xinetd.d"}
	return U20Input{Paths: paths}, nil
}

func evalU20(input U20Input) CheckResult {
	var problems []string

	for _, path := range input.Paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&0077 != 0 { // more than owner only
			problems = append(problems, path+" perm="+strconv.FormatUint(uint64(perm), 8))
		}
		ownerOut := strings.ToLower(run("stat -c %U " + path + " 2>/dev/null || echo unknown"))
		if !strings.Contains(ownerOut, "root") {
			problems = append(problems, path+" owner="+strings.TrimSpace(ownerOut))
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(problems) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			strings.Join(problems, "\n"),
			"문제점1. inetd/xinetd 설정 파일의 소유자 또는 권한이 올바르지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig("inetd_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
