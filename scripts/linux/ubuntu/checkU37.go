package main

import (
	"os"
	"strconv"
	"strings"
)

type U37Input struct {
	Paths []string
}

func checkU37(ctx ScanContext) CheckResult {
	const code = "U-37"
	const description = "crontab and at related files should have permission 640 or less and no general user execute permission."
	mitreAttack := MitreAttack{
		Tactic:      "Persistence",
		Techniques:  []string{"T1053"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU37Input()

	result := evalU37(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU37Input() (U37Input, []string) {
	paths := []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/var/spool/cron",
		"/etc/at.deny",
		"/etc/at.allow",
	}
	return U37Input{Paths: paths}, nil
}

func evalU37(input U37Input) CheckResult {
	var problems []string

	for _, path := range input.Paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&0027 != 0 { // stricter than 640 in some cases
			problems = append(problems, path+" perm="+strconv.FormatUint(uint64(perm), 8))
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(problems) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			strings.Join(problems, "\n"),
			"문제점1. crontab/at 관련 파일의 권한이 640 이하가 아니거나 일반 사용자 실행 권한이 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig("crontab_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
