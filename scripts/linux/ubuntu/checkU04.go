package main

import (
	"os"
	"strconv"
	"strings"
)

type U04Input struct {
	Paths []string
}

func checkU04(ctx ScanContext) CheckResult {
	const code = "U-04"
	const description = "The permissions of /etc/passwd and /etc/shadow should be set to prevent unauthorized access to password information."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1003.008"}, // OS Credential Dumping: /etc/passwd and /etc/shadow
		mitigations: []string{"M1026"},     // Privileged Account Management
	}

	input, errs := loadU04Input()

	result := evalU04(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU04Input() (U04Input, []string) {
	paths := []string{"/etc/passwd", "/etc/shadow"}
	var errs []string
	// no file reading here beyond stat checks done in eval to keep load minimal
	return U04Input{Paths: paths}, errs
}

func evalU04(input U04Input) CheckResult {
	var errs []string
	var processed []string

	for _, path := range input.Paths {
		info, err := os.Stat(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		perm := info.Mode().Perm()
		processed = append(processed, path+" perm="+strconv.FormatUint(uint64(perm), 8))
	}

	status := StatusGood

	passwd, err1 := os.Stat("/etc/passwd")
	shadow, err2 := os.Stat("/etc/shadow")

	if err1 != nil && err2 != nil {
		status = StatusError
	} else if err1 != nil || err2 != nil {
		status = StatusVulnerable
	}

	if err1 == nil {
		perm := passwd.Mode().Perm()
		if perm&022 != 0 {
			status = StatusVulnerable
		}
	}

	if err2 == nil {
		perm := shadow.Mode().Perm()
		if perm&0007 != 0 {
			status = StatusVulnerable
		}
	}

	vulnerableConfig := ""
	if status == StatusVulnerable {
		reasons := []string{}
		if err1 != nil {
			reasons = append(reasons, "문제점1. /etc/passwd 파일을 확인할 수 없습니다.")
		}
		if err1 == nil {
			if passwd.Mode().Perm()&022 != 0 {
				reasons = append(reasons, "문제점1. /etc/passwd가 그룹이나 다른 사용자 쓰기 가능 권한을 가집니다.")
			}
		}
		if err2 != nil {
			reasons = append(reasons, "문제점2. /etc/shadow 파일을 확인할 수 없습니다.")
		}
		if err2 == nil {
			if shadow.Mode().Perm()&0007 != 0 {
				reasons = append(reasons, "문제점2. /etc/shadow가 다른 사용자에게 읽기/쓰기/실행 권한을 허용합니다.")
			}
		}
		vulnerableConfig = buildVulnerableConfig(strings.Join(processed, " | "), strings.Join(reasons, "\n"))
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(strings.Join(processed, " | ")),
		VulnerableConfig: vulnerableConfig,
		ErrMsg:           joinErrors(errs),
	}
}
