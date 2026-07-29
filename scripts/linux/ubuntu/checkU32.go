package main

import (
	"os"
	"strings"
)

type U32Input struct {
	Passwd string
}

func checkU32(ctx ScanContext) CheckResult {
	const code = "U-32"
	const description = "Home directory specified in /etc/passwd must actually exist."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU32Input()

	result := evalU32(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU32Input() (U32Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U32Input{}, errs
	}
	return U32Input{Passwd: files[0].Content}, errs
}

func evalU32(input U32Input) CheckResult {
	content := input.Passwd
	var missingHomes []string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 6 {
			username := fields[0]
			home := fields[5]
			if home != "" && home != "/" {
				if _, err := os.Stat(home); os.IsNotExist(err) {
					missingHomes = append(missingHomes, username+" -> "+home)
				}
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(missingHomes) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"missing_home_dirs="+strings.Join(missingHomes, ";"),
			"문제점1. 홈 디렉토리가 존재하지 않는 계정이 있습니다: "+strings.Join(missingHomes, ", "),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("home_existence_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
