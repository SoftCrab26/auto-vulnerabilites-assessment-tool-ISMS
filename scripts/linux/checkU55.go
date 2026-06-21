package main

import (
	"strings"
)

type U55Input struct {
	Passwd string
}

func checkU55(ctx ScanContext) CheckResult {
	const code = "U-55"
	const description = "FTP accounts should have nologin or false shell."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU55Input()

	result := evalU55(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU55Input() (U55Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U55Input{}, errs
	}
	return U55Input{Passwd: files[0].Content}, errs
}

func evalU55(input U55Input) CheckResult {
	content := input.Passwd
	var badFTP []string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 7 {
			username := fields[0]
			shell := fields[6]
			if strings.Contains(username, "ftp") || username == "ftp" {
				if !strings.Contains(shell, "false") && !strings.Contains(shell, "nologin") {
					badFTP = append(badFTP, username+" shell="+shell)
				}
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(badFTP) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"ftp_account_bad_shell="+strings.Join(badFTP, ","),
			"문제점1. FTP 계정에 nologin/false 쉘이 부여되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("ftp_shell_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
