package main

import (
	"strconv"
	"strings"
)

type U07Input struct {
	Passwd string
}

func checkU07(ctx ScanContext) CheckResult {
	const code = "U-07"
	const description = "Unnecessary default accounts should be removed or have nologin shell."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU07Input()

	result := evalU07(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU07Input() (U07Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U07Input{}, errs
	}
	return U07Input{Passwd: files[0].Content}, errs
}

func evalU07(input U07Input) CheckResult {
	content := input.Passwd

	// Common unnecessary accounts in Korean gov guides
	unnecessaryAccounts := []string{
		"lp", "sync", "shutdown", "halt", "news", "uucp", "operator",
		"games", "gopher", "ftp", "nobody", "apache", "httpd", "www-data",
	}

	var foundBad []string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 7 {
			username := fields[0]
			shell := fields[6]
			for _, bad := range unnecessaryAccounts {
				if username == bad {
					// If it has a real login shell, it's bad
					if !strings.Contains(shell, "false") && !strings.Contains(shell, "nologin") && !strings.Contains(shell, "null") {
						foundBad = append(foundBad, username+" (shell: "+shell+")")
					}
					break
				}
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(foundBad) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"unnecessary_accounts="+strings.Join(foundBad, ","),
			"문제점1. 불필요한 계정이 존재하고 로그인 가능한 쉘이 부여되어 있습니다: "+strings.Join(foundBad, ", "),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("unnecessary_check=done", "bad_count="+strconv.Itoa(len(foundBad))),
		VulnerableConfig: vulnerableConfig,
	}
}
