package main

import (
	"strings"
)

type U57Input struct {
	Ftpusers string
}

func checkU57(ctx ScanContext) CheckResult {
	const code = "U-57"
	const description = "root account should be blocked from FTP login (ftpusers file)."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU57Input()

	result := evalU57(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU57Input() (U57Input, []string) {
	files, errs := collectFiles("/etc/ftpusers", "/etc/vsftpd/ftpusers", "/etc/vsftpd/user_list")
	if len(files) == 0 {
		return U57Input{}, errs
	}
	// Use first found
	return U57Input{Ftpusers: files[0].Content}, errs
}

func evalU57(input U57Input) CheckResult {
	content := input.Ftpusers
	rootBlocked := false

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "root" {
			rootBlocked = true
			break
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if !rootBlocked {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"root_in_ftpusers=false",
			"문제점1. ftpusers 파일에 root 계정이 차단되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("ftpusers_root_block=" + boolToStrForU57(rootBlocked)),
		VulnerableConfig: vulnerableConfig,
	}
}

func boolToStrForU57(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
