package main

import (
	"strconv"
	"strings"
)

type U11Input struct {
	Passwd string
}

func checkU11(ctx ScanContext) CheckResult {
	const code = "U-11"
	const description = "Accounts that do not require login should have /bin/false or /sbin/nologin shell."
	mitreAttack := MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1026"},
	}

	input, errs := loadU11Input()

	result := evalU11(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU11Input() (U11Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U11Input{}, errs
	}
	return U11Input{Passwd: files[0].Content}, errs
}

func evalU11(input U11Input) CheckResult {
	content := input.Passwd
	var badShellAccounts []string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 7 {
			username := fields[0]
			uid := fields[2]
			shell := fields[6]

			uidNum := safeAtoi(uid)
			// System accounts (UID < 1000) should not have real login shell
			if uidNum < 1000 && uidNum != 0 {
				if !strings.Contains(shell, "false") && !strings.Contains(shell, "nologin") && !strings.Contains(shell, "/bin/sync") {
					badShellAccounts = append(badShellAccounts, username+"(UID:"+uid+", shell:"+shell+")")
				}
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(badShellAccounts) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"bad_shell_accounts="+strings.Join(badShellAccounts, ";"),
			"문제점1. 로그인 불필요 계정에 잘못된 쉘이 부여되어 있습니다: "+strings.Join(badShellAccounts, ", "),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("shell_check=done", "bad_count="+strconv.Itoa(len(badShellAccounts))),
		VulnerableConfig: vulnerableConfig,
	}
}
