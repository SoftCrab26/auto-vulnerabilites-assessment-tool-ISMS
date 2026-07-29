package main

import (
	"sort"
	"strings"
)

type U11Input struct {
	Passwd string
}

func checkU11(ctx ScanContext) CheckResult {
	input, errs := loadU11Input()
	result := evalU11(input)
	result.Code = "U-11"
	result.Description = "AIX system accounts that do not need interactive access must have disabled shells."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
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
	if input.Passwd == "" {
		return CheckResult{Status: StatusError, VulnerableConfig: "required /etc/passwd input is missing"}
	}
	systemAccounts := map[string]bool{
		"daemon": true, "bin": true, "sys": true, "adm": true, "uucp": true, "guest": true,
		"nobody": true, "lpd": true, "nuucp": true, "snapp": true, "invscout": true, "ipsec": true,
	}
	var bad []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 7 && systemAccounts[fields[0]] && aixLoginShell(fields[6]) {
			bad = append(bad, fields[0]+"("+fields[6]+")")
		}
	}
	sort.Strings(bad)
	status := StatusGood
	if len(bad) > 0 {
		status = StatusVulnerable
	}
	return CheckResult{Status: status, RawConfig: input.Passwd, ProcessedConfig: "system_accounts_with_login_shell=" + strings.Join(bad, ","), VulnerableConfig: strings.Join(bad, "\n")}
}
