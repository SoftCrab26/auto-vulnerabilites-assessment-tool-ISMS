package main

import (
	"strconv"
	"strings"
)

type U07Input struct {
	Passwd string
}

func checkU07(ctx ScanContext) CheckResult {
	input, errs := loadU07Input()
	result := evalU07(input)
	result.Code = "U-07"
	result.Description = "Unnecessary default AIX accounts must not have login shells."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
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
	if input.Passwd == "" {
		return CheckResult{Status: StatusError, VulnerableConfig: "required /etc/passwd input is missing"}
	}
	unnecessary := map[string]bool{"guest": true, "uucp": true, "nuucp": true, "lpd": true, "printq": true}
	var bad []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 7 && unnecessary[fields[0]] && aixLoginShell(fields[6]) {
			bad = append(bad, fields[0]+"("+fields[6]+")")
		}
	}
	status := StatusGood
	if len(bad) > 0 {
		status = StatusVulnerable
	}
	return CheckResult{Status: status, RawConfig: input.Passwd, ProcessedConfig: "login_enabled_count=" + strconv.Itoa(len(bad)), VulnerableConfig: strings.Join(bad, "\n")}
}

func aixLoginShell(shell string) bool {
	shell = strings.ToLower(strings.TrimSpace(shell))
	return shell != "" && shell != "/bin/false" && shell != "/usr/bin/false" && shell != "/sbin/nologin" && shell != "/usr/sbin/nologin"
}
