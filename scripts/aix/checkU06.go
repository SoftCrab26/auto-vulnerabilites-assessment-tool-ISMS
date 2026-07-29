package main

import "strings"

type U06Input struct {
	SecurityUser string
}

func checkU06(ctx ScanContext) CheckResult {
	input, errs := loadU06Input()
	result := evalU06(input)
	result.Code = "U-06"
	result.Description = "Use of su to root must be restricted through AIX sugroups."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1548"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU06Input() (U06Input, []string) {
	files, errs := collectFiles("/etc/security/user")
	if len(files) == 0 {
		return U06Input{}, errs
	}
	return U06Input{SecurityUser: files[0].Content}, errs
}

func evalU06(input U06Input) CheckResult {
	value := findStanzaValue(input.SecurityUser, "root", "sugroups")
	status := StatusGood
	problem := ""
	normalized := strings.ToLower(strings.TrimSpace(value))
	if input.SecurityUser == "" {
		status, problem = StatusError, "required /etc/security/user input is missing"
	} else if normalized == "not_found" || normalized == "" || normalized == "all" || normalized == "*" {
		status, problem = StatusVulnerable, "root.sugroups must name a restricted group set"
	}
	return CheckResult{Status: status, RawConfig: extractStanza(input.SecurityUser, "root"), ProcessedConfig: "root.sugroups=" + value, VulnerableConfig: problem}
}
