package main

import "strings"

type U03Input struct {
	SecurityUser string
}

func checkU03(ctx ScanContext) CheckResult {
	input, errs := loadU03Input()
	result := evalU03(input)
	result.Code = "U-03"
	result.Description = "Failed login attempts must be limited to between 1 and 10."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1110"}, Mitigations: []string{"M1036"}}
	return resultWithErrors(result, errs)
}

func loadU03Input() (U03Input, []string) {
	files, errs := collectFiles("/etc/security/user")
	if len(files) == 0 {
		return U03Input{}, errs
	}
	return U03Input{SecurityUser: files[0].Content}, errs
}

func evalU03(input U03Input) CheckResult {
	value := findStanzaValue(input.SecurityUser, "default", "loginretries")
	status := StatusVulnerable
	problem := ""
	if input.SecurityUser == "" {
		status = StatusError
		problem = "required /etc/security/user input is missing"
	} else if value != "NOT_FOUND" && safeAtoi(value) >= 1 && safeAtoi(value) <= 10 {
		status = StatusGood
	} else {
		problem = "default.loginretries must be between 1 and 10"
	}
	return CheckResult{Status: status, RawConfig: extractStanza(input.SecurityUser, "default"), ProcessedConfig: "loginretries=" + value, VulnerableConfig: strings.TrimSpace(problem)}
}
