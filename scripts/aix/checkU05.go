package main

import "strings"

type U05Input struct {
	Passwd string
}

func checkU05(ctx ScanContext) CheckResult {
	input, errs := loadU05Input()
	result := evalU05(input)
	result.Code = "U-05"
	result.Description = "Only root may have UID 0."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU05Input() (U05Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U05Input{}, errs
	}
	return U05Input{Passwd: files[0].Content}, errs
}

func evalU05(input U05Input) CheckResult {
	if input.Passwd == "" {
		return CheckResult{Status: StatusError, VulnerableConfig: "required /etc/passwd input is missing"}
	}
	var bad []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 3 && fields[2] == "0" && fields[0] != "root" {
			bad = append(bad, fields[0])
		}
	}
	status := StatusGood
	if len(bad) > 0 {
		status = StatusVulnerable
	}
	return CheckResult{Status: status, RawConfig: input.Passwd, ProcessedConfig: "non_root_uid0=" + strings.Join(bad, ","), VulnerableConfig: strings.Join(bad, "\n")}
}
