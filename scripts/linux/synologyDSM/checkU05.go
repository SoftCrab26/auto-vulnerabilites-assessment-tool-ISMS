package main

import (
	"sort"
	"strings"
)

type U05Input struct {
	Passwd string
	Source string
}

func checkU05(ctx ScanContext) CheckResult {
	input, errs := loadU05Input(ctx)
	result := evalU05(input)
	result.Code = "U-05"
	result.Description = "Only root may have UID 0."
	result.MitreAttack = MitreAttack{
		Tactic:      "Privilege Escalation",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1026"},
	}
	return resultWithErrors(result, errs)
}

func loadU05Input(_ ScanContext) (U05Input, []string) {
	file, errs := collectFirstExisting(preferredDSMPaths("passwd")...)
	return U05Input{Passwd: file.Content, Source: file.Path}, errs
}

func evalU05(input U05Input) CheckResult {
	if input.Source == "" || strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: Error, ErrMsg: "passwd evidence is unavailable"}
	}
	var uidZero []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 3 && fields[0] != "root" && fields[2] == "0" {
			uidZero = append(uidZero, fields[0])
		}
	}
	sort.Strings(uidZero)
	status := Good
	if len(uidZero) > 0 {
		status = Vulnerable
	}
	return CheckResult{
		Status:           status,
		RawConfig:        "# FILE: " + input.Source + "\n" + input.Passwd,
		ProcessedConfig:  "non_root_uid0=" + strings.Join(uidZero, ","),
		VulnerableConfig: strings.Join(uidZero, ","),
	}
}
