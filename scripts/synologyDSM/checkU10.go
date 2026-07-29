package main

import (
	"sort"
	"strings"
)

type U10Input struct {
	Passwd string
	Source string
}

func checkU10(ctx ScanContext) CheckResult {
	input, errs := loadU10Input(ctx)
	result := evalU10(input)
	result.Code = "U-10"
	result.Description = "No duplicate UIDs may exist."
	result.MitreAttack = MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1026"},
	}
	return resultWithErrors(result, errs)
}

func loadU10Input(_ ScanContext) (U10Input, []string) {
	file, errs := collectFirstExisting(preferredDSMPaths("passwd")...)
	return U10Input{Passwd: file.Content, Source: file.Path}, errs
}

func evalU10(input U10Input) CheckResult {
	if input.Source == "" || strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: Error, ErrMsg: "passwd evidence is unavailable"}
	}
	uidUsers := make(map[string][]string)
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 3 && fields[0] != "" && fields[2] != "" {
			uidUsers[fields[2]] = append(uidUsers[fields[2]], fields[0])
		}
	}
	var duplicates []string
	for uid, users := range uidUsers {
		if len(users) > 1 {
			sort.Strings(users)
			duplicates = append(duplicates, uid+"="+strings.Join(users, ","))
		}
	}
	sort.Strings(duplicates)
	status := Good
	if len(duplicates) > 0 {
		status = Vulnerable
	}
	return CheckResult{
		Status:           status,
		RawConfig:        "# FILE: " + input.Source + "\n" + input.Passwd,
		ProcessedConfig:  "duplicate_uids=" + strings.Join(duplicates, ";"),
		VulnerableConfig: strings.Join(duplicates, "\n"),
	}
}
