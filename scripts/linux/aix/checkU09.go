package main

import (
	"sort"
	"strings"
)

type U09Input struct {
	Group  string
	Passwd string
}

func checkU09(ctx ScanContext) CheckResult {
	input, errs := loadU09Input()
	result := evalU09(input)
	result.Code = "U-09"
	result.Description = "Potentially unnecessary groups must be reviewed before removal."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1036"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU09Input() (U09Input, []string) {
	files, errs := collectFiles("/etc/group", "/etc/passwd")
	input := U09Input{}
	for _, file := range files {
		if file.Path == "/etc/group" {
			input.Group = file.Content
		} else if file.Path == "/etc/passwd" {
			input.Passwd = file.Content
		}
	}
	return input, errs
}

func evalU09(input U09Input) CheckResult {
	if input.Group == "" || input.Passwd == "" {
		return CheckResult{Status: StatusError, VulnerableConfig: "required /etc/group or /etc/passwd input is missing"}
	}
	primaryGIDs := map[string]bool{}
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 {
			primaryGIDs[fields[3]] = true
		}
	}
	legacy := map[string]bool{"uucp": true, "nuucp": true, "printq": true, "lpd": true, "guest": true}
	var candidates []string
	for _, line := range strings.Split(input.Group, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 && legacy[fields[0]] && !primaryGIDs[fields[2]] && strings.TrimSpace(fields[3]) == "" {
			candidates = append(candidates, fields[0])
		}
	}
	sort.Strings(candidates)
	status := StatusGood
	if len(candidates) > 0 {
		status = StatusInterview
	}
	return CheckResult{
		Status: status, RawConfig: input.Group,
		ProcessedConfig:  "review_candidates=" + strings.Join(candidates, ","),
		VulnerableConfig: strings.Join(candidates, "\n"),
	}
}
