package main

import (
	"sort"
	"strings"
)

type U08Input struct {
	Group  string
	Source string
}

func checkU08(ctx ScanContext) CheckResult {
	input, errs := loadU08Input(ctx)
	result := evalU08(input)
	result.Code = "U-08"
	result.Description = "DSM administrators group membership must be limited to authorized accounts."
	result.MitreAttack = MitreAttack{
		Tactic:      "Privilege Escalation",
		Techniques:  []string{"T1548.003"},
		Mitigations: []string{"M1026"},
	}
	return resultWithErrors(result, errs)
}

func loadU08Input(_ ScanContext) (U08Input, []string) {
	file, errs := collectFirstExisting(preferredDSMPaths("group")...)
	return U08Input{Group: file.Content, Source: file.Path}, errs
}

func evalU08(input U08Input) CheckResult {
	if input.Source == "" || strings.TrimSpace(input.Group) == "" {
		return CheckResult{Status: Error, ErrMsg: "group evidence is unavailable"}
	}
	var members []string
	var evidence string
	for _, line := range strings.Split(input.Group, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 && fields[0] == "administrators" {
			evidence = line
			for _, member := range strings.Split(fields[3], ",") {
				if member = strings.TrimSpace(member); member != "" {
					members = append(members, member)
				}
			}
			break
		}
	}
	if evidence == "" {
		return CheckResult{
			Status:          Error,
			RawConfig:       "# FILE: " + input.Source + "\nadministrators group not found",
			ProcessedConfig: "administrators_group=not_found",
			ErrMsg:          "DSM administrators group is absent from group evidence",
		}
	}
	sort.Strings(members)
	var clearlyUnauthorized []string
	for _, member := range members {
		switch strings.ToLower(member) {
		case "test", "testing", "demo", "sample":
			clearlyUnauthorized = append(clearlyUnauthorized, member)
		}
	}
	if len(clearlyUnauthorized) > 0 {
		return CheckResult{
			Status:           Vulnerable,
			RawConfig:        "# FILE: " + input.Source + "\n" + evidence,
			ProcessedConfig:  "administrators_members=" + strings.Join(members, ","),
			VulnerableConfig: "clearly unauthorized sample members=" + strings.Join(clearlyUnauthorized, ","),
		}
	}
	return CheckResult{
		Status:           Manual,
		RawConfig:        "# FILE: " + input.Source + "\n" + evidence,
		ProcessedConfig:  "administrators_members=" + strings.Join(members, ","),
		VulnerableConfig: "compare administrators membership with the approved administrator list",
	}
}
