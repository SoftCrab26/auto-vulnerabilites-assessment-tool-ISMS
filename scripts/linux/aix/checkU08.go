package main

import (
	"sort"
	"strings"
)

type U08Input struct {
	Group string
}

func checkU08(ctx ScanContext) CheckResult {
	input, errs := loadU08Input()
	result := evalU08(input)
	result.Code = "U-08"
	result.Description = "Membership of the AIX system administration group must be authorized."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1098", "T1548"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU08Input() (U08Input, []string) {
	files, errs := collectFiles("/etc/group")
	if len(files) == 0 {
		return U08Input{}, errs
	}
	return U08Input{Group: files[0].Content}, errs
}

func evalU08(input U08Input) CheckResult {
	if input.Group == "" {
		return CheckResult{Status: StatusError, VulnerableConfig: "required /etc/group input is missing"}
	}
	found := false
	var members []string
	for _, line := range strings.Split(input.Group, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 && fields[0] == "system" {
			found = true
			for _, member := range strings.Split(fields[3], ",") {
				if member = strings.TrimSpace(member); member != "" && member != "root" {
					members = append(members, member)
				}
			}
		}
	}
	if !found {
		return CheckResult{Status: StatusError, RawConfig: input.Group, ProcessedConfig: "system_group=NOT_FOUND", VulnerableConfig: "AIX system group is missing"}
	}
	sort.Strings(members)
	status := StatusGood
	if len(members) > 0 {
		status = StatusInterview
	}
	return CheckResult{Status: status, RawConfig: input.Group, ProcessedConfig: "system_members=" + strings.Join(members, ","), VulnerableConfig: strings.Join(members, "\n")}
}
