package main

import (
	"sort"
	"strconv"
	"strings"
)

type U09Input struct {
	Group        string
	GroupSource  string
	Passwd       string
	PasswdSource string
}

func checkU09(ctx ScanContext) CheckResult {
	input, errs := loadU09Input(ctx)
	result := evalU09(input)
	result.Code = "U-09"
	result.Description = "DSM groups must be reviewed for operational necessity."
	result.MitreAttack = MitreAttack{
		Tactic:      "Defense Evasion",
		Techniques:  []string{"T1036"},
		Mitigations: []string{"M1022"},
	}
	return resultWithErrors(result, errs)
}

func loadU09Input(_ ScanContext) (U09Input, []string) {
	group, groupErrs := collectFirstExisting(preferredDSMPaths("group")...)
	passwd, passwdErrs := collectFirstExisting(preferredDSMPaths("passwd")...)
	return U09Input{
		Group:        group.Content,
		GroupSource:  group.Path,
		Passwd:       passwd.Content,
		PasswdSource: passwd.Path,
	}, append(groupErrs, passwdErrs...)
}

func evalU09(input U09Input) CheckResult {
	if input.GroupSource == "" || input.PasswdSource == "" {
		return CheckResult{Status: Error, ErrMsg: "group and passwd evidence are required"}
	}
	primaryGIDs := make(map[string]bool)
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 {
			primaryGIDs[fields[3]] = true
		}
	}
	var inventory, unreferenced []string
	for _, line := range strings.Split(input.Group, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 4 || fields[0] == "" {
			continue
		}
		memberCount := 0
		if strings.TrimSpace(fields[3]) != "" {
			memberCount = len(strings.Split(fields[3], ","))
		}
		inventory = append(inventory, fields[0]+"(gid="+fields[2]+",members="+strconv.Itoa(memberCount)+")")
		if memberCount == 0 && !primaryGIDs[fields[2]] {
			unreferenced = append(unreferenced, fields[0])
		}
	}
	sort.Strings(inventory)
	sort.Strings(unreferenced)
	return CheckResult{
		Status: Manual,
		RawConfig: "# FILE: " + input.GroupSource + "\n" + input.Group +
			"\n# FILE: " + input.PasswdSource + "\n" + input.Passwd,
		ProcessedConfig:  "groups=" + strings.Join(inventory, ";") + " unreferenced=" + strings.Join(unreferenced, ","),
		VulnerableConfig: "review group inventory and unreferenced groups against installed DSM packages",
	}
}
