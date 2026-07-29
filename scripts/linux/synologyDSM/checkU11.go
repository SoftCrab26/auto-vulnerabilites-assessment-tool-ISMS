package main

import (
	"sort"
	"strconv"
	"strings"
)

type U11Input struct {
	Passwd string
	Source string
}

func checkU11(ctx ScanContext) CheckResult {
	input, errs := loadU11Input(ctx)
	result := evalU11(input)
	result.Code = "U-11"
	result.Description = "System accounts that do not require login must use a non-login shell."
	result.MitreAttack = MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1026"},
	}
	return resultWithErrors(result, errs)
}

func loadU11Input(_ ScanContext) (U11Input, []string) {
	file, errs := collectFirstExisting(preferredDSMPaths("passwd")...)
	return U11Input{Passwd: file.Content, Source: file.Path}, errs
}

func evalU11(input U11Input) CheckResult {
	if input.Source == "" || strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: Error, ErrMsg: "passwd evidence is unavailable"}
	}
	var interactive []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 7 || fields[0] == "root" {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < 0 || uid >= 1024 || dsmU11NonLoginShell(fields[6]) {
			continue
		}
		interactive = append(interactive, fields[0]+"(uid="+fields[2]+",shell="+fields[6]+")")
	}
	sort.Strings(interactive)
	status := Good
	if len(interactive) > 0 {
		status = Vulnerable
	}
	return CheckResult{
		Status:           status,
		RawConfig:        "# FILE: " + input.Source + "\n" + input.Passwd,
		ProcessedConfig:  "interactive_system_accounts=" + strings.Join(interactive, ","),
		VulnerableConfig: strings.Join(interactive, "\n"),
	}
}

func dsmU11NonLoginShell(shell string) bool {
	lower := strings.ToLower(strings.TrimSpace(shell))
	return lower == "" || strings.Contains(lower, "nologin") ||
		strings.HasSuffix(lower, "/false") || lower == "/bin/sync"
}
