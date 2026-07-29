package main

import (
	"sort"
	"strings"
)

type U07Input struct {
	Passwd string
	Source string
}

func checkU07(ctx ScanContext) CheckResult {
	input, errs := loadU07Input(ctx)
	result := evalU07(input)
	result.Code = "U-07"
	result.Description = "Unnecessary or sample accounts must be removed or disabled."
	result.MitreAttack = MitreAttack{
		Tactic:      "Initial Access",
		Techniques:  []string{"T1078"},
		Mitigations: []string{"M1026"},
	}
	return resultWithErrors(result, errs)
}

func loadU07Input(_ ScanContext) (U07Input, []string) {
	file, errs := collectFirstExisting(preferredDSMPaths("passwd")...)
	return U07Input{Passwd: file.Content, Source: file.Path}, errs
}

func evalU07(input U07Input) CheckResult {
	if input.Source == "" || strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: Error, ErrMsg: "passwd evidence is unavailable"}
	}
	var clear, review []string
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 7 || dsmU07NonLoginShell(fields[6]) {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "test", "testing", "demo", "sample":
			clear = append(clear, fields[0]+"="+fields[6])
		case "guest":
			review = append(review, fields[0]+"="+fields[6])
		}
	}
	sort.Strings(clear)
	sort.Strings(review)
	status := Good
	vulnerable := ""
	switch {
	case len(clear) > 0:
		status = Vulnerable
		vulnerable = "interactive sample_accounts=" + strings.Join(clear, ",")
	case len(review) > 0:
		status = Manual
		vulnerable = "verify DSM guest account necessity and disabled state: " + strings.Join(review, ",")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        "# FILE: " + input.Source + "\n" + input.Passwd,
		ProcessedConfig:  "clear_unnecessary=" + strings.Join(clear, ",") + " review=" + strings.Join(review, ","),
		VulnerableConfig: vulnerable,
	}
}

func dsmU07NonLoginShell(shell string) bool {
	lower := strings.ToLower(strings.TrimSpace(shell))
	return lower == "" || strings.Contains(lower, "nologin") ||
		strings.HasSuffix(lower, "/false") || lower == "/bin/sync"
}
