package main

import "strings"

type U06Input struct {
	SuPAM       string
	PAMSource   string
	Group       string
	GroupSource string
}

func checkU06(ctx ScanContext) CheckResult {
	input, errs := loadU06Input(ctx)
	result := evalU06(input)
	result.Code = "U-06"
	result.Description = "Use of su must be restricted through PAM to an administrative group."
	result.MitreAttack = MitreAttack{
		Tactic:      "Privilege Escalation",
		Techniques:  []string{"T1548.003"},
		Mitigations: []string{"M1026"},
	}
	return resultWithErrors(result, errs)
}

func loadU06Input(_ ScanContext) (U06Input, []string) {
	pam, pamErrs := collectFirstExisting(preferredDSMPaths("pam.d/su")...)
	group, groupErrs := collectFirstExisting(preferredDSMPaths("group")...)
	return U06Input{
		SuPAM:       pam.Content,
		PAMSource:   pam.Path,
		Group:       group.Content,
		GroupSource: group.Path,
	}, append(pamErrs, groupErrs...)
}

func evalU06(input U06Input) CheckResult {
	raw := dsmU06Evidence(input)
	if input.PAMSource == "" || input.GroupSource == "" {
		return CheckResult{
			Status:    Error,
			RawConfig: raw,
			ErrMsg:    "su PAM and group evidence are required",
		}
	}
	restriction := ""
	for _, rawLine := range strings.Split(input.SuPAM, "\n") {
		line := strings.TrimSpace(stripUnquotedComment(rawLine))
		if line == "" || !strings.Contains(strings.ToLower(line), "pam_wheel.so") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "group=administrators"):
			restriction = "administrators"
		case strings.Contains(lower, "group=wheel"):
			restriction = "wheel"
		default:
			restriction = "wheel(default)"
		}
		break
	}
	groupName := strings.TrimSuffix(restriction, "(default)")
	groupExists := groupName != "" && dsmU06GroupExists(input.Group, groupName)
	processed := "pam_wheel_group=" + dsmU06Display(restriction) +
		" administrative_group_exists=" + dsmU06Bool(groupExists)
	if restriction != "" && groupExists {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: processed}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  processed,
		VulnerableConfig: "su is not demonstrably restricted to administrators or wheel",
	}
}

func dsmU06Evidence(input U06Input) string {
	var parts []string
	if input.PAMSource != "" {
		parts = append(parts, "# FILE: "+input.PAMSource+"\n"+input.SuPAM)
	}
	if input.GroupSource != "" {
		parts = append(parts, "# FILE: "+input.GroupSource+"\n"+input.Group)
	}
	return strings.Join(parts, "\n")
}

func dsmU06GroupExists(raw, name string) bool {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), name+":") {
			return true
		}
	}
	return false
}

func dsmU06Display(value string) string {
	if value == "" {
		return "not_found"
	}
	return value
}

func dsmU06Bool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
