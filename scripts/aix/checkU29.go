package main

import (
	"os"
	"strconv"
)

type U29Input struct {
	Path   string
	Exists bool
	Owner  string
	Mode   os.FileMode
}

func checkU29(ctx ScanContext) CheckResult {
	const code = "U-29"
	const description = "/etc/hosts.lpd should not exist or be owned by root with permission 600 or less if used."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU29Input()
	result := evalU29(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	if len(errs) > 0 && result.Status == StatusNotApplicable {
		result.Status = StatusInterview
		result.ProcessedConfig = "hosts_lpd=metadata_unavailable"
	}
	return resultWithErrors(result, errs)
}

func loadU29Input() (U29Input, []string) {
	const path = "/etc/hosts.lpd"
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return U29Input{Path: path}, nil
	}
	if err != nil {
		return U29Input{Path: path}, []string{err.Error()}
	}
	owner, err := fileOwnerName(path)
	if err != nil {
		return U29Input{Path: path, Exists: true, Mode: info.Mode()}, []string{err.Error()}
	}
	return U29Input{Path: path, Exists: true, Owner: owner, Mode: info.Mode()}, nil
}

func evalU29(input U29Input) CheckResult {
	if !input.Exists {
		return CheckResult{Status: StatusNotApplicable, RawConfig: input.Path + " not present", ProcessedConfig: "hosts_lpd=not_present"}
	}
	mode := input.Mode.Perm()
	raw := input.Path + " owner=" + input.Owner + " mode=" + strconv.FormatUint(uint64(mode), 8)
	if input.Owner == "" {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "hosts_lpd=metadata_incomplete"}
	}
	if input.Owner != "root" || mode&0077 != 0 || !input.Mode.IsRegular() {
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: "hosts_lpd=noncompliant", VulnerableConfig: raw}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "hosts_lpd=compliant"}
}
