package main

import (
	"os"
	"strings"
)

type U32Home struct {
	User   string
	Path   string
	Exists bool
}

type U32Input struct {
	Passwd string
	Homes  []U32Home
}

func checkU32(ctx ScanContext) CheckResult {
	const code = "U-32"
	const description = "Home directories specified in /etc/passwd must exist."
	mitre := MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
	input, errs := loadU32Input()
	result := evalU32(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	if len(errs) > 0 && result.Status == StatusGood {
		result.Status = StatusInterview
		result.ProcessedConfig = "home_existence=incomplete"
	}
	return resultWithErrors(result, errs)
}

func loadU32Input() (U32Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U32Input{}, errs
	}
	input := U32Input{Passwd: files[0].Content}
	for _, home := range passwdHomes(input.Passwd) {
		_, err := os.Stat(home.Path)
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
			continue
		}
		input.Homes = append(input.Homes, U32Home{User: home.User, Path: home.Path, Exists: err == nil})
	}
	return input, errs
}

func evalU32(input U32Input) CheckResult {
	if strings.TrimSpace(input.Passwd) == "" || len(input.Homes) == 0 {
		return CheckResult{Status: StatusInterview, RawConfig: input.Passwd, ProcessedConfig: "home_existence=unavailable"}
	}
	var missing []string
	for _, home := range input.Homes {
		if !home.Exists {
			missing = append(missing, home.User+" -> "+home.Path)
		}
	}
	if len(missing) > 0 {
		return CheckResult{Status: StatusVulnerable, RawConfig: input.Passwd, ProcessedConfig: "home_existence=noncompliant", VulnerableConfig: strings.Join(missing, "\n")}
	}
	return CheckResult{Status: StatusGood, RawConfig: input.Passwd, ProcessedConfig: "home_existence=compliant"}
}
